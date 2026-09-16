use super::*;
pub(super) struct Discovered {
    key: Vec<u8>,
    original: Message,
    question: Question,
    job: u64,
    pub(super) waiters: Vec<Waiter>,
    base: Option<Vec<u8>>,
    forward_cache: bool,
}
impl Discovered {
    pub(super) fn from_pending(p: Pending) -> Self {
        Self {
            key: p.key,
            original: p.original,
            question: p.question,
            job: 0,
            waiters: p.waiters,
            base: p.base,
            forward_cache: p.forward_cache,
        }
    }
    pub(super) fn charge(&self) -> usize {
        4096 + self.key.len()
            + 16 * self.original.original().len()
            + 16 * self.base.as_ref().map_or(0, Vec::len)
            + 1024 * self.waiters.len()
    }
}
impl Resolver {
    pub fn enable_discovery(&mut self, zone: crate::discovery_proxy::Zone) -> io::Result<()> {
        if self.discovery.is_some() {
            return Err(io::Error::other("Discovery Proxy already configured"));
        }
        self.discovery = Some(crate::discovery_proxy::Proxy::new(zone));
        self.cache.clear();
        Ok(())
    }
    pub(super) fn waiters(&self) -> impl Iterator<Item = &Waiter> {
        self.pending
            .values()
            .flat_map(|p| &p.waiters)
            .chain(self.discovered.values().flat_map(|p| &p.waiters))
    }
    pub(super) fn cancel_unused_discovery(&mut self) {
        if let Some(d) = &mut self.discovery {
            d.retain_jobs(|id| self.discovered.values().any(|p| p.job == id));
        }
    }
    pub(super) fn submit_discovery(
        &mut self,
        m: Message,
        key: Vec<u8>,
        waiter: Waiter,
        now: u64,
    ) -> io::Result<Vec<Action>> {
        if self.waiter_count() >= WAITERS
            || self
                .waiters()
                .filter(|w| w.client.address.ip() == waiter.client.address.ip())
                .count()
                >= 8
            || self.pending_bytes() + 1024 > BYTES
        {
            return Err(capacity());
        }
        if let Some(p) = self.discovered.values_mut().find(|p| p.key == key) {
            p.waiters.push(waiter);
            return Ok(vec![]);
        }
        if self.pending_count() >= PENDING {
            return Err(capacity());
        }
        let mut p = Discovered {
            key,
            question: m.questions[0].clone(),
            original: m,
            job: 0,
            waiters: vec![waiter],
            base: None,
            forward_cache: false,
        };
        // Credit covers the proxy's translated names and job before mutating it.
        if self.pending_bytes() + p.charge() + 8192 > BYTES {
            return Err(capacity());
        }
        let next = self.next.checked_add(1).ok_or_else(capacity)?;
        p.job = self
            .discovery
            .as_mut()
            .unwrap()
            .start(p.question.clone(), now)?;
        self.next = next;
        self.discovered.insert(next, p);
        Ok(vec![])
    }
    pub fn poll_discovery(
        &mut self,
        engine: &mut crate::mdns::Engine,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        self.poll_discovery_with_source(engine, &|id, at, r| r.advertised(id, at), now, rng)
    }
    pub fn poll_discovery_with_source(
        &mut self,
        engine: &mut crate::mdns::Engine,
        source: &impl Fn(u64, u64, &Self) -> Vec<Record>,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        if self.discovery.is_none() {
            return Ok(vec![]);
        }
        let local = engine
            .publisher
            .all_ready(&|id, at| source(id, at, self), now)?;
        let proxy = self.discovery.as_mut().unwrap();
        let completed = proxy.poll_with_local(
            &mut engine.querier,
            &|q| {
                local
                    .iter()
                    .filter(|(_, r)| {
                        crate::mdns::cache::matches(q, r) || (r.name == q.name && r.kind == 47)
                    })
                    .map(|(_, r)| r.clone())
                    .collect()
            },
            now,
            rng,
        )?;
        let mut out = vec![];
        for done in completed {
            let ids: Vec<_> = self
                .discovered
                .iter()
                .filter_map(|(id, p)| (p.job == done.id).then_some(*id))
                .collect();
            for id in ids {
                let mut p = self.discovered.remove(&id).unwrap();
                let mut answer = done.answer.clone();
                answer.id = p.original.id;
                answer.flags |= p.original.flags & 0x110;
                let bytes = if let Some(base) = p.base.take() {
                    augment(&base, &answer, &p.question.name).unwrap_or(base)
                } else {
                    let bytes = answer.encode()?;
                    if let Some(aq) = additional_question(&answer, &p.question, self.additional_a) {
                        out.extend(self.continue_additional(p, aq, bytes, now, rng)?);
                        continue;
                    }
                    bytes
                };
                out.extend(self.finish_discovered(p, bytes, now)?);
            }
        }
        Ok(out)
    }
    fn finish_discovered(
        &mut self,
        p: Discovered,
        bytes: Vec<u8>,
        now: u64,
    ) -> io::Result<Vec<Action>> {
        if p.forward_cache {
            self.store(p.key, &bytes, now)?;
        }
        p.waiters.into_iter().map(|w| deliver(w, &bytes)).collect()
    }
    pub(super) fn continue_additional(
        &mut self,
        mut p: Discovered,
        question: Question,
        base: Vec<u8>,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        if let Some(registry) = self
            .registry()
            .filter(|r| !r.records(&question.name, 255, now).is_empty())
        {
            let mut answer = Message::new(0, 0x8400);
            answer.questions.push(question.clone());
            answer.answers = registry.records(&question.name, question.kind, now);
            let bytes = augment(&base, &answer, &question.name).unwrap_or(base);
            p.forward_cache = false;
            return self.finish_discovered(p, bytes, now);
        }
        if self.pending_bytes() + p.charge() + 16 * base.len() + 8192 > BYTES {
            return self.finish_discovered(p, base, now);
        }
        if let Some(d) = self.discovery.as_mut().filter(|d| d.accepts(&question)) {
            if let Ok(job) = d.start(question.clone(), now) {
                p.job = job;
                p.question = question;
                p.base = Some(base);
                p.forward_cache = false;
                self.next = self.next.wrapping_add(1);
                self.discovered.insert(self.next, p);
                return Ok(vec![]);
            }
            return self.finish_discovered(p, base, now);
        }
        if in_zone(&question.name, &"service.arpa.".parse().unwrap())
            || self.local_zones.iter().any(|z| in_zone(&question.name, z))
            || self.upstreams.is_empty()
        {
            return self.finish_discovered(p, base, now);
        }
        let mut m = Message::new(0, 0x100 | (p.original.flags & 0x10));
        m.questions.push(question.clone());
        m.additional = p.original.additional.clone();
        let query = self.make_query(&m.encode()?, self.upstreams[0], rng)?;
        let pending = Pending {
            key: p.key,
            original: p.original,
            query: query.clone(),
            question,
            waiters: p.waiters,
            deadline: now.saturating_add(10000),
            retry: now.saturating_add(1000),
            attempt: 0,
            base: Some(base),
            forward_cache: p.forward_cache,
        };
        self.pending.insert(query.exchange, pending);
        Ok(vec![Action::Upstream(query)])
    }
}
