use super::*;
pub(super) struct Discovered {
    key: Vec<u8>,
    original: Message,
    question: Question,
    job: u64,
    pub(super) waiters: Vec<Waiter>,
    base: Option<Vec<u8>>,
}
impl Discovered {
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
        let Some(proxy) = &mut self.discovery else {
            return Ok(vec![]);
        };
        let completed = proxy.poll(&mut engine.querier, now, rng)?;
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
                        let fits =
                            self.pending_bytes() + p.charge() + 16 * bytes.len() + 8192 <= BYTES;
                        let d = self.discovery.as_mut().unwrap();
                        if d.accepts(&aq) && fits {
                            if let Ok(job) = d.start(aq.clone(), now) {
                                p.base = Some(bytes);
                                p.question = aq;
                                p.job = job;
                                self.discovered.insert(id, p);
                                continue;
                            }
                        }
                    }
                    bytes
                };
                out.extend(
                    p.waiters
                        .into_iter()
                        .map(|w| deliver(w, &bytes))
                        .collect::<io::Result<Vec<_>>>()?,
                );
            }
        }
        Ok(out)
    }
}
