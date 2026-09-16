use super::*;
impl Resolver {
    pub fn configure_browsing(&mut self, contexts: &[Name], now: u64) -> io::Result<()> {
        self.browsing.sync(&self.upstreams, contexts, now)?;
        self.pending.retain(
            |_, p| !matches!(p.purpose, Purpose::Browse(id) if !self.browsing.live(id,now)),
        );
        Ok(())
    }
    pub fn poll_browsing(&mut self, now: u64, rng: &mut impl RandomSource) -> io::Result<()> {
        for probe in self.browsing.poll(now)? {
            if self.pending_count() >= PENDING || self.pending_bytes() + 16384 > BYTES {
                continue;
            }
            let mut message = Message::new(0, 0x100);
            message.questions.push(probe.question.clone());
            let bytes = message.encode()?;
            let query = self.make_query(&bytes, probe.origin, now, rng)?;
            let p = Pending {
                purpose: Purpose::Browse(probe.id),
                key: vec![],
                original: Message::parse(&bytes, Context::Unicast)?,
                query: query.clone(),
                question: probe.question,
                waiters: vec![],
                deadline: probe.until,
                retry: probe.until,
                attempt: 0,
                base: None,
                forward_cache: false,
                aliases: BTreeSet::new(),
            };
            if self.pending_bytes() + p.charge() <= BYTES {
                self.pending.insert(query.exchange, p);
            }
        }
        Ok(())
    }
    pub(super) fn merge_browsing(&self, m: &mut Message, now: u64) {
        let Some(q) = m.questions.first() else {
            return;
        };
        let labels = q.name.labels();
        if !matches!(q.kind, 12 | 255)
            || labels.len() < 4
            || !labels[1].eq_ignore_ascii_case(b"_dns-sd")
            || !labels[2].eq_ignore_ascii_case(b"_udp")
            || ![b"b".as_slice(), b"lb"]
                .iter()
                .any(|b| labels[0].eq_ignore_ascii_case(b))
        {
            return;
        }
        for (domain, ttl) in self
            .browsing
            .domains(labels[0].eq_ignore_ascii_case(b"lb"), now)
        {
            if !m
                .answers
                .iter()
                .any(|r| r.kind == 12 && r.data == Rdata::Name(domain.clone()))
            {
                m.answers.push(Record {
                    name: q.name.clone(),
                    kind: 12,
                    class: 1,
                    ttl: ttl.min(10),
                    data: Rdata::Name(domain),
                });
            }
        }
    }
}
