use super::*;
use crate::dns::privacy::{Policy, Probe, TlsProbe};
impl Resolver {
    pub fn configure_upstream_privacy(
        &mut self,
        origins: &[SocketAddr],
        explicit: bool,
        now: u64,
    ) -> io::Result<()> {
        self.set_upstreams(origins)?;
        self.browsing.set_origins(origins, now)?;
        self.pending.retain(|_, p| match p.purpose {
            Purpose::Client => true,
            Purpose::Ddr(_) => !explicit && origins.contains(&p.query.origin),
            Purpose::Browse(id) => self.browsing.live(id, now),
        });
        self.privacy
            .get_or_insert_with(Policy::default)
            .sync(origins, explicit, now)
    }
    pub fn upstream_route(&self, origin: SocketAddr, now: u64) -> crate::dns::privacy::Route {
        self.privacy.as_ref().map_or(
            crate::dns::privacy::Route::Plain {
                reason: "automatic privacy not configured",
            },
            |p| p.route(origin, now),
        )
    }
    pub fn poll_privacy(
        &mut self,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<TlsProbe>> {
        let Some(policy) = &mut self.privacy else {
            return Ok(vec![]);
        };
        let probes = policy.poll(now)?;
        let mut tls = vec![];
        for probe in probes {
            match probe {
                Probe::Tls(probe) => tls.push(probe),
                Probe::Ddr(probe) => {
                    if self.pending_count() >= PENDING || self.pending_bytes() + 16384 > BYTES {
                        continue;
                    }
                    let mut message = Message::new(0, 0x100);
                    message.questions.push(Question {
                        name: probe.name,
                        kind: 64,
                        class: 1,
                    });
                    let bytes = message.encode()?;
                    let mut query = self.make_query(&bytes, probe.origin, now, rng)?;
                    query.server = probe.origin;
                    query.tls = None;
                    query.tcp = false;
                    let pending = Pending {
                        purpose: Purpose::Ddr(probe.id),
                        key: vec![],
                        question: message.questions[0].clone(),
                        original: Message::parse(&bytes, Context::Unicast)?,
                        query: query.clone(),
                        waiters: vec![],
                        deadline: now.saturating_add(3000),
                        retry: now.saturating_add(3000),
                        attempt: 0,
                        base: None,
                        forward_cache: false,
                        aliases: BTreeSet::new(),
                    };
                    if self.pending_bytes() + pending.charge() <= BYTES {
                        self.pending.insert(query.exchange, pending);
                    }
                }
            }
        }
        Ok(tls)
    }
    pub(crate) fn live_tls(
        &self,
        origin: SocketAddr,
        endpoint: SocketAddr,
        name: &str,
        now: u64,
    ) -> bool {
        self.privacy
            .as_ref()
            .is_some_and(|p| p.live_tls(origin, endpoint, name, now))
    }
    pub(crate) fn tls_failed(&mut self, origin: SocketAddr, endpoint: SocketAddr, now: u64) {
        if let Some(p) = &mut self.privacy {
            p.failed(origin, endpoint, now);
        }
    }
    pub fn complete_tls_probe(&mut self, token: u64, success: bool, now: u64) {
        if let Some(p) = &mut self.privacy {
            p.complete_tls(token, success, now);
        }
    }
    pub fn fail_upstream(
        &mut self,
        exchange: u64,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        let Some(mut p) = self.pending.remove(&exchange) else {
            return Ok(vec![]);
        };
        if p.query.tls.is_some() {
            if let Some(policy) = &mut self.privacy {
                policy.failed(p.query.origin, p.query.server, now);
            }
        }
        if now >= p.deadline || self.upstreams.is_empty() || !matches!(p.purpose, Purpose::Client) {
            let bytes = match p.base.take() {
                Some(b) => b,
                None => failure(&p.original, 2)?,
            };
            return self.finish(p, bytes, now, rng);
        }
        let origin = if self.upstreams.contains(&p.query.origin) {
            p.query.origin
        } else {
            self.upstreams[0]
        };
        p.query = self.make_query(&p.query.bytes, origin, now, rng)?;
        p.retry = now.saturating_add(1000).min(p.deadline);
        let action = Action::Upstream(p.query.clone());
        self.pending.insert(p.query.exchange, p);
        Ok(vec![action])
    }
}
