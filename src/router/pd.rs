use super::*;
use crate::wire::dhcpv6::*;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PdState {
    Dormant,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}
#[derive(Clone, Debug)]
pub struct Exchange {
    pub kind: u8,
    pub xid: [u8; 3],
    pub started: Time,
    pub next: Time,
    pub interval: u64,
    pub count: u8,
    pub server: Vec<u8>,
}
#[derive(Debug)]
pub struct PdClient {
    pub offers: Vec<Message>,
    pub requested: Vec<Delegation>,
    pub state: PdState,
    pub exchange: Option<Exchange>,
    pub sol_max_rt: u64,
}
impl Default for PdClient {
    fn default() -> Self {
        Self {
            offers: vec![],
            requested: vec![],
            state: PdState::Dormant,
            exchange: None,
            sol_max_rt: 3600000,
        }
    }
}
impl PdClient {
    pub fn start(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.offers.clear();
        self.requested.clear();
        self.state = PdState::Soliciting;
        self.begin(1, vec![], now, now + rng.sample(1000)?, rng)
    }
    fn begin(
        &mut self,
        kind: u8,
        server: Vec<u8>,
        now: Time,
        next: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let mut xid = [0; 3];
        rng.fill(&mut xid)?;
        self.exchange = Some(Exchange {
            kind,
            xid,
            started: now,
            next,
            interval: 0,
            count: 0,
            server,
        });
        Ok(())
    }
    pub fn poll(
        &mut self,
        now: Time,
        source: Ipv6Addr,
        duid: &[u8],
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Vec<u8>>> {
        if self.state == PdState::Soliciting
            && !self.offers.is_empty()
            && self.exchange.as_ref().is_some_and(|e| now >= e.next)
        {
            self.choose(now, rng)?;
        }
        if self.state == PdState::Requesting
            && self
                .exchange
                .as_ref()
                .is_some_and(|e| e.count >= 10 && now >= e.next)
        {
            self.start(now, rng)?;
        }
        let Some(e) = &mut self.exchange else {
            return Ok(vec![]);
        };
        if now < e.next {
            return Ok(vec![]);
        }
        let mut b = vec![e.kind];
        b.extend(e.xid);
        b.extend(option(1, duid));
        if !e.server.is_empty() {
            b.extend(option(2, &e.server));
        }
        b.extend(option(
            8,
            &((now.saturating_sub(e.started) / 10).min(65535) as u16).to_be_bytes(),
        ));
        b.extend(option(6, &[0, 82]));
        for iaid in [1u32, 2] {
            let mut ia = iaid.to_be_bytes().to_vec();
            ia.extend([0; 8]);
            let ds: Vec<_> = self.requested.iter().filter(|d| d.iaid == iaid).collect();
            if e.kind == 1 || ds.is_empty() {
                let mut hint = vec![0; 25];
                hint[8] = 64;
                ia.extend(option(26, &hint));
            } else {
                for d in ds {
                    ia.extend(delegation_option(d));
                }
            }
            b.extend(option(25, &ia));
        }
        let packet = udp_packet(source, "ff02::1:2".parse().unwrap(), 546, 547, &b)
            .map_err(|_| io::Error::other("DHCP packet capacity"))?;
        e.interval = if e.count == 0 {
            if e.kind == 1 {
                1001 + rng.sample(199)?
            } else {
                900 + rng.sample(200)?
            }
        } else {
            let base =
                e.interval
                    .saturating_mul(2)
                    .min(if e.kind == 1 { self.sol_max_rt } else { 30000 });
            base * 9 / 10 + rng.sample(base / 5)?
        };
        e.next = now + e.interval;
        e.count = e.count.saturating_add(1);
        Ok(vec![packet])
    }
}

impl PdClient {
    fn choose(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.offers.sort_by_key(|m| {
            (
                std::cmp::Reverse(m.preference),
                std::cmp::Reverse(m.delegations.iter().map(|d| d.preferred).max().unwrap_or(0)),
                m.server.clone(),
            )
        });
        let offer = self.offers.remove(0);
        self.offers.clear();
        self.requested = offer
            .delegations
            .into_iter()
            .filter(|d| d.prefix.length <= 64 && d.prefix.routable() && d.preferred >= 1800)
            .collect();
        self.state = PdState::Requesting;
        self.begin(3, offer.server, now, now, rng)
    }
    pub fn receive(
        &mut self,
        e: &Envelope<'_>,
        duid: &[u8],
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let Ok(b) = udp_payload(e) else { return Ok(()) };
        let Ok(m) = decode(b) else { return Ok(()) };
        let Some(exchange) = &self.exchange else {
            return Ok(());
        };
        if m.xid != exchange.xid || m.client != duid {
            return Ok(());
        }
        if self.state == PdState::Soliciting && m.kind == 2 {
            if let Some(max) = m.sol_max_rt {
                self.sol_max_rt = max as u64 * 1000;
            }
            if m.status != 0
                || !m
                    .delegations
                    .iter()
                    .any(|d| d.prefix.length <= 64 && d.prefix.routable() && d.preferred >= 1800)
            {
                return Ok(());
            }
            if self.offers.len() >= 16 {
                return Err(io::Error::other("DHCP offer capacity"));
            }
            let immediate = m.preference == 255;
            self.offers.push(m);
            if immediate {
                self.choose(now, rng)?;
            }
        }
        Ok(())
    }
}
