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
    pub state: PdState,
    pub exchange: Option<Exchange>,
    pub sol_max_rt: u64,
}
impl Default for PdClient {
    fn default() -> Self {
        Self {
            state: PdState::Dormant,
            exchange: None,
            sol_max_rt: 3600000,
        }
    }
}
impl PdClient {
    pub fn start(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
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
            let mut hint = vec![0; 25];
            hint[8] = 64;
            ia.extend(option(26, &hint));
            b.extend(option(25, &ia));
        }
        let packet = udp_packet(source, "ff02::1:2".parse().unwrap(), 546, 547, &b)
            .map_err(|_| io::Error::other("DHCP packet capacity"))?;
        e.interval = if e.count == 0 {
            1001 + rng.sample(199)?
        } else {
            let base = e.interval.saturating_mul(2).min(self.sol_max_rt);
            base * 9 / 10 + rng.sample(base / 5)?
        };
        e.next = now + e.interval;
        e.count = e.count.saturating_add(1);
        Ok(vec![packet])
    }
}
