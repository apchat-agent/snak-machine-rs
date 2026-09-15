use crate::{
    persist::Identity,
    scheduler::RaScheduler,
    time::{Lifetime, RandomSource, Time},
    wire::*,
    Link,
};
use std::{collections::BTreeMap, io, net::Ipv6Addr};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AilState {
    Unknown,
    Suitable,
    BeginAdvertising,
    Advertising,
    Deprecating,
}
#[derive(Clone, Debug)]
pub struct Tx {
    pub link: Link,
    pub packet: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RouterKey {
    pub link: Link,
    pub address: Ipv6Addr,
}
#[derive(Clone, Debug)]
pub struct Supplier {
    pub pio_at: Time,
    pub preferred: Lifetime,
    pub valid: Lifetime,
}
#[derive(Clone, Debug)]
pub struct OnLink {
    pub valid: Lifetime,
    pub preferred: Lifetime,
}
pub struct LinkState {
    pub state: AilState,
    pub scheduler: RaScheduler,
    rs_count: u8,
    rs_next: Time,
    discovery_end: Time,
    pub last_valid: Lifetime,
    pub deprecate_at: Option<Time>,
}
pub struct Router {
    pub identity: Identity,
    pub links: [LinkState; 2],
    pub suppliers: BTreeMap<(RouterKey, Prefix), Supplier>,
    pub on_link: BTreeMap<(Link, Prefix), OnLink>,
}
impl Router {
    pub fn new(identity: Identity, now: Time, rng: &mut impl RandomSource) -> io::Result<Self> {
        fn link(now: Time, rng: &mut impl RandomSource) -> io::Result<LinkState> {
            let first = now + rng.sample(1000)?;
            Ok(LinkState {
                state: AilState::Unknown,
                scheduler: RaScheduler::new(now, rng)?,
                rs_count: 0,
                rs_next: first,
                discovery_end: first + 9000,
                last_valid: Lifetime::Until(now),
                deprecate_at: None,
            })
        }
        Ok(Self {
            identity,
            links: [link(now, rng)?, link(now, rng)?],
            suppliers: BTreeMap::new(),
            on_link: BTreeMap::new(),
        })
    }
    pub fn state(&self, link: Link) -> AilState {
        self.links[link.index()].state
    }
    pub fn receive(
        &mut self,
        link: Link,
        packet: &[u8],
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Tx>> {
        let Ok(e) = envelope(FrameKind::RawIpv6, packet) else {
            return Ok(vec![]);
        };
        if e.source == self.identity.link_local(link) {
            return Ok(vec![]);
        }
        let Ok(nd) = decode_nd(&e) else {
            return Ok(vec![]);
        };
        if nd.kind == 133 {
            self.links[link.index()]
                .scheduler
                .receive_rs(&e, now, rng)?;
        }
        if nd.kind == 134 {
            if u16::from_be_bytes([nd.body[6], nd.body[7]]) > 0 {
                self.links[link.index()].rs_count = 3;
            }
            let key = RouterKey {
                link,
                address: e.source,
            };
            for o in &nd.options {
                if let Some(p) = Pio::decode(o.bytes) {
                    if p.on_link() && p.prefix.routable() {
                        self.on_link.insert(
                            (link, p.prefix),
                            OnLink {
                                valid: Lifetime::from_secs(now, p.valid),
                                preferred: Lifetime::from_secs(now, p.preferred),
                            },
                        );
                    }
                    if p.suitable() {
                        self.suppliers.insert(
                            (key, p.prefix),
                            Supplier {
                                pio_at: now,
                                preferred: Lifetime::from_secs(now, p.preferred),
                                valid: Lifetime::from_secs(now, p.valid),
                            },
                        );
                        if self.state(link) == AilState::Unknown {
                            self.links[link.index()].state = AilState::Suitable;
                        }
                    } else if p.on_link() {
                        self.suppliers.remove(&(key, p.prefix));
                    }
                }
            }
        }
        Ok(vec![])
    }
    pub fn snapshot(&self, link: Link, now: Time) -> Advertisement {
        let mut pios = vec![];
        let state = &self.links[link.index()];
        if matches!(
            state.state,
            AilState::BeginAdvertising | AilState::Advertising
        ) {
            pios.push(Pio {
                prefix: self.identity.prefix(link),
                flags: 0xc0,
                preferred: 1800,
                valid: 1800,
            });
        }
        let rios = if link == Link::Ail {
            self.on_link
                .iter()
                .filter(|((l, _), v)| *l == Link::Stub && v.valid.live(now))
                .map(|((_, p), v)| Rio {
                    prefix: *p,
                    preference: Preference::Low,
                    lifetime: v.valid.remaining(now).min(1800),
                })
                .collect()
        } else {
            vec![]
        };
        Advertisement {
            link,
            source: self.identity.link_local(link),
            destination: "ff02::1".parse().unwrap(),
            mac: Some(self.identity.macs[link.index()]),
            mtu: 1500,
            mo: 0,
            default_lifetime: 0,
            pios,
            rios,
        }
    }
    pub fn tick(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<Vec<Tx>> {
        let mut out = vec![];
        for link in [Link::Stub, Link::Ail] {
            let s = &mut self.links[link.index()];
            if s.state == AilState::Unknown {
                if now >= s.discovery_end {
                    s.state = AilState::BeginAdvertising;
                } else if now >= s.rs_next && s.rs_count < 3 {
                    let mut body = vec![133, 0, 0, 0, 0, 0, 0, 0];
                    body.extend([1, 1]);
                    body.extend(self.identity.macs[link.index()]);
                    out.push(Tx {
                        link,
                        packet: icmp_packet(
                            self.identity.link_local(link),
                            "ff02::2".parse().unwrap(),
                            255,
                            body,
                        )
                        .map_err(|_| io::Error::other("RS encoding"))?,
                    });
                    s.rs_count += 1;
                    s.rs_next = now + 4000;
                }
            }
            if s.state == AilState::BeginAdvertising {
                self.on_link.insert(
                    (link, self.identity.prefix(link)),
                    OnLink {
                        valid: Lifetime::from_secs(now, 1800),
                        preferred: Lifetime::from_secs(now, 1800),
                    },
                );
            }
            if self.state(link) != AilState::Unknown && self.links[link.index()].scheduler.due(now)
            {
                let snap = self.snapshot(link, now);
                if link == Link::Stub || !snap.pios.is_empty() || !snap.rios.is_empty() {
                    out.push(Tx {
                        link,
                        packet: snap.encode().map_err(|_| io::Error::other("RA capacity"))?,
                    });
                }
            }
        }
        Ok(out)
    }
    pub fn transmitted(
        &mut self,
        tx: &Tx,
        now: Time,
        success: bool,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if !success {
            return Ok(());
        }
        let Ok(e) = envelope(FrameKind::RawIpv6, &tx.packet) else {
            return Ok(());
        };
        let Ok(nd) = decode_nd(&e) else { return Ok(()) };
        if nd.kind != 134 {
            return Ok(());
        }
        let state = &mut self.links[tx.link.index()];
        state.scheduler.sent(now, rng)?;
        if state.state == AilState::BeginAdvertising {
            state.state = AilState::Advertising;
        }
        for o in nd.options {
            if let Some(p) = Pio::decode(o.bytes) {
                state.last_valid = Lifetime::from_secs(now, p.valid);
                self.on_link.insert(
                    (tx.link, p.prefix),
                    OnLink {
                        valid: state.last_valid,
                        preferred: Lifetime::from_secs(now, p.preferred),
                    },
                );
            }
        }
        Ok(())
    }
}
