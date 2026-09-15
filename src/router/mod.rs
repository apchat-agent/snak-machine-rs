pub mod pd;
mod restart;
mod routes;
pub use routes::Route;
mod owned;
pub use owned::{DadState, OwnedAddress};
mod nd;
use crate::{
    persist::Identity,
    scheduler::RaScheduler,
    time::{Lifetime, RandomSource, Time},
    wire::*,
    Link,
};
pub use nd::{Neighbor, NeighborState};
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
    pub up: bool,
    pub state: AilState,
    pub scheduler: RaScheduler,
    rs_count: u8,
    rs_next: Time,
    discovery_end: Time,
    pub last_valid: Lifetime,
    pub deprecate_at: Option<Time>,
}
#[derive(Clone, Debug)]
pub struct Header {
    pub last_ra_at: Time,
    pub snac: bool,
    pub mo: u8,
    pub header_lifetime: Option<Lifetime>,
}
pub struct Router {
    pub pd_hints: BTreeMap<Prefix, Lifetime>,
    pub pd: pd::PdClient,
    pub pd_prefixes: BTreeMap<Prefix, pd::OwnedPrefix>,
    pub withdrawals: BTreeMap<(Link, Prefix), u8>,
    pub routes: BTreeMap<(Ipv6Addr, Prefix), Route>,
    pub no_stub_default: bool,
    pub always_advertise_ail_routes: bool,
    pub owned: BTreeMap<(Link, Ipv6Addr), OwnedAddress>,
    pub neighbors: BTreeMap<RouterKey, Neighbor>,
    pub headers: BTreeMap<RouterKey, Header>,
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
                up: true,
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
            pd_hints: BTreeMap::new(),
            pd: pd::PdClient::default(),
            pd_prefixes: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            routes: BTreeMap::new(),
            no_stub_default: false,
            always_advertise_ail_routes: false,
            owned: [Link::Ail, Link::Stub]
                .into_iter()
                .map(|l| {
                    (
                        (l, identity.link_local(l)),
                        OwnedAddress {
                            prefix: None,
                            state: DadState::Ready,
                            deadline: None,
                            attempts: 0,
                        },
                    )
                })
                .collect(),
            neighbors: BTreeMap::new(),
            headers: BTreeMap::new(),
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
        if !self.links[link.index()].up {
            return Ok(vec![]);
        }
        let Ok(e) = envelope(FrameKind::RawIpv6, packet) else {
            return Ok(vec![]);
        };
        if e.source == self.identity.link_local(link) {
            return Ok(vec![]);
        }
        if link == Link::Ail
            && e.destination == self.identity.link_local(link)
            && e.next_header == 17
        {
            self.pd.receive(&e, &self.identity.duid, now, rng)?;
            self.sync_pd(now, rng)?;
            return Ok(self
                .pd
                .poll(
                    now,
                    self.identity.link_local(link),
                    &self.identity.duid,
                    rng,
                )?
                .into_iter()
                .map(|packet| Tx { link, packet })
                .collect());
        }
        let Ok(nd) = decode_nd(&e) else {
            return Ok(vec![]);
        };
        if let Some(out) = self.owned_nd(link, &e, &nd, now, rng)? {
            return Ok(out);
        }
        if nd.kind == 133 {
            if self.state(link) == AilState::Suitable && !self.confirmed_supplier(link, now) {
                self.links[link.index()].state = AilState::BeginAdvertising;
                self.links[link.index()].deprecate_at = None;
                self.links[link.index()].scheduler.changed(now, rng)?;
            }
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
            self.observe_routes(key, &nd, now, rng)?;
            let raw_life = u16::from_be_bytes([nd.body[6], nd.body[7]]);
            self.headers.insert(
                key,
                Header {
                    last_ra_at: now,
                    snac: nd.body[5] & 2 != 0,
                    mo: if link == Link::Ail && nd.body[5] & 2 == 0 {
                        nd.body[5] & 0xc0
                    } else {
                        0
                    },
                    header_lifetime: if raw_life == 0 {
                        None
                    } else {
                        Some(Lifetime::from_secs(now, raw_life as u32))
                    },
                },
            );
            for o in &nd.options {
                if let Some(p) = Pio::decode(o.bytes) {
                    if link == Link::Ail {
                        let had = self.pd_hints.contains_key(&p.prefix);
                        let has = p.flags & 0x10 != 0 && p.preferred > 0 && p.preferred <= p.valid;
                        if has {
                            self.pd_hints
                                .insert(p.prefix, Lifetime::from_secs(now, p.preferred));
                        } else {
                            self.pd_hints.remove(&p.prefix);
                        }
                        if had != has
                            && !self.pd_hints.is_empty()
                            && self
                                .pd
                                .exchange
                                .as_ref()
                                .is_none_or(|e| now.saturating_sub(e.started) >= 1000)
                        {
                            self.pd.refresh(6, now, rng)?;
                        }
                    }

                    if p.on_link() && p.prefix.routable() {
                        if link == Link::Stub
                            && !self.on_link.contains_key(&(link, p.prefix))
                            && p.valid > 0
                        {
                            self.links[0].scheduler.changed(now, rng)?;
                        }

                        self.on_link.insert(
                            (link, p.prefix),
                            OnLink {
                                valid: Lifetime::from_secs(now, p.valid),
                                preferred: Lifetime::from_secs(now, p.preferred),
                            },
                        );
                    }
                    if p.suitable() {
                        let own = self.identity.prefix(link);
                        if self.state(link) == AilState::Advertising
                            && p.prefix != own
                            && ((link == Link::Ail && nd.body[5] & 2 == 0)
                                || (own.ula() && (!p.prefix.ula() || p.prefix < own))
                                || (link == Link::Stub
                                    && !own.ula()
                                    && !p.prefix.ula()
                                    && p.prefix < own))
                        {
                            self.links[link.index()].state = AilState::Deprecating;
                            self.links[link.index()].deprecate_at = Some(now);
                            self.links[link.index()].scheduler.changed(now, rng)?;
                        }

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
        self.observe_neighbor(link, &e, &nd, now)
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
        if state.state == AilState::Deprecating {
            if let Some(at) = state.deprecate_at {
                let valid = Lifetime::from_secs(at, 1800).remaining(now);
                if valid >= 206 {
                    pios.push(Pio {
                        prefix: self.identity.prefix(link),
                        flags: 0xc0,
                        preferred: 0,
                        valid,
                    });
                }
            }
        }
        if link == Link::Stub {
            pios.extend(self.delegated_pios(now));
            pios.sort_by_key(|p| p.prefix);
        }
        let mut rios: Vec<Rio> = if link == Link::Ail {
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
            self.stub_routes(now)
        };
        if link == Link::Ail {
            rios.sort_by_key(|r| {
                let p = &self.on_link[&(Link::Stub, r.prefix)];
                (
                    std::cmp::Reverse(p.preferred.live(now)),
                    std::cmp::Reverse(p.valid),
                    r.prefix,
                )
            });
            rios.truncate((1280usize.saturating_sub(40 + 16 + 8 + pios.len() * 32)) / 16);
            rios.sort_by_key(|r| r.prefix);
        }
        Advertisement {
            link,
            source: self.identity.link_local(link),
            destination: "ff02::1".parse().unwrap(),
            mac: Some(self.identity.macs[link.index()]),
            mtu: 1500,
            mo: self
                .headers
                .iter()
                .filter(|(k, h)| {
                    k.link == Link::Ail && !h.snac && h.header_lifetime.is_none_or(|l| l.live(now))
                })
                .max_by_key(|(_, h)| h.last_ra_at)
                .map_or(0, |(_, h)| h.mo),
            default_lifetime: if link == Link::Stub {
                self.default_lifetime(now)
            } else {
                0
            },
            pios,
            rios,
        }
    }
    pub fn tick(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<Vec<Tx>> {
        if self.links[0].up {
            self.pd.advance(now, rng)?;
        }
        self.pd_hints.retain(|_, l| l.live(now));
        self.sync_pd(now, rng)?;
        self.tick_dad(now);
        let mut out = self.tick_neighbors(now)?;
        self.suppliers.retain(|_, s| {
            s.valid.live(now) && s.preferred.live(now) && now < s.pio_at.saturating_add(600000)
        });
        self.on_link.retain(|_, p| p.valid.live(now));
        for link in [Link::Stub, Link::Ail] {
            if !self.links[link.index()].up
                || !self.address_ready(link, self.identity.link_local(link))
            {
                continue;
            }
            let fresh = (link == Link::Stub && !self.pd.selected(now).is_empty())
                || self.suppliers.iter().any(|((k, _), _)| {
                    k.link == link
                        && self
                            .neighbors
                            .get(k)
                            .is_none_or(|n| n.state != NeighborState::Failed)
                });
            if matches!(self.state(link), AilState::Suitable | AilState::Deprecating)
                && (!fresh
                    || (self.links[link.index()].scheduler.due(now)
                        && !self.confirmed_supplier(link, now)
                        && !(link == Link::Stub && !self.pd.selected(now).is_empty())))
            {
                self.links[link.index()].state = AilState::BeginAdvertising;
                self.links[link.index()].deprecate_at = None;
                self.links[link.index()].scheduler.changed(now, rng)?;
            }

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
                self.on_link
                    .entry((link, self.identity.prefix(link)))
                    .or_insert(OnLink {
                        valid: Lifetime::from_secs(now, 1800),
                        preferred: Lifetime::from_secs(now, 1800),
                    });
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
        if self.links[0].up
            && self.address_ready(Link::Ail, self.identity.link_local(Link::Ail))
            && (self.pd.state != pd::PdState::Dormant
                || matches!(
                    self.state(Link::Stub),
                    AilState::BeginAdvertising | AilState::Advertising | AilState::Deprecating
                ))
        {
            if self.pd.state == pd::PdState::Dormant {
                self.pd.start(now, rng)?;
            }
            for packet in self.pd.poll(
                now,
                self.identity.link_local(Link::Ail),
                &self.identity.duid,
                rng,
            )? {
                out.push(Tx {
                    link: Link::Ail,
                    packet,
                });
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
        if state.state == AilState::Deprecating
            && !nd.options.iter().any(|o| Pio::decode(o.bytes).is_some())
        {
            state.state = AilState::Suitable;
        }
        for o in &nd.options {
            if let Some(r) = Rio::decode(o.bytes) {
                if r.lifetime == 0 {
                    if let Some(count) = self.withdrawals.get_mut(&(tx.link, r.prefix)) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
        }
        self.withdrawals.retain(|_, count| *count > 0);
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
