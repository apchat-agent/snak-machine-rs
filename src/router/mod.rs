mod on_link;
pub use on_link::{OnLink, OnLinkTable};
pub mod attachment;
mod budget;
mod lifecycle;
pub use lifecycle::Lifecycle;
mod forward;
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
pub use nd::{Neighbor, NeighborState, Pending};
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
pub struct LinkState {
    pub mac: Option<[u8; 6]>,
    pub mtu: u32,
    pub kind: FrameKind,
    pub up: bool,
    pub state: AilState,
    pub scheduler: RaScheduler,
    rs_count: u8,
    rs_next: Time,
    discovery_end: Time,
    pub last_valid: Lifetime,
    pub deprecate_at: Option<i128>,
}
#[derive(Clone, Debug)]
pub struct Header {
    pub last_ra_at: Time,
    pub snac: bool,
    pub mo: u8,
    pub header_lifetime: Option<Lifetime>,
}
pub struct Router {
    pub ail_frames: crate::io::families::AilFrames,
    pub attachment: attachment::Attachment,
    pub retired_ulas: BTreeMap<(Link, Prefix), Lifetime>,
    pub lifecycle: Lifecycle,
    final_ras: [u8; 2],
    pub error_after: Option<Time>,
    pub pd_hints: BTreeMap<Prefix, Lifetime>,
    pub pd: pd::PdClient,
    pub pd_prefixes: BTreeMap<Prefix, pd::OwnedPrefix>,
    pub withdrawals: BTreeMap<(Link, Prefix), u8>,
    // Only successfully exported RIOs, bounded by each link's withdrawal budget.
    pub advertised_routes: BTreeMap<(Link, Prefix), Lifetime>,
    pub routes: BTreeMap<(Ipv6Addr, Prefix), Route>,
    pub no_stub_default: bool,
    pub always_advertise_ail_routes: bool,
    pub owned: BTreeMap<(Link, Ipv6Addr), OwnedAddress>,
    pub neighbors: BTreeMap<RouterKey, Neighbor>,
    pub headers: BTreeMap<RouterKey, Header>,
    pub identity: Identity,
    pub links: [LinkState; 2],
    pub suppliers: BTreeMap<(RouterKey, Prefix), Supplier>,
    pub on_link: OnLinkTable,
}
impl Router {
    pub fn new(identity: Identity, now: Time, rng: &mut impl RandomSource) -> io::Result<Self> {
        fn link(now: Time, rng: &mut impl RandomSource) -> io::Result<LinkState> {
            let first = now + rng.sample(1000)?;
            Ok(LinkState {
                mac: None,
                mtu: 1500,
                kind: FrameKind::Ethernet,
                up: true,
                state: AilState::Unknown,
                scheduler: RaScheduler::new(now, rng)?,
                rs_count: 0,
                rs_next: first,
                discovery_end: u64::MAX,
                last_valid: Lifetime::Until(now),
                deprecate_at: None,
            })
        }
        Ok(Self {
            ail_frames: Default::default(),
            attachment: attachment::Attachment {
                discovering: true,
                ..Default::default()
            },
            retired_ulas: BTreeMap::new(),
            lifecycle: Lifecycle::Running,
            final_ras: [0; 2],
            error_after: None,
            pd_hints: BTreeMap::new(),
            pd: pd::PdClient::default(),
            pd_prefixes: BTreeMap::new(),
            withdrawals: BTreeMap::new(),
            advertised_routes: BTreeMap::new(),
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
            on_link: OnLinkTable::default(),
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
        if matches!(self.lifecycle, Lifecycle::Stopping | Lifecycle::Stopped)
            || !self.links[link.index()].up
        {
            return Ok(vec![]);
        }
        let Ok(e) = envelope(FrameKind::RawIpv6, packet) else {
            return Ok(vec![]);
        };
        if e.source == self.identity.link_local(link) && self.address_ready(link, e.source) {
            return Ok(vec![]);
        }
        if link == Link::Ail
            && e.destination == self.identity.link_local(link)
            && self.address_ready(link, e.destination)
            && transport(&e).is_ok_and(|t| t.protocol == 17)
        {
            let excluded: Vec<_> = self
                .on_link
                .iter()
                .filter(|((l, _), v)| *l == Link::Ail && v.valid.live(now))
                .map(|((_, p), _)| *p)
                .chain([self.identity.prefix(Link::Ail)])
                .collect();
            if let Err(e) = self
                .pd
                .receive_with_policy(&e, &self.identity.duid, now, rng, |p| {
                    let local = Prefix::new(p.address, 64).unwrap();
                    !excluded
                        .iter()
                        .any(|p| p.contains(local.address) || local.contains(p.address))
                })
            {
                self.degrade(now, rng)?;
                return Err(e);
            }
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
        if self.address_ready(link, e.destination) {
            if let Ok(t) = transport(&e) {
                if t.protocol == 58
                    && !t.fragmented
                    && t.bytes.len() >= 8
                    && t.bytes[..2] == [128, 0]
                    && !e.source.is_unspecified()
                    && !e.source.is_multicast()
                    && !e.source.is_loopback()
                    && self.error_after.is_none_or(|t| now >= t)
                    && checksum(e.source, e.destination, 58, t.bytes) == 0
                {
                    self.error_after = Some(now.saturating_add(100));
                    let mut b = t.bytes.to_vec();
                    b[0] = 129;
                    return Ok(vec![Tx {
                        link,
                        packet: icmp_packet(e.destination, e.source, 64, b).unwrap(),
                    }]);
                }
            }
        }
        if !e.destination.is_multicast() && !self.owned.contains_key(&(link, e.destination)) {
            return Ok(vec![]);
        }
        let Ok(nd) = decode_nd(&e) else {
            return Ok(vec![]);
        };
        let prior_exports = self.stub_routes(now);
        let prior_default = self.default_lifetime(now);
        if let Some(out) = self.owned_nd(link, &e, &nd, now, rng)? {
            return Ok(out);
        }
        if nd.kind == 133 {
            if matches!(self.state(link), AilState::Suitable | AilState::Deprecating)
                && !self.confirmed_supplier(link, now)
            {
                self.links[link.index()].state = AilState::BeginAdvertising;
                self.links[link.index()].deprecate_at = None;
                self.links[link.index()].scheduler.changed(now, rng)?;
            }
            self.links[link.index()]
                .scheduler
                .receive_rs(&e, now, rng)?;
        }
        if nd.kind == 134 {
            self.admit_ra(link, &e, &nd, now, rng)?;
            if link == Link::Ail && self.attachment.discovering {
                self.attachment.observe(&e.source.octets())?;
            }
            if u16::from_be_bytes([nd.body[6], nd.body[7]]) > 0 {
                let s = &mut self.links[link.index()];
                s.rs_count = 3;
                if s.discovery_end == u64::MAX {
                    s.discovery_end = now.saturating_add(9000);
                }
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
                        if link == Link::Ail && p.valid > 0 {
                            self.withdrawals.remove(&(Link::Stub, p.prefix));
                        }
                        if link == Link::Stub
                            && !self.on_link.contains_key(&(link, p.prefix))
                            && p.valid > 0
                        {
                            self.links[0].scheduler.changed(now, rng)?;
                        }

                        if p.valid == 0 {
                            self.on_link.remove(&(link, p.prefix));
                        } else {
                            self.on_link.insert(
                                (link, p.prefix),
                                OnLink {
                                    valid: Lifetime::from_secs(now, p.valid),
                                    preferred: Lifetime::from_secs(now, p.preferred),
                                },
                            );
                        }
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
                            self.links[link.index()].deprecate_at = Some(now as i128);
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
                            if self.address_ready(link, self.identity.link_local(link)) {
                                self.links[link.index()].scheduler.enable(now, rng)?;
                            }
                        }
                    } else if p.on_link() {
                        self.suppliers.remove(&(key, p.prefix));
                    }
                }
            }
        }
        if nd.kind == 134 {
            self.sync_pd(now, rng)?;
        }
        let out = self.observe_neighbor(link, &e, &nd, now)?;
        self.reconcile_exports(prior_exports, now, rng)?;
        if prior_default != self.default_lifetime(now) {
            self.links[1].scheduler.changed(now, rng)?;
        }
        self.reap_exports(now);
        Ok(out)
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
                let valid = deprecation_remaining(at, now);
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
        pios.extend(
            self.retired_ulas
                .iter()
                .filter(|((l, _), v)| *l == link && v.remaining(now) >= 206)
                .map(|((_, prefix), v)| Pio {
                    prefix: *prefix,
                    flags: 0xc0,
                    preferred: 0,
                    valid: v.remaining(now),
                }),
        );
        if link == Link::Stub {
            pios.extend(self.delegated_pios(now));
            pios.sort_by_key(|p| p.prefix);
        }
        let mut rios: Vec<Rio> = if link == Link::Ail {
            self.on_link
                .iter()
                .filter(|((l, _), v)| self.links[1].up && *l == Link::Stub && v.valid.live(now))
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
                let p = self.on_link.get(&(Link::Stub, r.prefix)).unwrap();
                (
                    std::cmp::Reverse(p.preferred.live(now)),
                    std::cmp::Reverse(p.valid),
                    r.prefix,
                )
            });
            rios = self.budget_ail(rios, now);
        }
        for r in &mut rios {
            if self.withdrawals.contains_key(&(link, r.prefix)) {
                r.lifetime = 0;
            }
        }
        for ((l, p), valid) in &self.advertised_routes {
            if *l == link && valid.live(now) && !rios.iter().any(|r| r.prefix == *p) {
                rios.push(Rio {
                    prefix: *p,
                    preference: Preference::Low,
                    lifetime: 0,
                });
            }
        }
        if matches!(
            self.lifecycle,
            Lifecycle::Stopping | Lifecycle::Stopped | Lifecycle::Degraded
        ) {
            rios = self
                .advertised_routes
                .iter()
                .filter(|((l, _), v)| *l == link && v.live(now))
                .map(|((_, p), _)| Rio {
                    prefix: *p,
                    preference: Preference::Low,
                    lifetime: 0,
                })
                .collect();
        }
        if matches!(self.lifecycle, Lifecycle::Stopping | Lifecycle::Stopped) {
            for p in &mut pios {
                p.preferred = 0;
                let last = if p.prefix == self.identity.prefix(link) {
                    self.links[link.index()].last_valid
                } else {
                    self.pd_prefixes
                        .get(&p.prefix)
                        .map_or(Lifetime::Until(now), |p| p.last_valid)
                };
                p.valid = p.valid.min(last.remaining(now));
            }
            pios.retain(|p| p.valid > 0);
        }
        Advertisement {
            link,
            source: self.identity.link_local(link),
            destination: "ff02::1".parse().unwrap(),
            mac: if self.links[link.index()].kind == FrameKind::Ethernet {
                Some(
                    self.links[link.index()]
                        .mac
                        .unwrap_or(self.identity.macs[link.index()]),
                )
            } else {
                None
            },
            mtu: self.links[link.index()].mtu,
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
        if self.lifecycle == Lifecycle::Stopped {
            return Ok(vec![]);
        }
        if self.lifecycle == Lifecycle::Stopping {
            return self.stopping_tick(now);
        }

        if self.links[0].up {
            self.finish_attachment(now, rng)?;
            self.retired_ulas.retain(|_, v| v.live(now));
            self.pd.advance(now, rng)?;
        }
        self.reap_exports(now);
        self.pd_hints.retain(|_, l| l.live(now));
        self.sync_pd(now, rng)?;
        let ready =
            [Link::Ail, Link::Stub].map(|l| self.address_ready(l, self.identity.link_local(l)));
        let mut out = self.tick_dad(now);
        for link in [Link::Ail, Link::Stub] {
            if !ready[link.index()]
                && self.address_ready(link, self.identity.link_local(link))
                && self.state(link) != AilState::Unknown
            {
                self.links[link.index()].scheduler.enable(now, rng)?;
            }
        }
        if self.lifecycle == Lifecycle::Starting
            && [Link::Ail, Link::Stub]
                .into_iter()
                .all(|l| self.address_ready(l, self.identity.link_local(l)))
        {
            self.lifecycle = Lifecycle::Running;
        }
        let prior_exports = self.stub_routes(now);
        let prior_default = self.default_lifetime(now);
        out.extend(self.tick_neighbors(now)?);
        self.reconcile_exports(prior_exports, now, rng)?;
        if prior_default != self.default_lifetime(now) {
            self.links[1].scheduler.changed(now, rng)?;
        }
        self.suppliers.retain(|_, s| {
            s.valid.live(now) && s.preferred.live(now) && now < s.pio_at.saturating_add(600000)
        });
        self.on_link.retain(|_, p| p.valid.live(now));
        self.routes.retain(|_, r| r.valid.live(now));
        self.reap_headers(now);
        self.owned.retain(|(link, _), a| {
            a.state == DadState::Failed
                || a.prefix.is_none_or(|p| {
                    self.on_link
                        .get(&(*link, p))
                        .is_some_and(|p| p.valid.live(now))
                })
        });
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
                    s.scheduler.enable(now, rng)?;
                } else if now >= s.rs_next && s.rs_count < 3 {
                    let mut body = vec![133, 0, 0, 0, 0, 0, 0, 0];
                    if s.kind == FrameKind::Ethernet {
                        body.extend([1, 1]);
                        body.extend(s.mac.unwrap_or(self.identity.macs[link.index()]));
                    }
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
                }
            }
            if s.state == AilState::BeginAdvertising {
                if link == Link::Stub
                    && !self
                        .on_link
                        .contains_key(&(link, self.identity.prefix(link)))
                {
                    self.links[0].scheduler.changed(now, rng)?;
                }
                if !self
                    .on_link
                    .contains_key(&(link, self.identity.prefix(link)))
                {
                    self.on_link.insert(
                        (link, self.identity.prefix(link)),
                        OnLink {
                            valid: Lifetime::from_secs(now, 1800),
                            preferred: Lifetime::from_secs(now, 1800),
                        },
                    );
                }
            }
            if self.state(link) != AilState::Unknown && self.links[link.index()].scheduler.due(now)
            {
                let mut snap = self.snapshot(link, now);
                if snap.rios.iter().map(|r| r.encode().len()).sum::<usize>()
                    > Self::route_budget(link)
                {
                    self.degrade(now, rng)?;
                    snap = self.snapshot(link, now);
                }
                if link == Link::Ail {
                    let omitted = self
                        .on_link
                        .iter()
                        .filter(|((l, _), v)| *l == Link::Stub && v.valid.live(now))
                        .count()
                        .saturating_sub(snap.rios.iter().filter(|r| r.lifetime > 0).count());
                    if omitted > 0 {
                        eprintln!(
                            "{now}ms AIL RA omits {omitted} OSNRs (capacity or unavailable egress)"
                        );
                    }
                }
                if link == Link::Stub || !snap.pios.is_empty() || !snap.rios.is_empty() {
                    out.push(Tx {
                        link,
                        packet: match snap.encode() {
                            Ok(p) => p,
                            Err(WireError::Capacity) => {
                                self.degrade(now, rng)?;
                                self.snapshot(link, now)
                                    .encode()
                                    .map_err(|_| io::Error::other("degraded RA capacity"))?
                            }
                            Err(_) => return Err(io::Error::other("invalid RA snapshot")),
                        },
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
        if nd.kind == 133 {
            let s = &mut self.links[tx.link.index()];
            if s.state == AilState::Unknown && s.rs_count < 3 {
                s.rs_count += 1;
                s.rs_next = now.saturating_add(4000);
                s.discovery_end = now.saturating_add((3 - s.rs_count as u64) * 4000 + 1000);
            }
        }
        if nd.kind != 134 {
            return Ok(());
        }
        if self.lifecycle == Lifecycle::Stopping {
            self.final_ras[tx.link.index()] = self.final_ras[tx.link.index()].saturating_sub(1);
            if self.final_ras == [0, 0] {
                self.lifecycle = Lifecycle::Stopped;
            }
        }
        let state = &mut self.links[tx.link.index()];
        state.scheduler.sent(now, rng)?;
        if state.state == AilState::BeginAdvertising {
            state.state = AilState::Advertising;
        }
        if state.state == AilState::Deprecating
            && !nd.options.iter().any(|o| {
                Pio::decode(o.bytes).is_some_and(|p| p.prefix == self.identity.prefix(tx.link))
            })
        {
            state.state = AilState::Suitable;
        }
        for o in &nd.options {
            if let Some(r) = Rio::decode(o.bytes) {
                let key = (tx.link, r.prefix);
                if r.lifetime > 0 {
                    self.advertised_routes
                        .insert(key, Lifetime::from_secs(now, r.lifetime));
                    self.withdrawals.remove(&key);
                } else if self.advertised_routes.contains_key(&key) {
                    let count = self.withdrawals.entry(key).or_insert(3);
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.advertised_routes.remove(&key);
                    }
                }
            }
        }
        self.withdrawals.retain(|_, count| *count > 0);
        for o in nd.options {
            if let Some(p) = Pio::decode(o.bytes) {
                let valid = Lifetime::from_secs(now, p.valid);
                if p.prefix == self.identity.prefix(tx.link) {
                    state.last_valid = valid;
                } else if let Some(owned) = self.pd_prefixes.get_mut(&p.prefix) {
                    owned.last_valid = valid;
                }
                self.on_link.insert(
                    (tx.link, p.prefix),
                    OnLink {
                        valid,
                        preferred: Lifetime::from_secs(now, p.preferred),
                    },
                );
                if !matches!(self.lifecycle, Lifecycle::Stopping | Lifecycle::Stopped)
                    && !self
                        .owned
                        .iter()
                        .any(|((l, _), a)| *l == tx.link && a.prefix == Some(p.prefix))
                {
                    let address = self.identity.address(tx.link, p.prefix);
                    self.owned
                        .entry((tx.link, address))
                        .or_insert(OwnedAddress {
                            prefix: Some(p.prefix),
                            state: DadState::Tentative,
                            deadline: Some(now),
                            attempts: 0,
                        });
                }
            }
        }
        Ok(())
    }
}

fn deprecation_remaining(at: i128, now: Time) -> u32 {
    ((at + 1800000 - now as i128).clamp(0, 1800000) / 1000) as u32
}
