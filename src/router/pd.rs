use super::*;
use crate::wire::dhcpv6::*;
use std::rc::Rc;
#[derive(Clone, Debug)]
pub struct Offer {
    pub server: Vec<u8>,
    pub preference: u8,
    pub delegations: Vec<Delegation>,
}
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
    pub sol_max_rt_seen: Option<Option<u32>>,
    pub reserved_xid: Option<[u8; 3]>,
    pub refresh_after: Time,
    pub fallback_at: Option<Time>,
    pub leases: BTreeMap<LeaseKey, Lease>,
    pub releases: Vec<Release>,
    pub offers: Vec<Offer>,
    pub requested: Vec<Delegation>,
    pub state: PdState,
    pub exchange: Option<Exchange>,
    pub sol_max_rt: u64,
}
impl Default for PdClient {
    fn default() -> Self {
        Self {
            sol_max_rt_seen: None,
            reserved_xid: None,
            refresh_after: 0,
            fallback_at: None,
            leases: BTreeMap::new(),
            releases: vec![],
            offers: vec![],
            requested: vec![],
            state: PdState::Dormant,
            exchange: None,
            sol_max_rt: 3600000,
        }
    }
}
impl PdClient {
    pub fn reserve_xid(&mut self, xid: Option<[u8; 3]>) {
        self.reserved_xid = xid;
    }
    pub fn start(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.offers.clear();
        self.sol_max_rt_seen = None;
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
        self.refresh_after = now.saturating_add(1000);
        let mut xid = [0; 3];
        rng.fill(&mut xid)?;
        if self.reserved_xid == Some(xid) {
            xid[2] ^= 1;
        }
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
        let mut out = self.poll_releases(now, source, duid, rng)?;
        let Some(e) = &mut self.exchange else {
            return Ok(out);
        };
        if now < e.next {
            return Ok(out);
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
        b.extend(option(6, &[0, 23, 0, 24, 0, 82]));
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
        e.interval = retransmission(
            e,
            if e.kind == 1 {
                self.sol_max_rt
            } else if e.kind == 5 || e.kind == 6 {
                600000
            } else {
                30000
            },
            rng,
        )?;
        e.next = now + e.interval;
        e.count = e.count.saturating_add(1);
        if e.kind == 6 && e.count == 1 {
            let t2 = self
                .leases
                .values()
                .map(|l| match l.t2 {
                    Lifetime::Until(t) => t,
                    Lifetime::Infinite => u64::MAX,
                })
                .min()
                .unwrap_or(now);
            self.fallback_at = Some(e.next.max(t2));
        }
        out.push(packet);
        Ok(out)
    }
}

impl PdClient {
    fn choose(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.offers.sort_by_key(|m| {
            (
                std::cmp::Reverse(m.preference),
                std::cmp::Reverse(
                    [false, true]
                        .into_iter()
                        .filter(|ula| {
                            m.delegations.iter().any(|d| {
                                d.prefix.ula() == *ula
                                    && d.prefix.length <= 64
                                    && d.prefix.routable()
                                    && d.preferred >= 1800
                            })
                        })
                        .count(),
                ),
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
        self.receive_with_policy(e, duid, now, rng, |_| true)
    }
    pub(super) fn receive_with_policy(
        &mut self,
        e: &Envelope<'_>,
        duid: &[u8],
        now: Time,
        rng: &mut impl RandomSource,
        allowed: impl Fn(Prefix) -> bool,
    ) -> io::Result<()> {
        let Ok(b) = udp_payload(e) else { return Ok(()) };
        let Ok(mut m) = decode(b) else { return Ok(()) };
        if m.kind == 7 && m.client == duid {
            self.releases
                .retain(|r| r.exchange.xid != m.xid || r.exchange.server != m.server);
        }
        let Some(exchange) = &self.exchange else {
            return Ok(());
        };
        if m.xid != exchange.xid || m.client != duid {
            return Ok(());
        }
        if m.kind == 7
            && matches!(
                self.state,
                PdState::Requesting | PdState::Renewing | PdState::Rebinding
            )
            && (self.state == PdState::Rebinding || m.server == exchange.server)
        {
            return self.install(m, now, rng);
        }
        if self.state == PdState::Soliciting && m.kind == 2 {
            m.delegations.retain(|d| allowed(d.prefix));
            if let Some(max) = m.sol_max_rt {
                self.sol_max_rt_seen = Some(match self.sol_max_rt_seen {
                    None => Some(max),
                    Some(Some(prior)) if prior == max => Some(max),
                    _ => None,
                });
                self.sol_max_rt = self
                    .sol_max_rt_seen
                    .flatten()
                    .map_or(3600000, |n| n as u64 * 1000);
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
            self.offers.push(Offer {
                server: m.server,
                preference: m.preference,
                delegations: m.delegations,
            });
            if immediate {
                self.choose(now, rng)?;
            }
        }
        Ok(())
    }
}

pub type LeaseKey = (u32, Prefix);
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Association {
    pub iaid: u32,
    pub server: Vec<u8>,
    pub t1: Lifetime,
    pub t2: Lifetime,
}
#[derive(Clone, Debug)]
pub struct Lease {
    pub association: Rc<Association>,
    pub preferred: Lifetime,
    pub valid: Lifetime,
    pub used: bool,
}
impl std::ops::Deref for Lease {
    type Target = Association;
    fn deref(&self) -> &Association {
        &self.association
    }
}
#[derive(Clone, Debug)]
pub struct Release {
    pub exchange: Exchange,
    pub prefixes: Vec<Delegation>,
}
#[derive(Clone, Debug)]
pub struct OwnedPrefix {
    pub lease: LeaseKey,
    pub deprecate_at: Option<i128>,
    pub last_valid: Lifetime,
}
impl PdClient {
    pub fn selected(&self, now: Time) -> Vec<LeaseKey> {
        if self.fallback_at.is_some_and(|t| now >= t) {
            return vec![];
        }
        let mut result = vec![];
        for ula in [false, true] {
            if let Some((key, _)) = self
                .leases
                .iter()
                .filter(|((_, p), l)| {
                    p.length <= 64
                        && p.routable()
                        && p.ula() == ula
                        && l.valid.live(now)
                        && l.preferred.live(now)
                })
                .max_by_key(|(key, l)| (l.preferred, std::cmp::Reverse(**key)))
            {
                result.push(*key);
            }
        }
        result
    }
    fn install(&mut self, m: Message, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        if m.status == 3 && matches!(self.state, PdState::Renewing | PdState::Rebinding) {
            self.state = PdState::Requesting;
            return self.begin(3, m.server, now, now, rng);
        }
        if m.status == 6 && self.state == PdState::Requesting {
            return self.start(now, rng);
        }
        if m.status != 0 {
            return Ok(());
        }
        self.leases.retain(|_, l| l.valid.live(now));
        let mut acquired: std::collections::BTreeSet<_> = self.leases.keys().copied().collect();
        for d in &m.delegations {
            if d.valid == 0 {
                acquired.remove(&(d.iaid, d.prefix));
            } else {
                acquired.insert((d.iaid, d.prefix));
            }
        }
        if acquired.len() > 16 {
            // Keep live backing routes. Return newly acquired bindings to the
            // server instead of silently forgetting or advertising them.
            let prefixes = m
                .delegations
                .into_iter()
                .filter(|d| d.valid != 0 && !self.leases.contains_key(&(d.iaid, d.prefix)))
                .collect();
            self.queue_release(m.server, prefixes, now, rng)?;
            self.state = PdState::Bound;
            self.exchange = None;
            return Err(io::Error::other("acquired DHCP prefix capacity"));
        }
        let mut shortest = BTreeMap::new();
        for d in &m.delegations {
            if d.preferred > 0 && d.valid > 0 {
                shortest
                    .entry(d.iaid)
                    .and_modify(|p: &mut u32| *p = (*p).min(d.preferred))
                    .or_insert(d.preferred);
            }
        }
        let mut associations = BTreeMap::new();
        for d in m.delegations {
            let key = (d.iaid, d.prefix);
            if d.valid == 0 {
                self.leases.remove(&key);
                continue;
            }
            let used = self.leases.get(&key).is_some_and(|l| l.used);
            let preferred = shortest.get(&d.iaid).copied().unwrap_or(1);
            let derived = |numerator: u64, denominator: u64| {
                if preferred == u32::MAX {
                    u32::MAX
                } else {
                    ((preferred as u64 * numerator / denominator) as u32).max(1)
                }
            };
            let t1 = if d.t1 == 0 { derived(1, 2) } else { d.t1 };
            let t2 = if d.t2 == 0 {
                derived(4, 5).max(t1)
            } else {
                d.t2
            };
            let association = associations
                .entry(d.iaid)
                .or_insert_with(|| {
                    Rc::new(Association {
                        iaid: d.iaid,
                        server: m.server.clone(),
                        t1: Lifetime::from_secs(now, t1.min(t2)),
                        t2: Lifetime::from_secs(now, t2),
                    })
                })
                .clone();
            self.leases.insert(
                key,
                Lease {
                    association,
                    preferred: Lifetime::from_secs(now, d.preferred),
                    valid: Lifetime::from_secs(now, d.valid),
                    used,
                },
            );
        }
        self.fallback_at = None;
        let selected = self.selected(now);
        for key in &selected {
            self.leases.get_mut(key).unwrap().used = true;
        }
        let unused: Vec<_> = self
            .leases
            .iter()
            .filter(|(_, l)| !l.used)
            .map(|(k, l)| (*k, l.clone()))
            .collect();
        let mut prefixes = vec![];
        for ((iaid, prefix), l) in unused {
            prefixes.push(Delegation {
                iaid,
                prefix,
                t1: 0,
                t2: 0,
                preferred: l.preferred.remaining(now),
                valid: l.valid.remaining(now),
            });
            self.leases.remove(&(iaid, prefix));
        }
        self.queue_release(m.server, prefixes, now, rng)?;
        self.fallback_at = None;
        self.state = PdState::Bound;
        self.exchange = None;
        self.requested.clear();
        Ok(())
    }
    fn queue_release(
        &mut self,
        server: Vec<u8>,
        prefixes: Vec<Delegation>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if prefixes.is_empty() {
            return Ok(());
        }
        if self.releases.len() >= 16 {
            return Err(io::Error::other("DHCP Release exchange capacity"));
        }
        let mut xid = [0; 3];
        rng.fill(&mut xid)?;
        self.releases.push(Release {
            exchange: Exchange {
                kind: 8,
                xid,
                started: now,
                next: now,
                interval: 1000,
                count: 0,
                server,
            },
            prefixes,
        });
        Ok(())
    }
    fn poll_releases(
        &mut self,
        now: Time,
        source: Ipv6Addr,
        duid: &[u8],
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Vec<u8>>> {
        let mut out = vec![];
        for release in &mut self.releases {
            let e = &mut release.exchange;
            if e.count >= 4 || now < e.next {
                continue;
            }
            let mut b = vec![8];
            b.extend(e.xid);
            b.extend(option(1, duid));
            b.extend(option(2, &e.server));
            b.extend(option(
                8,
                &((now.saturating_sub(e.started) / 10).min(65535) as u16).to_be_bytes(),
            ));
            for iaid in [1u32, 2] {
                let mut ia = iaid.to_be_bytes().to_vec();
                ia.extend([0; 8]);
                for d in release.prefixes.iter().filter(|d| d.iaid == iaid) {
                    ia.extend(delegation_option(d));
                }
                if ia.len() > 12 {
                    b.extend(option(25, &ia));
                }
            }
            out.push(
                udp_packet(source, "ff02::1:2".parse().unwrap(), 546, 547, &b)
                    .map_err(|_| io::Error::other("Release encoding"))?,
            );
            e.interval = retransmission(e, 0, rng)?;
            e.count += 1;
            e.next = now.saturating_add(e.interval);
        }
        self.releases
            .retain(|r| r.exchange.count < 4 || now < r.exchange.next);
        Ok(out)
    }
}
impl Router {
    pub(super) fn pd_conflicts(&self, prefix: Prefix, now: Time) -> bool {
        let local = Prefix::new(prefix.address, 64).unwrap();
        local == self.identity.prefix(Link::Ail)
            || self.on_link.iter().any(|((l, p), v)| {
                *l == Link::Ail
                    && v.valid.live(now)
                    && (p.contains(local.address) || local.contains(p.address))
            })
    }
    pub(super) fn sync_pd(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        // Recheck on every synchronization: an AIL PIO can arrive after the offer.
        let conflicts: Vec<_> = self
            .pd
            .leases
            .iter()
            .filter(|((_, p), _)| self.pd_conflicts(*p, now))
            .map(|(k, l)| (*k, l.clone()))
            .collect();
        for ((iaid, prefix), l) in conflicts {
            self.pd.queue_release(
                l.server.clone(),
                vec![Delegation {
                    iaid,
                    prefix,
                    t1: 0,
                    t2: 0,
                    preferred: l.preferred.remaining(now),
                    valid: l.valid.remaining(now),
                }],
                now,
                rng,
            )?;
            self.pd.leases.remove(&(iaid, prefix));
        }
        for offer in &mut self.pd.offers {
            let own = self.identity.prefix(Link::Ail);
            offer.delegations.retain(|d| {
                let local = Prefix::new(d.prefix.address, 64).unwrap();
                local != own
                    && !self.on_link.iter().any(|((l, p), v)| {
                        *l == Link::Ail
                            && v.valid.live(now)
                            && (p.contains(local.address) || local.contains(p.address))
                    })
            });
        }
        self.pd.offers.retain(|o| !o.delegations.is_empty());
        let had_pd = !self.pd_prefixes.is_empty();
        let mut selected = self.pd.selected(now);
        selected.retain(|key| {
            let local = Prefix::new(key.1.address, 64).unwrap();
            !self.suppliers.iter().any(|((router, p), s)| {
                router.link == Link::Stub
                    && p.ula() == local.ula()
                    && *p < local
                    && s.valid.live(now)
                    && s.preferred.live(now)
                    && now < s.pio_at.saturating_add(600000)
                    && self
                        .neighbors
                        .get(router)
                        .is_none_or(|n| n.state != NeighborState::Failed)
            })
        });
        let mut changed = false;
        for key in &selected {
            let prefix = Prefix::new(key.1.address, 64).unwrap();
            let lease = &self.pd.leases[key];
            if self
                .pd_prefixes
                .get(&prefix)
                .is_none_or(|p| p.lease != *key || p.deprecate_at.is_some())
            {
                changed = true;
            }
            let owned = self.pd_prefixes.entry(prefix).or_insert(OwnedPrefix {
                lease: *key,
                deprecate_at: None,
                last_valid: Lifetime::Until(now),
            });
            owned.lease = *key;
            owned.deprecate_at = None;
            if self.links[1].up {
                self.withdrawals.remove(&(Link::Ail, prefix));
            }
            self.on_link.insert(
                (Link::Stub, prefix),
                OnLink {
                    valid: lease.valid,
                    preferred: lease.preferred,
                },
            );
        }
        for p in self.pd_prefixes.values_mut() {
            if !selected.contains(&p.lease) && p.deprecate_at.is_none() {
                p.deprecate_at = Some(now as i128);
                changed = true;
            }
        }
        let invalid: Vec<_> = self
            .pd_prefixes
            .iter()
            .filter(|(_, p)| {
                !self
                    .pd
                    .leases
                    .get(&p.lease)
                    .is_some_and(|l| l.valid.live(now))
            })
            .map(|(p, _)| *p)
            .collect();
        for p in invalid {
            self.pd_prefixes.remove(&p);
            self.on_link.remove(&(Link::Stub, p));
            self.withdrawals.insert((Link::Ail, p), 3);
            changed = true;
        }
        if selected.is_empty()
            && had_pd
            && !self.suppliers.iter().any(|((k, _), s)| {
                k.link == Link::Stub
                    && s.valid.live(now)
                    && s.preferred.live(now)
                    && now < s.pio_at.saturating_add(600000)
                    && self
                        .neighbors
                        .get(k)
                        .is_none_or(|n| n.state != NeighborState::Failed)
            })
            && !matches!(
                self.state(Link::Stub),
                AilState::Advertising | AilState::BeginAdvertising
            )
        {
            self.links[1].state = AilState::BeginAdvertising;
            self.links[1].deprecate_at = None;
            changed = true;
        }
        if !selected.is_empty()
            && matches!(
                self.state(Link::Stub),
                AilState::Advertising | AilState::BeginAdvertising
            )
        {
            self.links[1].state = AilState::Deprecating;
            self.links[1].deprecate_at = Some(now as i128);
            changed = true;
        }
        if changed {
            self.links[0].scheduler.changed(now, rng)?;
            self.links[1].scheduler.changed(now, rng)?;
        }
        Ok(())
    }
    pub(super) fn delegated_pios(&self, now: Time) -> Vec<Pio> {
        self.pd_prefixes
            .iter()
            .filter_map(|(prefix, p)| {
                let l = self.pd.leases.get(&p.lease)?;
                let mut valid = l.valid.remaining(now).min(1800);
                let preferred = if let Some(at) = p.deprecate_at {
                    valid = valid.min(deprecation_remaining(at, now));
                    0
                } else {
                    l.preferred.remaining(now).min(valid)
                };
                if valid == 0 || (p.deprecate_at.is_some() && valid < 206) {
                    None
                } else {
                    Some(Pio {
                        prefix: *prefix,
                        flags: 0xc0,
                        preferred,
                        valid,
                    })
                }
            })
            .collect()
    }
}

impl PdClient {
    pub fn advance(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.leases.retain(|_, l| l.valid.live(now));
        if self.leases.is_empty()
            && matches!(
                self.state,
                PdState::Bound | PdState::Renewing | PdState::Rebinding
            )
        {
            self.start(now, rng)?;
        }
        if matches!(self.state, PdState::Bound | PdState::Renewing)
            && self.leases.values().any(|l| !l.t2.live(now))
        {
            self.refresh(6, now, rng)?;
        } else if self.state == PdState::Bound && self.leases.values().any(|l| !l.t1.live(now)) {
            self.refresh(5, now, rng)?;
        }
        Ok(())
    }
    pub fn refresh(&mut self, kind: u8, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        if self.leases.is_empty() || now < self.refresh_after {
            return Ok(());
        }
        let server = if kind == 5 {
            self.leases
                .values()
                .min_by_key(|l| l.t1)
                .unwrap()
                .server
                .clone()
        } else {
            vec![]
        };
        self.requested = self
            .leases
            .iter()
            .filter(|(_, l)| kind == 6 || l.server == server)
            .map(|((iaid, prefix), l)| Delegation {
                iaid: *iaid,
                prefix: *prefix,
                t1: 0,
                t2: 0,
                preferred: l.preferred.remaining(now),
                valid: l.valid.remaining(now),
            })
            .collect();
        self.state = if kind == 5 {
            PdState::Renewing
        } else {
            PdState::Rebinding
        };
        self.begin(kind, server, now, now, rng)
    }
}

// RFC 9915 section 15: jitter is relative to RTprev, not 2*RTprev.
fn retransmission(e: &Exchange, mrt: u64, rng: &mut impl RandomSource) -> io::Result<u64> {
    if e.count == 0 && e.kind == 1 {
        return Ok(1001 + rng.sample(99)?);
    }
    let previous = if e.count == 0 {
        if e.kind == 5 || e.kind == 6 {
            10000
        } else {
            1000
        }
    } else {
        e.interval
    };
    let rand = rng.sample(2000)? as i128 - 1000;
    let base = previous as i128 * if e.count == 0 { 1 } else { 2 };
    let rt = (base * 10000 + previous as i128 * rand) / 10000;
    let rt = if mrt != 0 && rt > mrt as i128 {
        (mrt as i128 * (10000 + rand)) / 10000
    } else {
        rt
    };
    Ok(rt.clamp(1, u64::MAX as i128) as u64)
}
