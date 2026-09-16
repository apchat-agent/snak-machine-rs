use super::*;
use crate::nat64::{Announcement, Readiness, Source};

#[derive(Default)]
pub(super) struct Services {
    // At most two installed resolver endpoints, and two outstanding promises.
    pub(super) resolvers: Vec<Ipv6Addr>,
    dns_history: BTreeMap<Ipv6Addr, (Lifetime, u8)>,
    ipv4: Option<Time>,
    translator: bool,
}
impl Router {
    pub(crate) fn service_inventory(
        &mut self,
        resolvers: &[Ipv6Addr],
        ipv4: Option<Time>,
        translator: bool,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let mut addresses: Vec<_> = resolvers
            .iter()
            .copied()
            .filter(|a| {
                self.address_ready(Link::Stub, *a)
                    && !a.is_unspecified()
                    && !a.is_multicast()
                    && !a.is_loopback()
            })
            .collect();
        addresses.sort_by_key(|a| (link_local(*a), *a));
        addresses.dedup();
        addresses.truncate(2);
        let changed = self.services.resolvers != addresses
            || self.services.ipv4 != ipv4
            || self.services.translator != translator;
        self.services.resolvers = addresses;
        self.services.ipv4 = ipv4;
        self.services.translator = translator;
        if changed {
            self.links[1].scheduler.changed(now, rng)?;
        }
        Ok(())
    }
    fn service_until(&self, address: Ipv6Addr, now: Time) -> Option<Time> {
        if !self.links[1].up
            || !self.address_ready(Link::Stub, address)
            || matches!(
                self.lifecycle,
                Lifecycle::Stopping | Lifecycle::Stopped | Lifecycle::Degraded
            )
        {
            return None;
        }
        let cap = now.saturating_add(1800000);
        if link_local(address) {
            return Some(cap);
        }
        self.on_link
            .iter()
            .filter(|((l, p), v)| *l == Link::Stub && p.contains(address) && v.valid.live(now))
            .map(|(_, v)| deadline(v.valid).min(cap))
            .max()
    }
    pub(super) fn encode_services(
        &mut self,
        mut ad: Advertisement,
        now: Time,
    ) -> Result<Vec<u8>, WireError> {
        if ad.link == Link::Ail {
            return ad.encode();
        }
        self.services.dns_history.retain(|_, (v, _)| v.live(now));
        let mut dns = BTreeMap::new();
        for address in self.services.dns_history.keys() {
            let life = if self.services.resolvers.contains(address) {
                self.service_until(*address, now)
                    .unwrap_or(now)
                    .saturating_sub(now)
                    / 1000
            } else {
                0
            };
            dns.insert(*address, life as u32);
        }
        for address in &self.services.resolvers {
            if dns.len() == 2 {
                break;
            }
            if let Some(until) = self.service_until(*address, now) {
                dns.insert(*address, (until.saturating_sub(now) / 1000) as u32);
            }
        }
        let stub = self
            .services
            .resolvers
            .iter()
            .filter(|a| !link_local(**a))
            .filter_map(|a| self.service_until(*a, now))
            .max();
        let pd = self
            .pd_prefixes
            .iter()
            .filter(|(p, _)| {
                self.owned.iter().any(|((l, a), own)| {
                    *l == Link::Stub
                        && own.prefix == Some(**p)
                        && self.service_until(*a, now).is_some()
                })
            })
            .map(|(_, p)| deadline(p.last_valid))
            .filter(|t| *t > now)
            .max();
        let ready = Readiness {
            stub,
            pd,
            ipv4: self.services.ipv4,
            translator: self.services.translator
                && self.links[0].up
                && self.lifecycle == Lifecycle::Running,
        };
        let neighbors = &self.neighbors;
        let routes = &self.routes;
        let ail_up = self.links[0].up;
        let reachable = |link, address| {
            neighbors
                .get(&RouterKey { link, address })
                .is_some_and(|n| {
                    n.state == NeighborState::Reachable && n.deadline.is_some_and(|t| t > now)
                })
        };
        let decision = self.nat64.select(now, ready, reachable, |prefix| {
            routes
                .iter()
                .filter(|((address, p), r)| {
                    ail_up
                        && p.length <= prefix.length
                        && p.contains(prefix.address)
                        && r.valid.live(now)
                        && neighbors
                            .get(&RouterKey {
                                link: Link::Ail,
                                address: *address,
                            })
                            .is_some_and(|n| n.is_router && n.state != NeighborState::Failed)
                })
                .map(|(_, r)| deadline(r.valid))
                .max()
        });
        // Reserve future service withdrawals and the owned PIO envelope before
        // admitting new learned routes. Existing successful promises always win.
        let nat_prefixes: std::collections::BTreeSet<_> =
            decision.routes.iter().map(|r| r.prefix).collect();
        if !self.services.resolvers.is_empty() || !self.services.dns_history.is_empty() {
            let reserved = 40
                + 16
                + usize::from(ad.mac.is_some()) * 8
                + 8
                + ad.pios.len().max(17) * 32
                + 2 * 24
                + 8 * (16 + 24);
            let mut available = 1280usize.saturating_sub(reserved);
            let mut admitted = vec![];
            let mut candidates = vec![];
            for r in ad
                .rios
                .drain(..)
                .filter(|r| !nat_prefixes.contains(&r.prefix))
            {
                if self.advertised_routes.contains_key(&(Link::Stub, r.prefix)) {
                    available = available
                        .checked_sub(r.encode().len())
                        .ok_or(WireError::Capacity)?;
                    admitted.push(r);
                } else {
                    candidates.push(r);
                }
            }
            let mut omitted = 0;
            for r in candidates {
                let size = r.encode().len();
                if size <= available {
                    available -= size;
                    admitted.push(r);
                } else {
                    omitted += 1;
                }
            }
            if omitted > 0 {
                eprintln!(
                    "{now}ms stub RA omits {omitted} new learned routes (service reservation)"
                );
            }
            ad.rios = admitted;
        }
        for route in decision.routes {
            ad.rios.retain(|r| r.prefix != route.prefix);
            ad.rios.push(route);
        }
        let dns: Vec<_> = dns.into_iter().collect();
        let pref64: Vec<_> = decision.announcements.iter().map(|a| a.pref64).collect();
        let encoded = ad.encode_services(&dns, &pref64);
        if encoded == Err(WireError::Capacity) {
            self.nat64.announcement_failed(decision.mode, now);
        }
        encoded
    }
    pub(super) fn services_transmitted(
        &mut self,
        link: Link,
        nd: &Nd<'_>,
        now: Time,
    ) -> io::Result<()> {
        if link != Link::Stub {
            return Ok(());
        }
        let announcements: Vec<_> = nd
            .options
            .iter()
            .filter_map(|o| Pref64::decode(o.bytes))
            .map(|pref64| Announcement {
                source: if pref64.prefix == self.nat64.local_prefix() {
                    Source::Local
                } else if Some(pref64.prefix) == self.nat64.policy().infrastructure {
                    Source::Configured
                } else {
                    Source::Infrastructure
                },
                pref64,
            })
            .collect();
        self.nat64.advertised(&announcements, now)?;
        self.services.dns_history.retain(|_, (v, _)| v.live(now));
        for o in &nd.options {
            if o.kind != 25 || o.bytes.len() < 24 || o.bytes.len() % 16 != 8 {
                continue;
            }
            let lifetime = u32_at(o.bytes, 4);
            for bytes in o.bytes[8..].chunks_exact(16) {
                let a = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap());
                if lifetime > 0
                    && (self.services.dns_history.contains_key(&a)
                        || self.services.dns_history.len() < 2)
                {
                    self.services
                        .dns_history
                        .insert(a, (Lifetime::from_secs(now, lifetime), 3));
                } else if let Some((_, count)) = self.services.dns_history.get_mut(&a) {
                    *count = count.saturating_sub(1);
                }
            }
        }
        self.services.dns_history.retain(|_, (_, count)| *count > 0);
        Ok(())
    }
}
fn deadline(lifetime: Lifetime) -> Time {
    match lifetime {
        Lifetime::Until(t) => t,
        Lifetime::Infinite => u64::MAX,
    }
}
