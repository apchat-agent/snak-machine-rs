use super::*;
#[derive(Clone, Debug)]
pub struct Route {
    pub valid: Lifetime,
    pub preference: Preference,
}
impl Router {
    pub(super) fn observe_routes(
        &mut self,
        key: RouterKey,
        nd: &Nd<'_>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if key.link != Link::Ail {
            return Ok(());
        }
        let prefix = Prefix::new(Ipv6Addr::UNSPECIFIED, 0).unwrap();
        let lifetime = u16::from_be_bytes([nd.body[6], nd.body[7]]) as u32;
        self.routes.remove(&(key.address, prefix));
        if lifetime > 0 {
            self.routes.insert(
                (key.address, prefix),
                Route {
                    valid: Lifetime::from_secs(now, lifetime),
                    preference: Preference::decode(nd.body[5]).unwrap_or(Preference::Medium),
                },
            );
        }
        for o in &nd.options {
            if let Some(r) = Rio::decode(o.bytes) {
                if r.prefix.length == 0
                    || (r.prefix.routable() && !self.on_link.contains_key(&(Link::Stub, r.prefix)))
                {
                    self.routes.remove(&(key.address, r.prefix));
                    if r.prefix.length > 0
                        && r.lifetime == 0
                        && !self
                            .routes
                            .iter()
                            .any(|((a, p), v)| *p == r.prefix && self.usable_route(*a, v, now))
                    {
                        self.withdrawals.insert((Link::Stub, r.prefix), 3);
                    }
                    if r.lifetime > 0 {
                        self.withdrawals.remove(&(Link::Stub, r.prefix));
                    }
                    if r.lifetime > 0 {
                        self.routes.insert(
                            (key.address, r.prefix),
                            Route {
                                valid: Lifetime::from_secs(now, r.lifetime),
                                preference: r.preference,
                            },
                        );
                    }
                }
            }
        }
        self.links[1].scheduler.changed(now, rng)?;
        Ok(())
    }
    pub fn usable_route(&self, router: Ipv6Addr, route: &Route, now: Time) -> bool {
        route.valid.live(now)
            && self
                .neighbors
                .get(&RouterKey {
                    link: Link::Ail,
                    address: router,
                })
                .is_some_and(|n| n.is_router && n.state != NeighborState::Failed)
    }
    pub fn default_lifetime(&self, now: Time) -> u16 {
        if matches!(
            self.lifecycle,
            Lifecycle::Stopping | Lifecycle::Stopped | Lifecycle::Degraded
        ) || !self.links[0].up
            || self.no_stub_default
        {
            return 0;
        }
        self.routes
            .iter()
            .filter(|((a, p), r)| p.length == 0 && self.usable_route(*a, r, now))
            .map(|(_, r)| r.valid.remaining(now).min(1800) as u16)
            .max()
            .unwrap_or(0)
    }
    pub(super) fn stub_routes(&self, now: Time) -> Vec<Rio> {
        let mut routes: BTreeMap<Prefix, u32> = BTreeMap::new();
        if !self.links[0].up {
            return self
                .withdrawals
                .keys()
                .filter(|(l, _)| *l == Link::Stub)
                .map(|(_, p)| Rio {
                    prefix: *p,
                    preference: Preference::Low,
                    lifetime: 0,
                })
                .collect();
        }
        if self.default_lifetime(now) == 0 || self.always_advertise_ail_routes {
            for ((l, p), v) in &self.on_link {
                if *l == Link::Ail && v.valid.live(now) {
                    routes.insert(*p, v.valid.remaining(now).min(1800));
                }
            }
        }
        for ((a, p), r) in &self.routes {
            if p.length > 0
                && self.usable_route(*a, r, now)
                && !self.on_link.contains_key(&(Link::Stub, *p))
            {
                let lifetime = r.valid.remaining(now).min(1800);
                routes
                    .entry(*p)
                    .and_modify(|l| *l = (*l).max(lifetime))
                    .or_insert(lifetime);
            }
        }
        for ((l, p), _) in &self.withdrawals {
            if *l == Link::Stub {
                routes.entry(*p).or_insert(0);
            }
        }
        routes
            .into_iter()
            .map(|(prefix, lifetime)| Rio {
                prefix,
                preference: Preference::Low,
                lifetime,
            })
            .collect()
    }
}

impl Router {
    pub(super) fn reconcile_exports(
        &mut self,
        prior: Vec<Rio>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let current = self.stub_routes(now);
        let mut changed = false;
        for r in prior {
            if r.lifetime > 0
                && !current
                    .iter()
                    .any(|c| c.prefix == r.prefix && c.lifetime > 0)
            {
                self.withdrawals.insert((Link::Stub, r.prefix), 3);
                changed = true;
            }
        }
        if changed {
            self.links[1].scheduler.changed(now, rng)?;
        }
        Ok(())
    }
}
