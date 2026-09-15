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
                if r.prefix.length == 0 {
                    self.routes.remove(&(key.address, r.prefix));
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
        if self.no_stub_default {
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
        if self.default_lifetime(now) > 0 && !self.always_advertise_ail_routes {
            return vec![];
        }
        self.on_link
            .iter()
            .filter(|((l, _), p)| *l == Link::Ail && p.valid.live(now))
            .map(|((_, prefix), p)| Rio {
                prefix: *prefix,
                preference: Preference::Low,
                lifetime: p.valid.remaining(now).min(1800),
            })
            .collect()
    }
}
