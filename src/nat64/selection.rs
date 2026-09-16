use super::*;
use crate::wire::{Preference, Rio};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    pub enabled: bool,
    pub infrastructure: Option<Prefix>,
    pub allow_without_pd: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: true,
            infrastructure: None,
            allow_without_pd: false,
        }
    }
}
impl Policy {
    pub fn validate(&self) -> io::Result<()> {
        if self.infrastructure.is_some_and(|p| !usable(p)) {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Readiness {
    pub pd: Option<u64>,
    pub ipv4: Option<u64>,
    pub stub: Option<u64>,
    pub translator: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Disabled,
    None,
    Local,
    Infrastructure,
    Peer,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    Local,
    Infrastructure,
    Configured,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Announcement {
    pub pref64: Pref64,
    pub source: Source,
}
#[derive(Debug)]
pub struct Decision {
    pub mode: Mode,
    pub announcements: Vec<Announcement>,
    pub routes: Vec<Rio>,
    pub reason: &'static str,
}
pub struct Selector {
    policy: Policy,
    observations: Observations,
    local: Prefix,
    promised: BTreeMap<Prefix, (Source, u64, bool)>,
    suppressed: bool,
}
impl Selector {
    pub fn new(site: Prefix) -> io::Result<Self> {
        if site.length != 48 || !site.ula() || Prefix::new(site.address, 48) != Some(site) {
            return Err(invalid());
        }
        let local =
            Prefix::new((u128::from(site.address) | (0xffffu128 << 64)).into(), 96).unwrap();
        Ok(Self {
            policy: Policy::default(),
            observations: Observations::default(),
            local,
            promised: BTreeMap::new(),
            suppressed: false,
        })
    }
    pub fn local_prefix(&self) -> Prefix {
        self.local
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn configure(&mut self, policy: Policy, _now: u64) -> io::Result<()> {
        policy.validate()?;
        if self.policy != policy {
            self.observations = Observations::default();
            self.suppressed = false;
        }
        self.policy = policy;
        Ok(())
    }
    pub fn receive(&mut self, link: Link, packet: &[u8], now: u64) -> io::Result<()> {
        if !self.policy.enabled {
            return Ok(());
        }
        self.observations.receive(link, packet, now)
    }
    pub fn link_lost(&mut self, link: Link) {
        self.observations.link_lost(link);
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.observations
            .next_deadline()
            .into_iter()
            .chain(self.promised.values().map(|(_, t, _)| *t))
            .min()
    }
    pub fn advertised(&mut self, announcements: &[Announcement], now: u64) -> io::Result<()> {
        if announcements.len() > 8 {
            return Err(invalid());
        }
        let mut next = self.promised.clone();
        next.retain(|_, (_, t, _)| *t > now);
        for a in announcements {
            if !usable(a.pref64.prefix) {
                return Err(invalid());
            }
            if a.pref64.lifetime == 0 {
                if let Some((_, _, withdrawn)) = next.get_mut(&a.pref64.prefix) {
                    *withdrawn = true;
                }
            } else {
                next.insert(
                    a.pref64.prefix,
                    (
                        a.source,
                        now.saturating_add(u64::from(a.pref64.lifetime.min(65528) & !7) * 1000),
                        false,
                    ),
                );
            }
        }
        if next.len() > 8 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "NAT64 advertisement history capacity",
            ));
        }
        self.promised = next;
        Ok(())
    }
    pub fn announcement_failed(&mut self, mode: Mode, now: u64) {
        if mode == Mode::Infrastructure
            && !self.observations.live(Link::Stub, now, |_| true).is_empty()
        {
            self.suppressed = true;
        }
    }
    pub fn select(
        &mut self,
        now: u64,
        ready: Readiness,
        reachable: impl Fn(Link, Ipv6Addr) -> bool,
        route: impl Fn(Prefix) -> Option<u64>,
    ) -> Decision {
        let mut decision = self.select_active(now, ready, reachable, route);
        for (prefix, (source, until, withdrawn)) in &self.promised {
            if decision
                .announcements
                .iter()
                .any(|a| a.pref64.prefix == *prefix)
            {
                continue;
            }
            if !withdrawn {
                decision.announcements.push(Announcement {
                    pref64: Pref64 {
                        prefix: *prefix,
                        lifetime: 0,
                    },
                    source: *source,
                });
            }
            let life = if self.policy.enabled && *source == Source::Local && ready.translator {
                until
                    .min(&ready.ipv4.unwrap_or(now))
                    .min(&ready.stub.unwrap_or(now))
                    .saturating_sub(now)
                    / 1000
            } else {
                0
            };
            decision.routes.push(Rio {
                prefix: *prefix,
                preference: Preference::Medium,
                lifetime: life.min(u64::from(u32::MAX)) as u32,
            });
        }
        decision
    }
    fn select_active(
        &mut self,
        now: u64,
        ready: Readiness,
        reachable: impl Fn(Link, Ipv6Addr) -> bool,
        route: impl Fn(Prefix) -> Option<u64>,
    ) -> Decision {
        self.observations.expire(now);
        self.promised.retain(|_, (_, t, _)| *t > now);
        if self.observations.live(Link::Stub, now, |_| true).is_empty() {
            self.suppressed = false;
        }
        let empty = |mode, reason| Decision {
            mode,
            reason,
            announcements: vec![],
            routes: vec![],
        };
        if !self.policy.enabled {
            return empty(Mode::Disabled, "administratively disabled");
        }
        let Some(stub) = ready.stub.filter(|t| *t > now) else {
            return empty(Mode::None, "stub address or return path is not ready");
        };
        if self.suppressed {
            return empty(
                Mode::Peer,
                "announcement admission failed; waiting for all peer advertisements to disappear",
            );
        }
        let peer = !self
            .observations
            .live(Link::Stub, now, |a| reachable(Link::Stub, a))
            .is_empty();
        let pd = ready.pd.filter(|t| *t > now);
        if pd.is_some() || self.policy.allow_without_pd {
            let candidates = if let Some(p) = self.policy.infrastructure {
                vec![(p, u64::MAX, Source::Configured)]
            } else {
                self.observations
                    .live(Link::Ail, now, |a| reachable(Link::Ail, a))
                    .into_iter()
                    .map(|(p, t)| (p, t, Source::Infrastructure))
                    .collect()
            };
            let mut slots = 8 - self.promised.len();
            let announcements: Vec<_> =
                candidates
                    .into_iter()
                    .filter_map(|(prefix, until, source)| {
                        let until = until.min(route(prefix)?).min(stub).min(
                            if self.policy.allow_without_pd {
                                u64::MAX
                            } else {
                                pd?
                            },
                        );
                        let lifetime = remaining(until, now);
                        if lifetime == 0 {
                            return None;
                        }
                        if !self.promised.contains_key(&prefix) {
                            if slots == 0 {
                                return None;
                            }
                            slots -= 1;
                        }
                        Some(Announcement {
                            pref64: Pref64 { prefix, lifetime },
                            source,
                        })
                    })
                    .take(8)
                    .collect();
            if !announcements.is_empty() {
                let routes = announcements
                    .iter()
                    .map(|a| Rio {
                        prefix: a.pref64.prefix,
                        preference: Preference::Medium,
                        lifetime: a.pref64.lifetime,
                    })
                    .collect();
                return Decision {
                    mode: Mode::Infrastructure,
                    reason: "usable infrastructure translation with a return route",
                    announcements,
                    routes,
                };
            }
        }
        let active = self
            .promised
            .get(&self.local)
            .is_some_and(|(source, t, withdrawn)| {
                *source == Source::Local && *t > now && !withdrawn
            });
        if peer && !active {
            return empty(Mode::Peer, "a reachable stub peer already provides NAT64");
        }
        if ready.translator {
            if let Some(ipv4) = ready.ipv4.filter(|t| *t > now) {
                let lifetime = remaining(ipv4.min(stub).min(now.saturating_add(1800000)), now);
                if lifetime > 0
                    && (self.promised.contains_key(&self.local) || self.promised.len() < 8)
                {
                    return Decision {
                        mode: Mode::Local,
                        reason: "local translator and IPv4 path are ready",
                        announcements: vec![Announcement {
                            pref64: Pref64 {
                                prefix: self.local,
                                lifetime,
                            },
                            source: Source::Local,
                        }],
                        routes: vec![Rio {
                            prefix: self.local,
                            preference: Preference::Medium,
                            lifetime,
                        }],
                    };
                }
            }
        }
        empty(
            Mode::None,
            "no usable translation path or advertisement capacity",
        )
    }
}
fn remaining(until: u64, now: u64) -> u32 {
    ((until.saturating_sub(now) / 1000).min(65528) as u32) & !7
}
