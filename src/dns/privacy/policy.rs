use super::{ddr_candidates, invalid, Designation};
use crate::{
    dns::wire::{Message, Name},
    time::RandomSource,
};
use std::{collections::BTreeMap, io, net::SocketAddr};
#[derive(Clone, Debug)]
pub struct TlsProbe {
    pub id: u64,
    pub origin: SocketAddr,
    pub endpoint: SocketAddr,
    pub server_name: String,
    pub expires: u64,
}
#[derive(Clone, Debug)]
pub struct DdrProbe {
    pub id: u64,
    pub origin: SocketAddr,
    pub name: Name,
}
#[derive(Clone, Debug)]
pub enum Probe {
    Tls(TlsProbe),
    Ddr(DdrProbe),
}
#[derive(Clone, Debug)]
pub enum Route {
    Plain { reason: &'static str },
    Tls(Designation),
}
enum TlsState {
    Due(u64),
    Waiting { probe: TlsProbe, until: u64 },
    Idle(u64),
}
enum DdrState {
    Due(u64),
    Waiting { id: u64, until: u64 },
    Idle(u64),
}
struct Endpoint {
    desired: Option<Designation>,
    working: Option<Designation>,
    tls: TlsState,
    ddr: DdrState,
    path: Vec<Name>,
    alias_expires: u64,
    reason: &'static str,
}
impl Endpoint {
    fn new(now: u64) -> Self {
        Self {
            desired: None,
            working: None,
            tls: TlsState::Due(now),
            ddr: DdrState::Due(now),
            path: vec!["_dns.resolver.arpa.".parse().unwrap()],
            alias_expires: u64::MAX,
            reason: "probing encrypted DNS",
        }
    }
    fn reset_ddr(&mut self) {
        self.path = vec!["_dns.resolver.arpa.".parse().unwrap()];
        self.alias_expires = u64::MAX;
    }
}
#[derive(Default)]
pub struct Policy {
    endpoints: BTreeMap<SocketAddr, Endpoint>,
    sequence: u64,
    explicit: bool,
}
impl Policy {
    pub fn count(&self) -> usize {
        self.endpoints.len()
    }
    pub fn sync(&mut self, origins: &[SocketAddr], explicit: bool, now: u64) -> io::Result<()> {
        if origins.len() > 8
            || origins
                .iter()
                .any(|a| a.port() == 0 || a.ip().is_unspecified() || a.ip().is_multicast())
        {
            return Err(invalid());
        }
        if self.explicit != explicit {
            self.endpoints.clear();
        }
        self.explicit = explicit;
        self.endpoints.retain(|o, _| origins.contains(o));
        for origin in origins {
            self.endpoints
                .entry(*origin)
                .or_insert_with(|| Endpoint::new(now));
        }
        Ok(())
    }
    pub fn route(&self, origin: SocketAddr, now: u64) -> Route {
        if self.explicit {
            return Route::Plain {
                reason: "explicitly configured DNS service",
            };
        }
        let Some(e) = self.endpoints.get(&origin) else {
            return Route::Plain {
                reason: "no encrypted resolver evidence",
            };
        };
        if let Some(t) = e.working.as_ref().filter(|t| t.expires > now) {
            return Route::Tls(t.clone());
        }
        Route::Plain {
            reason: if e.working.is_some() {
                "encrypted designation expired"
            } else {
                e.reason
            },
        }
    }
    pub fn next_deadline(&self) -> Option<u64> {
        if self.explicit {
            return None;
        }
        self.endpoints
            .values()
            .flat_map(|e| {
                let tls = match &e.tls {
                    TlsState::Due(t) | TlsState::Idle(t) => *t,
                    TlsState::Waiting { until, .. } => *until,
                };
                let ddr = match e.ddr {
                    DdrState::Due(t) | DdrState::Idle(t) => t,
                    DdrState::Waiting { until, .. } => until,
                };
                [tls, ddr, e.working.as_ref().map_or(u64::MAX, |t| t.expires)]
            })
            .min()
    }
    pub fn poll(&mut self, now: u64) -> io::Result<Vec<Probe>> {
        if self.explicit {
            return Ok(vec![]);
        }
        let mut out = vec![];
        for (origin, e) in &mut self.endpoints {
            if e.desired.as_ref().is_some_and(|t| t.expires <= now) {
                e.desired = None;
            }
            if e.working.as_ref().is_some_and(|t| t.expires <= now) {
                e.working = None;
                e.reason = "encrypted designation expired";
            }
            match &e.tls {
                TlsState::Waiting { until, .. } if *until <= now => {
                    e.tls = TlsState::Due(now.saturating_add(30000));
                    e.reason = "TLS handshake timeout";
                }
                TlsState::Idle(until) if *until <= now => e.tls = TlsState::Due(now),
                _ => {}
            }
            match e.ddr {
                DdrState::Waiting { until, .. } if until <= now => {
                    e.ddr = DdrState::Idle(now.saturating_add(30000));
                    e.reset_ddr();
                }
                DdrState::Idle(until) if until <= now => {
                    e.ddr = DdrState::Due(now);
                    e.reset_ddr();
                }
                _ => {}
            }
            if matches!(e.tls,TlsState::Due(at) if at<=now) {
                let target = e.desired.clone().unwrap_or_else(|| {
                    let mut endpoint = *origin;
                    endpoint.set_port(853);
                    Designation {
                        endpoint,
                        server_name: origin.ip().to_string(),
                        priority: u16::MAX,
                        expires: now.saturating_add(300000),
                    }
                });
                self.sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
                let probe = TlsProbe {
                    id: self.sequence,
                    origin: *origin,
                    endpoint: target.endpoint,
                    server_name: target.server_name,
                    expires: target.expires,
                };
                e.tls = TlsState::Waiting {
                    probe: probe.clone(),
                    until: now.saturating_add(10000).min(probe.expires),
                };
                out.push(Probe::Tls(probe));
            }
            if matches!(e.ddr,DdrState::Due(at) if at<=now) {
                self.sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
                let probe = DdrProbe {
                    id: self.sequence,
                    origin: *origin,
                    name: e.path.last().unwrap().clone(),
                };
                e.ddr = DdrState::Waiting {
                    id: probe.id,
                    until: now.saturating_add(3000).min(e.alias_expires),
                };
                out.push(Probe::Ddr(probe));
            }
        }
        Ok(out)
    }
    pub fn complete_tls(&mut self, id: u64, success: bool, now: u64) {
        if self.explicit {
            return;
        }
        for e in self.endpoints.values_mut() {
            let TlsState::Waiting { probe, until } = &e.tls else {
                continue;
            };
            if probe.id != id || *until <= now || probe.expires <= now {
                continue;
            }
            if success {
                e.working = Some(Designation {
                    endpoint: probe.endpoint,
                    server_name: probe.server_name.clone(),
                    priority: e.desired.as_ref().map_or(u16::MAX, |d| d.priority),
                    expires: probe.expires,
                });
                e.tls = TlsState::Idle(probe.expires);
            } else {
                e.tls = TlsState::Due(now.saturating_add(30000));
                e.reason = "TLS probe failed";
            }
            break;
        }
    }
    pub fn failed(&mut self, origin: SocketAddr, endpoint: SocketAddr, now: u64) {
        let Some(e) = self.endpoints.get_mut(&origin) else {
            return;
        };
        if e.working.as_ref().is_some_and(|t| t.endpoint == endpoint) {
            e.working = None;
            e.tls = TlsState::Due(now.saturating_add(30000));
            e.reason = "TLS transport failed; plaintext fallback";
        }
    }
    pub fn complete_ddr(
        &mut self,
        id: u64,
        message: &Message,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if self.explicit {
            return Err(invalid());
        }
        let Some((origin, e)) = self.endpoints.iter_mut().find(
            |(_, e)| matches!(e.ddr,DdrState::Waiting{id:token,until} if token==id && now<until),
        ) else {
            return Err(invalid());
        };
        e.ddr = DdrState::Idle(now.saturating_add(30000));
        if message.questions.len() != 1 || message.questions[0].name != *e.path.last().unwrap() {
            return Err(invalid());
        }
        let discovery = ddr_candidates(*origin, message, now, rng)?;
        if let Some((alias, expires)) = discovery.alias {
            if e.path.len() >= 17 || e.path.contains(&alias) {
                e.reset_ddr();
                return Err(invalid());
            }
            e.path.push(alias);
            e.alias_expires = e.alias_expires.min(expires);
            e.ddr = DdrState::Due(now);
            return Ok(());
        }
        if let Some(mut target) = discovery.candidates.into_iter().next() {
            target.expires = target.expires.min(e.alias_expires);
            e.ddr = DdrState::Idle(target.expires);
            let changed = e.desired.as_ref().is_none_or(|old| {
                old.endpoint != target.endpoint || old.server_name != target.server_name
            });
            if changed {
                e.tls = TlsState::Due(now);
            }
            e.desired = Some(target);
        }
        e.reset_ddr();
        Ok(())
    }
}
