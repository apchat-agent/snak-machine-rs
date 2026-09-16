//! Registry-owned publication identity and transient changes awaiting mDNS delivery.
use super::{invalid, Mapping};
use crate::{
    dns::wire::{Name, Record},
    mdns::{tsr::RegistrationError, Engine},
    srp::{registry::Registry, wire::Error},
    time::{RandomSource, Time},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};
struct Slot {
    id: u64,
    mapping: Mapping,
    version: u32,
    projected_at: Time,
    next_change: Time,
}
#[derive(Default)]
pub(crate) struct Proxy {
    slots: BTreeMap<Name, Slot>,
    pending: BTreeMap<Name, Vec<Record>>,
    sequence: u64,
    zone: Option<Name>,
}
impl Proxy {
    pub fn set_zone(&mut self, zone: Name) -> io::Result<()> {
        if !self.slots.is_empty() || !self.pending.is_empty() || zone.labels().is_empty() {
            return Err(invalid());
        }
        self.zone = Some(zone);
        Ok(())
    }
    fn mapping(&self) -> Mapping {
        let zone = self
            .zone
            .clone()
            .unwrap_or_else(|| "default.service.arpa.".parse().unwrap());
        let digest = crate::srp::wire::fingerprint(zone.canonical());
        Mapping::new(zone, &digest[..8]).unwrap()
    }
    pub fn next_deadline(&self) -> Option<Time> {
        self.slots.values().map(|s| s.next_change).min()
    }
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.slots.len(),
            self.pending.len(),
            self.pending
                .values()
                .map(|r| crate::mdns::publish::estimate(r).map_or(0, |(_, n)| n))
                .sum(),
        )
    }
    pub fn preflight(&self, registry: &Registry, now: Time) -> Result<(), Error> {
        let mut count = 0;
        let mut bytes = 0;
        let mut hosts = 0;
        for (name, _) in registry.hosts() {
            let map = self
                .slots
                .get(name)
                .map(|s| s.mapping.clone())
                .unwrap_or_else(|| self.mapping());
            let records = map
                .project(registry, name, now)
                .map_err(|_| Error::ServFail)?;
            if records.is_empty() {
                continue;
            }
            let (n, size) =
                crate::mdns::publish::estimate_stamped(&records).map_err(|_| Error::ServFail)?;
            hosts += 1;
            count += n;
            bytes += size;
            // Reserve equal work space for simultaneous old-data withdrawals.
            if hosts > 128 || count > 4096 || bytes > (4 * 1024 * 1024 - 8192) / 2 {
                return Err(Error::ServFail);
            }
        }
        Ok(())
    }
    pub fn capture(
        &self,
        registry: &Registry,
        changed: &BTreeSet<Name>,
        now: Time,
    ) -> io::Result<BTreeMap<Name, Vec<Record>>> {
        self.slots
            .iter()
            .filter(|(n, s)| {
                !self.pending.contains_key(*n) && (changed.contains(*n) || s.next_change <= now)
            })
            .map(|(n, s)| Ok((n.clone(), s.mapping.project(registry, n, s.projected_at)?)))
            .collect()
    }
    pub fn committed(&mut self, before: BTreeMap<Name, Vec<Record>>) {
        for (n, records) in before {
            self.pending.entry(n).or_insert(records);
        }
    }
    pub fn records(&self, registry: &Registry, id: u64, now: Time) -> Vec<Record> {
        let Some((n, s)) = self.slots.iter().find(|(_, s)| s.id == id) else {
            return vec![];
        };
        if let Some(records) = self.pending.get(n) {
            let ttl = (s.next_change.saturating_add(999).saturating_sub(now) / 1000)
                .max(1)
                .min(u64::from(u32::MAX)) as u32;
            return records
                .iter()
                .cloned()
                .map(|mut r| {
                    r.ttl = r.ttl.min(ttl);
                    r
                })
                .collect();
        }
        s.mapping.project(registry, n, now).unwrap_or_default()
    }
    pub fn sync(
        &mut self,
        registry: &Registry,
        engine: &mut Engine,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let mut conflicts = BTreeSet::new();
        while let Some(id) = engine.publisher.take_conflict() {
            conflicts.insert(id);
        }
        let names: BTreeSet<_> = registry
            .hosts()
            .map(|(n, _)| n.clone())
            .chain(self.slots.keys().cloned())
            .collect();
        let mut ordered = names
            .into_iter()
            .map(|name| {
                let map = self
                    .slots
                    .get(&name)
                    .map(|s| s.mapping.clone())
                    .unwrap_or_else(|| self.mapping());
                let live = !map.project(registry, &name, now)?.is_empty();
                Ok((live, name))
            })
            .collect::<io::Result<Vec<_>>>()?;
        ordered.sort();
        // Retire expired slots before admitting a replacement into a full table.
        for (live, name) in ordered {
            if !live && !self.slots.contains_key(&name) {
                continue;
            }

            let prior = self.slots.get(&name);
            let old = if let Some(r) = self.pending.get(&name) {
                r.clone()
            } else if let Some(s) = prior {
                s.mapping.project(registry, &name, s.projected_at)?
            } else {
                vec![]
            };
            let mut map = prior
                .map(|s| s.mapping.clone())
                .unwrap_or_else(|| self.mapping());
            let mut version = prior.map_or(1, |s| s.version);
            let id = if let Some(s) = prior {
                s.id
            } else {
                if self.slots.len() >= 128 {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "AP dataset capacity",
                    ));
                }
                self.sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
                (1 << 63) | self.sequence
            };
            if conflicts.contains(&id) {
                version = version.checked_add(1).ok_or_else(invalid)?;
                map = map.renamed(version)?;
            }
            let mut installed = false;
            let mut empty = false;
            for _ in 0..8 {
                let new = map.project(registry, &name, now)?;
                empty = new.is_empty();
                let stamps = new
                    .iter()
                    .filter(|r| r.class & 0x8000 != 0)
                    .filter_map(|r| {
                        map.stamp(registry, &r.name, now)
                            .map(|s| (r.name.clone(), s))
                    })
                    .collect();
                match engine.register_tsr(id, (&old, &new), &stamps, now, rng) {
                    Ok(()) => {
                        installed = true;
                        break;
                    }
                    Err(RegistrationError::Conflict) => {
                        version = version.checked_add(1).ok_or_else(invalid)?;
                        map = map.renamed(version)?;
                    }
                    Err(RegistrationError::Capacity) => {
                        // Keep the old bounded view until capacity returns. It
                        // cannot remain visible past its original backing lease.
                        if prior.is_some_and(|s| s.next_change <= now) {
                            engine.publisher.pause(id);
                        }
                        break;
                    }
                    Err(RegistrationError::Stale) => break,
                    Err(RegistrationError::Invalid) => return Err(invalid()),
                }
            }
            if !installed {
                continue;
            }
            self.pending.remove(&name);
            if empty {
                self.slots.remove(&name);
                continue;
            }
            let next_change = registry
                .hosts()
                .filter(|(n, _)| **n == name)
                .map(|(_, h)| h.expires)
                .chain(
                    registry
                        .services()
                        .filter(|(_, s)| s.host == name && s.expires > now)
                        .map(|(_, s)| s.expires),
                )
                .min()
                .unwrap_or(now)
                .saturating_sub(999);
            self.slots.insert(
                name,
                Slot {
                    id,
                    mapping: map,
                    version,
                    projected_at: now,
                    next_change,
                },
            );
        }
        Ok(())
    }
}
