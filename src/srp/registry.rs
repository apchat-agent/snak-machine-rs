//! Durable FCFS ownership and independent host/service record and key leases.
use super::wire::{Error, Key, Update};
use crate::{
    dns::wire::{Message, Name, Rdata, Record},
    persist::StateStore,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};
mod journal;
#[derive(Clone, Copy, Debug)]
pub struct LeasePolicy {
    pub max_lease: u32,
    pub max_key_lease: u32,
    pub min_ttl: u32,
    pub max_ttl: u32,
}
impl Default for LeasePolicy {
    fn default() -> Self {
        Self {
            max_lease: 7200,
            max_key_lease: 1209600,
            min_ttl: 30,
            max_ttl: 4500,
        }
    }
}
impl LeasePolicy {
    pub fn validate(self) -> io::Result<Self> {
        if self.max_lease == 0
            || self.max_key_lease < self.max_lease
            || self.min_ttl == 0
            || self.min_ttl > self.max_ttl
            || self.max_ttl > i32::MAX as u32
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid SRP lease/TTL policy",
            ));
        }
        Ok(self)
    }
}
const MAX_BYTES: usize = 4 * 1024 * 1024;
#[derive(Clone, Debug)]
pub struct Host {
    pub key: Key,
    pub addresses: Vec<Record>,
    pub expires: u64,
    pub key_expires: u64,
    pub received_at: i128,
}
#[derive(Clone, Debug)]
pub struct Service {
    pub host: Name,
    pub key: Key,
    pub records: Vec<Record>,
    pub discovery: Vec<Record>,
    pub expires: u64,
    pub key_expires: u64,
    pub received_at: i128,
}
#[derive(Clone, Default)]
pub struct Registry {
    hosts: BTreeMap<Name, Host>,
    services: BTreeMap<Name, Service>,
    replies: BTreeMap<[u8; 32], Receipt>,
    policy: LeasePolicy,
}
#[derive(Clone)]
struct Receipt {
    grant: Grant,
    received_at: i128,
    expires: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Grant {
    pub lease: u32,
    pub key_lease: u32,
}
impl Grant {
    pub fn response(&self, request: &Message) -> io::Result<Vec<u8>> {
        let length = request.additional.iter().find_map(|r| {
            if let Rdata::Opt(v) = &r.data {
                v.iter().find(|(code, _)| *code == 2).map(|(_, b)| b.len())
            } else {
                None
            }
        });
        if !matches!(length, Some(4 | 8)) || request.questions.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid lease response request",
            ));
        }
        let mut m = Message::new(request.id, 0xa800);
        m.questions = request.questions.clone();
        let mut bytes = self.lease.to_be_bytes().to_vec();
        if length == Some(8) {
            bytes.extend(self.key_lease.to_be_bytes());
        }
        m.additional.push(Record {
            name: Name::root(),
            kind: 41,
            class: 4096,
            ttl: 0,
            data: Rdata::Opt(vec![(2, bytes)]),
        });
        m.encode()
    }
}
impl Registry {
    pub fn set_policy(&mut self, policy: LeasePolicy) -> io::Result<()> {
        self.policy = policy.validate()?;
        Ok(())
    }

    pub fn cached(&self, bytes: &[u8], now: u64) -> Option<Grant> {
        if bytes.len() > 65535 {
            return None;
        }
        self.cached_digest(&super::wire::fingerprint(bytes), now)
    }
    fn cached_digest(&self, digest: &[u8; 32], now: u64) -> Option<Grant> {
        let r = self.replies.get(digest).filter(|r| r.expires > now)?;
        let elapsed = ((now as i128 - r.received_at).max(0) / 1000).min(u32::MAX.into()) as u32;
        Some(Grant {
            lease: r.grant.lease.saturating_sub(elapsed),
            key_lease: r.grant.key_lease.saturating_sub(elapsed),
        })
    }
    pub fn replay_count(&self) -> usize {
        self.replies.len()
    }

    pub fn hosts(&self) -> impl Iterator<Item = (&Name, &Host)> {
        self.hosts.iter()
    }
    pub fn services(&self) -> impl Iterator<Item = (&Name, &Service)> {
        self.services.iter()
    }
    pub fn key(&self, name: &Name, now: u64) -> Option<&Key> {
        self.hosts
            .get(name)
            .filter(|h| h.key_expires > now)
            .map(|h| &h.key)
            .or_else(|| {
                self.services
                    .get(name)
                    .filter(|s| s.key_expires > now)
                    .map(|s| &s.key)
            })
    }
    pub fn records(&self, name: &Name, kind: u16, now: u64) -> Vec<Record> {
        let mut out = vec![];
        if let Some(h) = self.hosts.get(name) {
            if h.key_expires > now && (kind == 25 || kind == 255) {
                out.push(key_record(
                    name,
                    &h.key,
                    self.key_ttl(h.key_expires, h.received_at),
                ));
            }
            if h.expires > now {
                out.extend(
                    h.addresses
                        .iter()
                        .filter(|r| kind == 255 || kind == r.kind)
                        .cloned(),
                );
            }
        }
        for (owner, s) in &self.services {
            if owner == name && s.key_expires > now && (kind == 25 || kind == 255) {
                out.push(key_record(
                    owner,
                    &s.key,
                    self.key_ttl(s.key_expires, s.received_at),
                ));
            }
            if !self.service_live(s, now) {
                continue;
            }
            out.extend(
                s.records
                    .iter()
                    .chain(s.discovery.iter())
                    .filter(|r| r.name == *name && (kind == 255 || r.kind == kind))
                    .cloned(),
            );
        }
        // Shared PTR RRsets can be supplied by different hosts with different
        // advisory TTLs. Return a consistent constant TTL for the whole RRset.
        let mut ttls = BTreeMap::new();
        for r in &out {
            let ttl = ttls.entry(r.kind).or_insert(r.ttl);
            *ttl = (*ttl).min(r.ttl);
        }
        for r in &mut out {
            r.ttl = ttls[&r.kind];
        }
        out.dedup_by(|a, b| a.name == b.name && a.kind == b.kind && a.data == b.data);
        out
    }
    fn key_ttl(&self, expires: u64, received_at: i128) -> u32 {
        120u32
            .clamp(self.policy.min_ttl, self.policy.max_ttl)
            .min(((expires as i128 - received_at).max(0) / 1000).min(u32::MAX.into()) as u32)
    }
    fn service_live(&self, s: &Service, now: u64) -> bool {
        s.expires > now
            && self
                .hosts
                .get(&s.host)
                .is_some_and(|h| h.expires > now && h.key.same_public_key(&s.key))
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.hosts
            .values()
            .flat_map(|h| [h.expires, h.key_expires])
            .chain(
                self.services
                    .values()
                    .flat_map(|s| [s.expires, s.key_expires]),
            )
            .filter(|t| *t != 0)
            .min()
    }
    pub fn expire(&mut self, now: u64) {
        self.replies.retain(|_, r| r.expires > now);
        self.hosts.retain(|_, h| h.key_expires > now);
        for h in self.hosts.values_mut() {
            if h.expires <= now {
                h.addresses.clear();
                h.addresses.shrink_to_fit();
                h.expires = 0;
            }
        }
        self.services.retain(|_, s| s.key_expires > now);
        for s in self.services.values_mut() {
            if s.expires <= now
                || !self
                    .hosts
                    .get(&s.host)
                    .is_some_and(|h| h.expires > now && h.key.same_public_key(&s.key))
            {
                s.records.clear();
                s.records.shrink_to_fit();
                s.discovery.clear();
                s.discovery.shrink_to_fit();
                s.expires = 0;
            }
        }
    }
    pub fn counts(&self) -> (usize, usize, usize) {
        let parents: BTreeSet<_> = self
            .hosts
            .keys()
            .chain(self.services.values().map(|s| &s.host))
            .collect();
        (parents.len(), self.services.len(), self.charge())
    }
    fn charge(&self) -> usize {
        let hosts: usize = self
            .hosts
            .iter()
            .map(|(n, h)| 384 + name_charge(n) + h.key.bytes.len() + records_charge(&h.addresses))
            .sum();
        let services: usize = self
            .services
            .iter()
            .map(|(n, s)| {
                384 + name_charge(n)
                    + name_charge(&s.host)
                    + s.key.bytes.len()
                    + records_charge(&s.records)
                    + records_charge(&s.discovery)
            })
            .sum();
        // Two reducer images plus wire journal/work space. No unbounded retry history.
        (hosts + services + 192 * self.replies.len()) * 3
    }
    pub fn apply(
        &mut self,
        u: &Update,
        store: &mut (impl StateStore + ?Sized),
        now: u64,
        wall: u64,
    ) -> Result<Grant, Error> {
        self.apply_checked(u, store, now, wall, &|_| Ok(()))
    }
    pub(crate) fn apply_checked(
        &mut self,
        u: &Update,
        store: &mut (impl StateStore + ?Sized),
        now: u64,
        wall: u64,
        accept: &impl Fn(&Self) -> Result<(), Error>,
    ) -> Result<Grant, Error> {
        if let Some(grant) = self.cached_digest(&u.digest, now) {
            return Ok(grant);
        }
        for n in std::iter::once(&u.host).chain(u.services.iter().map(|s| &s.name)) {
            if self.key(n, now).is_some_and(|k| !k.same_public_key(&u.key)) {
                return Err(Error::YxDomain);
            }
        }
        let grant = Grant {
            lease: u.lease.min(self.policy.max_lease),
            key_lease: u.key_lease.min(if u.extended_lease {
                self.policy.max_key_lease
            } else {
                self.policy.max_lease
            }),
        };
        if grant.key_lease < grant.lease {
            return Err(Error::Refused);
        }
        let work = name_charge(&u.host)
            + records_charge(&u.addresses)
            + u.services
                .iter()
                .map(|s| {
                    name_charge(&s.name)
                        + records_charge(&s.records)
                        + records_charge(&s.discovery)
                        + 512
                })
                .sum::<usize>();
        if self.charge().saturating_add(work * 2) > MAX_BYTES {
            return Err(Error::ServFail);
        }
        let mut next = self.clone();
        next.expire(now);
        let expires = now.saturating_add(u64::from(grant.lease) * 1000);
        let key_expires = now.saturating_add(u64::from(grant.key_lease) * 1000);
        if grant.key_lease == 0 {
            next.hosts.remove(&u.host);
            next.services
                .retain(|_, s| s.host != u.host || !s.key.same_public_key(&u.key));
        } else {
            next.hosts.insert(
                u.host.clone(),
                Host {
                    key: u.key.clone(),
                    addresses: normalized(&u.addresses, grant.lease, self.policy),
                    expires: if grant.lease == 0 { 0 } else { expires },
                    key_expires,
                    received_at: now.into(),
                },
            );
            if grant.lease == 0 {
                for s in next
                    .services
                    .values_mut()
                    .filter(|s| s.host == u.host && s.key.same_public_key(&u.key))
                {
                    s.records.clear();
                    s.discovery.clear();
                    s.expires = 0;
                }
            }
            for s in &u.services {
                let live = !s.deleted && grant.lease != 0;
                next.services.insert(
                    s.name.clone(),
                    Service {
                        host: u.host.clone(),
                        key: u.key.clone(),
                        records: normalized(&s.records, grant.lease, self.policy),
                        discovery: normalized(&s.discovery, grant.lease, self.policy),
                        expires: if live { expires } else { 0 },
                        key_expires,
                        received_at: now.into(),
                    },
                );
            }
        }
        if next.replies.len() == 128 {
            let oldest = *next
                .replies
                .iter()
                .min_by_key(|(_, r)| r.received_at)
                .unwrap()
                .0;
            next.replies.remove(&oldest);
        }
        next.replies.insert(
            u.digest,
            Receipt {
                grant,
                received_at: now.into(),
                expires: now.saturating_add(30000),
            },
        );
        next.check_bounds()?;
        accept(&next)?;
        let bytes = next.encode(now, wall).map_err(|_| Error::ServFail)?;
        store.save(&bytes).map_err(|_| Error::ServFail)?;
        *self = next;
        Ok(grant)
    }
    fn check_bounds(&self) -> Result<(), Error> {
        let (hosts, services, bytes) = self.counts();
        if hosts > 128 || services > 1024 || self.replies.len() > 128 || bytes > MAX_BYTES {
            return Err(Error::ServFail);
        }
        let mut per_host = BTreeMap::new();
        for s in self.services.values() {
            let count = per_host.entry(&s.host).or_insert(0);
            *count += 1;
            if *count > 8 {
                return Err(Error::ServFail);
            }
        }
        Ok(())
    }
    pub fn restore(bytes: &[u8], now: u64, wall: u64) -> io::Result<Self> {
        Self::decode(bytes, now, wall)
    }
}
fn key_record(name: &Name, key: &Key, ttl: u32) -> Record {
    Record {
        name: name.clone(),
        kind: 25,
        class: 1,
        ttl,
        data: key.rdata(),
    }
}
fn normalized(records: &[Record], lease: u32, policy: LeasePolicy) -> Vec<Record> {
    let mut out = vec![];
    for r in records {
        let mut r = r.clone();
        r.ttl = r.ttl.clamp(policy.min_ttl, policy.max_ttl).min(lease);
        if !out.contains(&r) {
            out.push(r);
        }
    }
    out
}
fn name_charge(n: &Name) -> usize {
    64 + 4 * n.canonical().len() + 48 * n.labels().len()
}
fn records_charge(rs: &[Record]) -> usize {
    rs.iter()
        .map(|r| {
            128 + name_charge(&r.name)
                + match &r.data {
                    Rdata::Name(n) => name_charge(n),
                    Rdata::Srv { target, .. } => name_charge(target),
                    Rdata::Txt(v) => v.iter().map(|s| 48 + s.len() * 2).sum(),
                    Rdata::Key { key, .. } => key.len() * 2,
                    _ => 32,
                }
        })
        .sum()
}
