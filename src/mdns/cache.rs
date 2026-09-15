//! AIL-scoped learned records. Registrations are owned by SRP, never by this LRU.
use super::tsr::{self, Relation, Stamp};
use crate::{
    dns::wire::{Message, Name, Question, Rdata, Record},
    time::{RandomSource, Time},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};
const SETS: usize = 1024;
const BYTES: usize = 4 * 1024 * 1024;
type Key = (Name, u16, u16);
struct Entry {
    record: Record,
    received: Time,
    expires: Time,
    charge: usize,
    stamp: Option<Stamp>,
    refresh: [Time; 4],
    refreshed: usize,
    // First unanswered multicast question, last distinct query, and count.
    failure: Option<(Time, Time, u8)>,
}
impl Entry {
    fn deadline(&self) -> Time {
        self.failure.filter(|f| f.2 >= 2).map_or(self.expires, |f| {
            self.expires.min(f.0.saturating_add(10000))
        })
    }
}
#[derive(Default)]
struct Set {
    records: Vec<Entry>,
    used: Time,
}
#[derive(Default)]
pub struct Cache {
    sets: BTreeMap<Key, Set>,
    bytes: usize,
    reserved: usize,
}
fn key(r: &Record) -> Key {
    (r.name.clone(), r.kind, r.class & 0x7fff)
}
pub(crate) fn same(a: &Record, b: &Record) -> bool {
    a.name == b.name && a.kind == b.kind && a.class & 0x7fff == b.class & 0x7fff && a.data == b.data
}
pub(crate) fn matches(q: &Question, r: &Record) -> bool {
    q.name == r.name
        && (q.class & 0x7fff == 255 || q.class & 0x7fff == r.class & 0x7fff)
        && (q.kind == 255 || q.kind == r.kind || r.kind == 5)
}
pub(crate) fn charge(r: &Record) -> Option<usize> {
    // The multiplier includes decoded labels/TXT vectors, the RRset key/index,
    // Vec slack, and the bounded response/encoding work copy.
    let mut m = Message::new(0, 0x8400);
    m.answers.push(r.clone());
    m.encode()
        .ok()
        .map(|b| 1024 + 16 * b.len() + decoded_overhead(r))
}
pub(crate) fn cacheable(r: &Record) -> bool {
    !matches!(r.kind, 0 | 41 | 249 | 250 | 251 | 252 | 253 | 254 | 255)
        && !matches!(
            r.data,
            Rdata::Opaque(_) | Rdata::Empty | Rdata::Sig { covered: 0, .. }
        )
        && r.class & 0x7fff != 0
        && r.class & 0x7fff != 255
}
impl Cache {
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.sets.len(),
            self.sets.values().map(|s| s.records.len()).sum(),
            self.bytes + self.reserved,
        )
    }
    pub fn clear(&mut self) {
        self.sets.clear();
        self.bytes = 0;
    }
    pub fn next_deadline(&self) -> Option<Time> {
        self.sets
            .values()
            .flat_map(|s| &s.records)
            .map(Entry::deadline)
            .min()
    }
    pub fn expire(&mut self, now: Time) {
        self.sets.retain(|_, s| {
            s.records.retain(|e| {
                if e.deadline() <= now {
                    self.bytes -= e.charge;
                    false
                } else {
                    true
                }
            });
            // Bound retained capacity after churn, not merely the vector length.
            s.records.shrink_to_fit();
            !s.records.is_empty()
        });
    }
    pub fn receive(
        &mut self,
        message: &Message,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        self.receive_with_code(message, tsr::OPTION_CODE, now, rng)
    }
    pub fn receive_with_code(
        &mut self,
        message: &Message,
        code: u16,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if message.answers.len() + message.authority.len() + message.additional.len() > 512 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mDNS record work limit",
            ));
        }
        self.expire(now);
        let stamps = tsr::extract(message, code, now)?;
        let mut selected = BTreeMap::new();
        let mut ignored = BTreeSet::new();
        for (index, r) in message
            .answers
            .iter()
            .chain(&message.authority)
            .chain(&message.additional)
            .enumerate()
        {
            if !cacheable(r)
                || (message.flags & 0x8000 == 0 && index < message.answers.len())
                || selected.contains_key(&r.name)
                || ignored.contains(&r.name)
            {
                continue;
            }
            let remote = stamps.get(&r.name).copied();
            let mut chosen = remote;
            if let Some(local) = self.owner_stamp(&r.name, now) {
                match tsr::compare(local, remote) {
                    Relation::Older => {
                        ignored.insert(r.name.clone());
                        continue;
                    }
                    Relation::Newer | Relation::Conflict => self.remove_owner(&r.name),
                    Relation::Equal => {
                        if let (Some(a), Some(b)) = (local, remote) {
                            chosen = Some(Stamp {
                                received_at: a.received_at.min(b.received_at),
                                ..b
                            });
                        }
                    }
                    Relation::Unstamped => {}
                }
            }
            selected.insert(r.name.clone(), chosen);
        }

        for (index, r) in message
            .answers
            .iter()
            .chain(&message.authority)
            .chain(&message.additional)
            .enumerate()
        {
            if !cacheable(r)
                || ignored.contains(&r.name)
                || (message.flags & 0x8000 == 0
                    && index < message.answers.len() + message.authority.len())
            {
                continue;
            }
            let k = key(r);
            if r.ttl == 0 {
                if let Some(s) = self.sets.get_mut(&k) {
                    for e in &mut s.records {
                        if same(&e.record, r) {
                            e.expires = e.expires.min(now.saturating_add(1000));
                        }
                    }
                }
                continue;
            }
            let Some(cost) = charge(r).filter(|n| *n <= BYTES) else {
                continue;
            };
            let ttl_ms = u64::from(r.ttl.min(0x7fffffff)) * 1000;
            let jitter = rng.sample(ttl_ms / 50)?;
            let refresh = [80, 85, 90, 95]
                .map(|p| now.saturating_add(ttl_ms * p / 100).saturating_add(jitter));
            if let Some(s) = self.sets.get_mut(&k) {
                if r.class & 0x8000 != 0 {
                    for e in &mut s.records {
                        if now.saturating_sub(e.received) > 1000 {
                            e.expires = e.expires.min(now.saturating_add(1000));
                        }
                    }
                }
                if let Some(e) = s.records.iter_mut().find(|e| same(&e.record, r)) {
                    e.received = now;
                    e.expires = now.saturating_add(u64::from(r.ttl.min(0x7fffffff)) * 1000);
                    e.record.ttl = r.ttl.min(0x7fffffff);
                    e.record.class = r.class; // Preserve uniqueness separately from the RRset class.
                    e.failure = None;
                    e.stamp = selected.get(&r.name).copied().flatten();
                    e.refresh = refresh;
                    e.refreshed = 0;
                    s.used = now;
                    continue;
                }
            }
            while self.bytes + self.reserved + cost > BYTES
                || (!self.sets.contains_key(&k) && self.sets.len() == SETS)
            {
                let Some(oldest) = self
                    .sets
                    .iter()
                    .min_by_key(|(_, s)| s.used)
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                let old = self.sets.remove(&oldest).unwrap();
                self.bytes -= old.records.iter().map(|e| e.charge).sum::<usize>();
            }
            let s = self.sets.entry(k).or_default();
            let mut record = r.clone();
            record.ttl = record.ttl.min(0x7fffffff);
            let expires = now.saturating_add(u64::from(record.ttl) * 1000);
            s.records.push(Entry {
                record,
                received: now,
                expires,
                charge: cost,
                stamp: selected.get(&r.name).copied().flatten(),
                refresh,
                refreshed: 0,
                failure: None,
            });
            s.used = now;
            self.bytes += cost;
        }
        Ok(())
    }
    pub fn owner_stamp(&self, name: &Name, now: Time) -> Option<Option<Stamp>> {
        self.sets
            .values()
            .flat_map(|s| &s.records)
            .find(|e| e.record.name == *name && e.deadline() > now)
            .map(|e| e.stamp)
    }
    pub fn remove_owner(&mut self, name: &Name) {
        self.sets.retain(|(owner, _, _), s| {
            if *owner == *name {
                self.bytes -= s.records.iter().map(|r| r.charge).sum::<usize>();
                false
            } else {
                true
            }
        });
    }
    pub fn answers(&mut self, q: &Question, now: Time) -> Vec<Record> {
        let mut out = vec![];
        for s in self.sets.values_mut() {
            for e in &s.records {
                if e.deadline() > now && matches(q, &e.record) {
                    let mut r = e.record.clone();
                    r.class &= 0x7fff;
                    r.ttl = e
                        .deadline()
                        .saturating_sub(now)
                        .div_ceil(1000)
                        .min(u64::from(u32::MAX)) as u32;
                    out.push(r);
                    s.used = now;
                }
            }
        }
        out
    }
    pub fn negative(&self, q: &Question, now: Time) -> bool {
        if q.kind == 255 {
            return false;
        }
        self.sets.values().flat_map(|s| &s.records).any(|e| {
            if e.deadline() <= now
                || e.record.name != q.name
                || e.record.class & 0x7fff != q.class & 0x7fff
            {
                return false;
            }
            let Rdata::Nsec { bitmap, .. } = &e.record.data else {
                return false;
            };
            !bitmap_has(bitmap, q.kind) && !bitmap_has(bitmap, 5)
        })
    }
    pub(crate) fn reserve(&mut self, bytes: usize) {
        self.reserved = bytes;
        while self.bytes + self.reserved > BYTES {
            let Some(k) = self
                .sets
                .iter()
                .min_by_key(|(_, s)| s.used)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.bytes -= self
                .sets
                .remove(&k)
                .unwrap()
                .records
                .iter()
                .map(|e| e.charge)
                .sum::<usize>();
        }
    }
    pub(crate) fn timing(&self, q: &Question, now: Time) -> (bool, Option<Time>) {
        let entries = self
            .sets
            .values()
            .flat_map(|s| &s.records)
            .filter(|e| e.deadline() > now && interested(q, &e.record));
        let unique = entries.clone().any(|e| e.record.class & 0x8000 != 0);
        (
            unique,
            entries
                .filter_map(|e| e.refresh.get(e.refreshed).copied())
                .min(),
        )
    }
    pub(crate) fn refreshed(&mut self, q: &Question, now: Time) {
        for e in self.sets.values_mut().flat_map(|s| &mut s.records) {
            if interested(q, &e.record) {
                while e.refresh.get(e.refreshed).is_some_and(|t| *t <= now) {
                    e.refreshed += 1;
                }
            }
        }
    }
    pub(crate) fn known(&mut self, q: &Question, now: Time) -> Vec<Record> {
        let mut out = vec![];
        for s in self.sets.values_mut() {
            for e in &s.records {
                let remaining = e.deadline().saturating_sub(now) / 1000;
                if interested(q, &e.record)
                    && remaining >= u64::from(e.record.ttl.div_ceil(2))
                    && remaining > 0
                {
                    let mut r = e.record.clone();
                    r.class &= 0x7fff;
                    r.ttl = remaining as u32;
                    out.push(r);
                    s.used = now;
                }
            }
        }
        out
    }
    pub(crate) fn suspect(&mut self, q: &Question, now: Time) {
        for e in self.sets.values_mut().flat_map(|s| &mut s.records) {
            if interested(q, &e.record) {
                e.expires = e.expires.min(now.saturating_add(10000));
            }
        }
    }
    pub fn observe_question(&mut self, q: &Question, known: &[Record], now: Time) {
        if q.class & 0x8000 != 0 {
            return;
        }
        for e in self.sets.values_mut().flat_map(|s| &mut s.records) {
            if e.deadline() <= now
                || !matches(q, &e.record)
                || known
                    .iter()
                    .any(|r| same(r, &e.record) && r.ttl >= e.record.ttl.div_ceil(2))
            {
                continue;
            }
            match &mut e.failure {
                None => e.failure = Some((now, now, 1)),
                Some(f) if now.saturating_sub(f.1) >= 1000 => {
                    f.1 = now;
                    f.2 = f.2.saturating_add(1);
                }
                _ => {}
            }
        }
    }
}
pub(crate) fn bitmap_has(mut b: &[u8], kind: u16) -> bool {
    while b.len() >= 2 {
        let n = usize::from(b[1]);
        if n == 0 || n > 32 || b.len() < n + 2 {
            return false;
        }
        if u16::from(b[0]) == kind / 256 {
            let bit = usize::from(kind % 256);
            return bit / 8 < n && b[2 + bit / 8] & (0x80 >> (bit % 8)) != 0;
        }
        b = &b[2 + n..];
    }
    false
}

fn interested(q: &Question, r: &Record) -> bool {
    matches(q, r) || (r.kind == 47 && r.name == q.name && r.class & 0x7fff == q.class & 0x7fff)
}

// Wire-byte multipliers alone miss a long name made of one-byte labels, or
// TXT containing many empty character strings. Charge their Vec structures
// and the bounded projection/response copies explicitly as well.
pub(crate) fn decoded_overhead(r: &Record) -> usize {
    let mut labels = r.name.labels().len();
    let vectors = match &r.data {
        Rdata::Name(n)
        | Rdata::Srv { target: n, .. }
        | Rdata::Preference { name: n, .. }
        | Rdata::Nsec { next: n, .. }
        | Rdata::Sig { signer: n, .. }
        | Rdata::Svcb { target: n, .. } => {
            labels += n.labels().len();
            0
        }
        Rdata::TwoNames { first, second } => {
            labels += first.labels().len() + second.labels().len();
            0
        }
        Rdata::Px {
            map822, mapx400, ..
        } => {
            labels += map822.labels().len() + mapx400.labels().len();
            0
        }
        Rdata::Soa { mname, rname, .. } => {
            labels += mname.labels().len() + rname.labels().len();
            0
        }
        Rdata::Txt(v) => v.len(),
        Rdata::Opt(v) => v.len(),
        _ => 0,
    };
    128 * (labels + vectors)
}
