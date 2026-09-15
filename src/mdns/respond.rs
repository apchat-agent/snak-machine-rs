//! Delayed replies retain bounded record identities, never subscriber zone copies.
use super::{
    cache::{bitmap_has, matches, same},
    publish::{identity, pack, Digest, Publisher},
    wire::{multicast, Datagram},
};
use crate::{
    dns::wire::{Message, Question, Rdata, Record},
    time::{RandomSource, Time},
};
use std::{collections::BTreeMap, io, net::SocketAddr};
type Ref = (u64, Digest);
struct Pending {
    source: SocketAddr,
    destination: SocketAddr,
    // false = direct answer, true = DNS-SD additional record.
    records: BTreeMap<Ref, bool>,
    questions: Vec<Question>,
    id: u16,
    due: Time,
    expires: Time,
    probe: bool,
}
impl Pending {
    fn legacy(&self) -> bool {
        self.destination.port() != 5353
    }
    fn charge(&self) -> usize {
        1024 + 128 * self.records.len() + 8192 * self.questions.len()
    }
}
pub struct Reply {
    pub token: u64,
    pub destination: SocketAddr,
    pub messages: Vec<Message>,
}
#[derive(Default)]
pub struct Responder {
    pending: BTreeMap<u64, Pending>,
    next: u64,
    offered: Option<u64>,
}
fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "mDNS response capacity")
}
fn references(records: Vec<(u64, Record)>) -> io::Result<Vec<(Ref, Record)>> {
    records
        .into_iter()
        .map(|(id, r)| Ok(((id, identity(&r)?), r)))
        .collect()
}
impl Responder {
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.pending.len(),
            self.pending.values().map(|p| p.records.len()).sum(),
            self.pending.values().map(Pending::charge).sum(),
        )
    }
    pub fn clear(&mut self) {
        self.pending.clear();
        self.offered = None;
    }
    pub fn next_deadline(&self) -> Option<Time> {
        self.pending.values().map(|p| p.due.min(p.expires)).min()
    }
    fn expire(&mut self, now: Time) {
        self.pending
            .retain(|_, p| p.expires > now && p.records.values().any(|additional| !additional));
    }
    pub fn receive(
        &mut self,
        d: &Datagram,
        on_link: bool,
        publisher: &mut Publisher,
        source: &impl Fn(u64, Time) -> Vec<Record>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        self.expire(now);
        if d.message.questions.len() > 128
            || d.message.answers.len() + d.message.authority.len() + d.message.additional.len()
                > 512
        {
            return Err(capacity());
        }
        if !d.destination.ip().is_multicast() && !on_link {
            return Ok(());
        }
        let all = references(publisher.all_ready(source, now)?)?;
        let m = &d.message;
        if m.flags & 0x8000 != 0 {
            for p in self.pending.values_mut() {
                if !p.destination.ip().is_multicast() {
                    continue;
                }
                p.records.retain(|key, _| {
                    !all.iter().find(|(k, _)| k == key).is_some_and(|(_, r)| {
                        m.answers
                            .iter()
                            .chain(&m.authority)
                            .chain(&m.additional)
                            .any(|peer| same(peer, r) && peer.ttl >= r.ttl)
                    })
                });
            }
            self.expire(now);
            return Ok(());
        }
        // Known-answer continuations apply only to the original querier's work.
        for p in self
            .pending
            .values_mut()
            .filter(|p| p.source == d.source && !p.legacy())
        {
            p.records.retain(|key, _| {
                !all.iter()
                    .find(|(k, _)| k == key)
                    .is_some_and(|(_, r)| known(m, r))
            });
            if m.flags & 0x200 != 0 {
                p.due = now.saturating_add(400 + rng.sample(100)?).min(p.expires);
            }
        }
        self.expire(now);
        if m.questions.is_empty() {
            return Ok(());
        }
        let all_unique = m.questions.iter().all(|q| {
            let answers = answers(q, &all);
            !answers.is_empty() && answers.iter().all(|(_, r)| r.class & 0x8000 != 0)
        });
        let probe = m
            .questions
            .iter()
            .any(|q| m.authority.iter().any(|r| matches(q, r)))
            && all_unique;
        let delay = if m.flags & 0x200 != 0 {
            400 + rng.sample(100)?
        } else if all_unique {
            0
        } else {
            20 + rng.sample(100)?
        };
        let mut work: BTreeMap<SocketAddr, Pending> = BTreeMap::new();
        for q in &m.questions {
            for (key, r) in answers(q, &all) {
                if d.source.port() == 5353 && known(m, r) {
                    continue;
                }
                let unicast = d.source.port() != 5353
                    || (on_link
                        && (q.class & 0x8000 != 0 || !d.destination.ip().is_multicast())
                        && (probe
                            || publisher
                                .last(key.0, &key.1)
                                .is_some_and(|t| now.saturating_sub(t) < u64::from(r.ttl) * 250)));
                let destination = if unicast {
                    d.source
                } else {
                    SocketAddr::new(multicast(d.source.is_ipv6()), 5353)
                };
                let p = work.entry(destination).or_insert_with(|| Pending {
                    source: d.source,
                    destination,
                    records: BTreeMap::new(),
                    questions: if d.source.port() != 5353 {
                        m.questions.clone()
                    } else {
                        vec![]
                    },
                    id: if d.source.port() != 5353 { m.id } else { 0 },
                    due: now.saturating_add(delay),
                    expires: now.saturating_add(2000),
                    probe,
                });
                p.records.insert(*key, false);
            }
        }
        for p in work.values_mut() {
            expand(p, &all);
        }
        let (n, refs, bytes) = self.counts();
        if n + work.len() > 128
            || refs + work.values().map(|p| p.records.len()).sum::<usize>() > 4096
            || bytes + publisher.counts().2 + work.values().map(Pending::charge).sum::<usize>()
                > 4 * 1024 * 1024
        {
            return Err(capacity());
        }
        for p in work.into_values() {
            self.next = self.next.checked_add(1).ok_or_else(capacity)?;
            self.pending.insert(self.next, p);
        }
        Ok(())
    }
    pub fn poll(
        &mut self,
        publisher: &Publisher,
        source: &impl Fn(u64, Time) -> Vec<Record>,
        now: Time,
    ) -> io::Result<Option<Reply>> {
        self.expire(now);
        let all = references(publisher.all_ready(source, now)?)?;
        for p in self.pending.values_mut() {
            p.records.retain(|key, _| all.iter().any(|(k, _)| k == key));
            if p.destination.ip().is_multicast() {
                for key in p.records.keys() {
                    if let Some(last) = publisher.last(key.0, &key.1) {
                        p.due = p
                            .due
                            .max(last.saturating_add(if p.probe { 250 } else { 1000 }));
                    }
                }
            }
        }
        self.expire(now);
        let Some((&token, p)) = self
            .pending
            .iter()
            .filter(|(_, p)| p.due <= now)
            .min_by_key(|(id, p)| (p.due, *id))
        else {
            return Ok(None);
        };
        // Include complete unique RRsets even when one member was suppressed.
        let mut selected = p.records.clone();
        for (key, r) in all
            .iter()
            .filter(|(key, r)| p.records.contains_key(key) && r.class & 0x8000 != 0)
        {
            for (other, member) in &all {
                if r.name == member.name
                    && r.kind == member.kind
                    && r.class & 0x7fff == member.class & 0x7fff
                {
                    selected.entry(*other).or_insert(p.records[key]);
                }
            }
        }
        let mut records = vec![];
        for additional in [false, true] {
            for (key, r) in &all {
                if selected.get(key) == Some(&additional) {
                    records.push(r.clone());
                }
            }
        }
        let mut messages = pack(&records, false)?;
        for m in &mut messages {
            let rrs = std::mem::take(&mut m.answers);
            for r in rrs {
                let hash = identity(&r)?;
                if selected
                    .iter()
                    .any(|((_, h), additional)| *h == hash && !additional)
                {
                    m.answers.push(r);
                } else {
                    m.additional.push(r);
                }
            }
        }
        if p.legacy() {
            let mut m = Message::new(p.id, 0x8400);
            m.questions = p.questions.clone();
            for packet in messages {
                m.answers.extend(packet.answers);
                m.additional.extend(packet.additional);
            }
            for r in m.answers.iter_mut().chain(&mut m.additional) {
                r.ttl = r.ttl.min(10);
                r.class &= 0x7fff;
            }
            while m.encode()?.len() > 512 {
                m.flags |= 0x200;
                if m.additional.pop().is_none() && m.answers.pop().is_none() {
                    // Legacy requests with an excessive question section cannot be echoed safely.
                    self.pending.remove(&token);
                    return Ok(None);
                }
            }
            messages = vec![m];
        }
        self.offered = Some(token);
        Ok(Some(Reply {
            token,
            destination: p.destination,
            messages,
        }))
    }
    pub(crate) fn offered(&self, token: u64, now: Time) -> bool {
        self.offered == Some(token) && self.pending.get(&token).is_some_and(|p| p.expires > now)
    }
    pub fn sent(&mut self, token: u64, success: bool, publisher: &mut Publisher, now: Time) {
        if self.offered != Some(token) {
            return;
        }
        self.offered = None;
        if success {
            if let Some(p) = self.pending.remove(&token) {
                if p.destination.ip().is_multicast() {
                    publisher.note(&p.records.keys().copied().collect::<Vec<_>>(), now);
                }
            }
        } else if let Some(p) = self.pending.get_mut(&token) {
            p.due = now.saturating_add(100);
        }
    }
}
fn known(m: &Message, r: &Record) -> bool {
    m.answers
        .iter()
        .any(|peer| same(peer, r) && peer.ttl >= r.ttl.div_ceil(2))
}
fn answers<'a>(q: &Question, all: &'a [(Ref, Record)]) -> Vec<(&'a Ref, &'a Record)> {
    let mut out: Vec<_> = all
        .iter()
        .filter(|(_, r)| matches(q, r))
        .map(|(k, r)| (k, r))
        .collect();
    if out.is_empty() {
        out.extend(all.iter().filter(|(_, r)| r.name == q.name && (q.class & 0x7fff == 255 || q.class & 0x7fff == r.class & 0x7fff))
            .filter(|(_, r)| matches!(&r.data, Rdata::Nsec { bitmap, .. } if !bitmap_has(bitmap, q.kind)))
            .map(|(k, r)| (k, r)));
    }
    out
}
fn expand(p: &mut Pending, all: &[(Ref, Record)]) {
    // PTR -> instance SRV/TXT -> host addresses; a fixed three passes suffices.
    for _ in 0..3 {
        let current: Vec<_> = all
            .iter()
            .filter(|(key, _)| p.records.contains_key(key))
            .collect();
        for (key, r) in current {
            for (other, candidate) in all {
                let rrset = r.class & 0x8000 != 0
                    && r.name == candidate.name
                    && r.kind == candidate.kind
                    && r.class & 0x7fff == candidate.class & 0x7fff;
                let related = match &r.data {
                    Rdata::Name(target) if r.kind == 12 => {
                        *target == candidate.name && [16, 33].contains(&candidate.kind)
                    }
                    Rdata::Srv { target, .. } => {
                        *target == candidate.name && [1, 28].contains(&candidate.kind)
                    }
                    _ => false,
                };
                if rrset {
                    let additional = p.records[key];
                    p.records.entry(*other).or_insert(additional);
                } else if related {
                    p.records.entry(*other).or_insert(true);
                }
            }
        }
    }
}
