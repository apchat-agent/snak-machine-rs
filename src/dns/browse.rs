//! Infrastructure enumeration evidence, scoped to resolver and query context.
use super::wire::{Message, Name, Question, Rdata};
use crate::mdns::advertise::within;
use std::{collections::BTreeMap, io, net::SocketAddr};
#[derive(Clone, Debug)]
pub struct Probe {
    pub id: u64,
    pub origin: SocketAddr,
    pub question: Question,
    pub until: u64,
}
#[derive(Default)]
pub struct Browser {
    origins: Vec<SocketAddr>,
    contexts: Vec<Name>,
    active: BTreeMap<u64, Probe>,
    evidence: BTreeMap<(SocketAddr, Name, Name), u64>,
    sequence: u64,
    cursor: usize,
    next: u64,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or excessive browsing-domain evidence",
    )
}
fn owner(context: &Name, legacy: bool) -> io::Result<Name> {
    let mut labels = vec![
        if legacy {
            b"lb".to_vec()
        } else {
            b"b".to_vec()
        },
        b"_dns-sd".to_vec(),
        b"_udp".to_vec(),
    ];
    labels.extend_from_slice(context.labels());
    Name::from_labels(labels)
}
impl Browser {
    pub(crate) fn set_origins(&mut self, origins: &[SocketAddr], now: u64) -> io::Result<()> {
        self.sync(origins, &self.contexts.clone(), now)
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.active.len(), self.evidence.len())
    }
    pub fn sync(&mut self, origins: &[SocketAddr], contexts: &[Name], now: u64) -> io::Result<()> {
        if origins.len() > 8
            || contexts.len() > 64
            || origins
                .iter()
                .any(|o| o.port() == 0 || o.ip().is_unspecified() || o.ip().is_multicast())
            || contexts.iter().any(|n| n.labels().is_empty())
        {
            return Err(invalid());
        }
        for context in contexts {
            owner(context, true)?;
        }
        let mut origins = origins.to_vec();
        origins.sort();
        origins.dedup();
        let mut contexts = contexts.to_vec();
        contexts.sort();
        contexts.dedup();
        if origins != self.origins || contexts != self.contexts {
            self.active.clear();
            self.cursor = 0;
            self.next = now;
            self.evidence.retain(|(source, name, _), until| {
                *until > now
                    && origins.contains(source)
                    && contexts.iter().any(|c| {
                        name == &owner(c, true).unwrap() || name == &owner(c, false).unwrap()
                    })
            });
            self.origins = origins;
            self.contexts = contexts;
        }
        Ok(())
    }
    pub fn next_deadline(&self) -> Option<u64> {
        if self.origins.is_empty() || self.contexts.is_empty() {
            return None;
        }
        self.active
            .values()
            .map(|p| p.until)
            .chain(self.evidence.values().copied())
            .chain((self.active.len() < 8).then_some(self.next))
            .min()
    }
    pub fn live(&self, id: u64, now: u64) -> bool {
        self.active.get(&id).is_some_and(|p| p.until > now)
    }
    pub fn poll(&mut self, now: u64) -> io::Result<Vec<Probe>> {
        self.active.retain(|_, p| p.until > now);
        self.evidence.retain(|_, until| *until > now);
        let total = self.origins.len() * self.contexts.len() * 2;
        if total == 0 || (self.cursor == 0 && now < self.next) {
            return Ok(vec![]);
        }
        if self.cursor == total {
            if now < self.next {
                return Ok(vec![]);
            }
            self.cursor = 0;
        }
        if self.cursor == 0 {
            self.next = now.saturating_add(30000);
        }
        let mut out = vec![];
        while self.active.len() < 8 && self.cursor < total {
            let n = self.cursor;
            let origin = self.origins[n / (self.contexts.len() * 2)];
            let context = &self.contexts[(n / 2) % self.contexts.len()];
            self.sequence = self.sequence.checked_add(1).ok_or_else(invalid)?;
            let p = Probe {
                id: self.sequence,
                origin,
                question: Question {
                    name: owner(context, n % 2 == 0)?,
                    kind: 12,
                    class: 1,
                },
                until: now.saturating_add(3000),
            };
            self.active.insert(p.id, p.clone());
            out.push(p);
            self.cursor += 1;
        }
        // Continue a sweep as soon as a control slot becomes free.
        if self.cursor < total {
            self.next = now;
        } else {
            self.next = self.next.max(now.saturating_add(1000));
        }
        Ok(out)
    }
    pub fn complete(
        &mut self,
        id: u64,
        origin: SocketAddr,
        m: &Message,
        now: u64,
    ) -> io::Result<()> {
        let p = self.active.get(&id).ok_or_else(invalid)?;
        if p.origin != origin
            || p.until <= now
            || m.flags & 0xfa0f != 0x8000
            || m.questions != [p.question.clone()]
            || m.answers.len() + m.authority.len() + m.additional.len() > 64
        {
            return Err(invalid());
        }
        let mut evidence = self.evidence.clone();
        evidence
            .retain(|(o, q, _), until| *until > now && !(*o == origin && *q == p.question.name));
        for r in m.answers.iter().filter(|r| r.name == p.question.name) {
            if r.kind != 12 {
                continue;
            }
            let Rdata::Name(target) = &r.data else {
                return Err(invalid());
            };
            if r.class != 1
                || target.labels().is_empty()
                || within(target, &"local.".parse().unwrap())
                || within(target, &"resolver.arpa.".parse().unwrap())
            {
                return Err(invalid());
            }
            if r.ttl == 0 {
                continue;
            }
            let until = now.saturating_add(u64::from(r.ttl.min(86400)) * 1000);
            let key = (origin, p.question.name.clone(), target.clone());
            evidence
                .entry(key)
                .and_modify(|old| *old = (*old).min(until))
                .or_insert(until);
            if evidence.len() > 64 {
                return Err(invalid());
            }
        }
        if let Some(until) = evidence.values().min() {
            self.next = self
                .next
                .min(now.saturating_add((until.saturating_sub(now) / 2).max(1000)));
        }
        self.evidence = evidence;
        self.active.remove(&id);
        Ok(())
    }
    pub fn domains(&self, legacy: bool, now: u64) -> Vec<(Name, u32)> {
        let mut out = BTreeMap::<Name, u32>::new();
        for ((_, owner, target), until) in &self.evidence {
            if *until <= now || legacy && !owner.labels()[0].eq_ignore_ascii_case(b"lb") {
                continue;
            }
            let ttl = ((until - now) / 1000) as u32;
            if ttl == 0 {
                continue;
            }
            out.entry(target.clone())
                .and_modify(|old| *old = (*old).max(ttl))
                .or_insert(ttl);
        }
        out.into_iter().collect()
    }
}
