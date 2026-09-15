//! Publication state holds identities and timers; records are projected by their owner.
use super::{
    cache::{cacheable, matches, same},
    wire::Datagram,
};
use crate::{
    dns::wire::{Context, Message, Name, Question, Rdata, Record},
    time::{RandomSource, Time},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
};
const BYTES: usize = 4 * 1024 * 1024;
pub(crate) type Digest = [u8; 32];
type Names = BTreeSet<(Name, u16)>;
#[derive(Clone, Copy)]
enum State {
    Probe { sent: u8, next: Time },
    Announce { sent: u8, next: Time },
    Ready,
    Failed { until: Time, notice: bool },
}
impl State {
    fn next(self) -> Option<Time> {
        match self {
            Self::Probe { next, .. } | Self::Announce { next, .. } => Some(next),
            _ => None,
        }
    }
    fn ready(self) -> bool {
        matches!(self, Self::Ready | Self::Announce { sent: 1.., .. })
    }
}
struct Publication {
    digest: Digest,
    names: Names,
    count: usize,
    charge: usize,
    state: State,
    history: BTreeMap<Digest, Time>,
}
struct Goodbye {
    records: Vec<Record>,
    charge: usize,
    next: Time,
}
enum Offered {
    Publication {
        id: u64,
        probe: bool,
        records: Vec<Digest>,
    },
    Goodbye,
}
pub struct Outbound {
    pub token: u64,
    pub messages: Vec<Message>,
}
pub struct Publisher {
    publications: BTreeMap<u64, Publication>,
    goodbyes: VecDeque<Goodbye>,
    offered: Option<(u64, Offered)>,
    next_token: u64,
    up: bool,
}
impl Default for Publisher {
    fn default() -> Self {
        Self {
            publications: BTreeMap::new(),
            goodbyes: VecDeque::new(),
            offered: None,
            next_token: 0,
            up: true,
        }
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid mDNS publication or stale projection",
    )
}
fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "mDNS publication capacity")
}
struct Prepared {
    records: Vec<Record>,
    digest: Digest,
    names: Names,
    charge: usize,
}
impl Prepared {
    fn new(input: &[Record]) -> io::Result<Self> {
        if input.len() > 4096 {
            return Err(capacity());
        }
        let mut records = vec![];
        let mut names = Names::new();
        let mut charge = 0;
        for r in input {
            if !cacheable(r) || r.ttl == 0 {
                return Err(invalid());
            }
            charge += record_charge(r)?;
            if charge > BYTES {
                return Err(capacity());
            }
            if r.class & 0x8000 != 0 {
                names.insert((r.name.clone(), r.class & 0x7fff));
            }
            records.push(r.clone());
        }
        for (name, class) in &names {
            if records
                .iter()
                .any(|r| r.name == *name && r.class & 0x7fff == *class && r.kind == 47)
            {
                continue;
            }
            let own: Vec<_> = records
                .iter()
                .filter(|r| r.name == *name && r.class & 0x7fff == *class)
                .collect();
            let mut blocks: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
            for kind in own.iter().map(|r| r.kind).chain([47]) {
                let b = blocks.entry((kind / 256) as u8).or_default();
                let at = usize::from(kind % 256 / 8);
                b.resize(b.len().max(at + 1), 0);
                b[at] |= 0x80 >> (kind % 8);
            }
            let mut bitmap = vec![];
            for (window, b) in blocks {
                bitmap.extend([window, b.len() as u8]);
                bitmap.extend(b);
            }
            let r = Record {
                name: name.clone(),
                kind: 47,
                class: class | 0x8000,
                ttl: own.iter().map(|r| r.ttl).min().unwrap_or(120),
                data: Rdata::Nsec {
                    next: name.clone(),
                    bitmap,
                },
            };
            charge += record_charge(&r)?;
            if records.len() == 4096 || charge > BYTES {
                return Err(capacity());
            }
            records.push(r);
        }
        let mut encoded = records
            .iter()
            .map(identity)
            .collect::<io::Result<Vec<_>>>()?;
        encoded.sort();
        encoded.dedup();
        let digest = crate::srp::wire::fingerprint(&encoded.concat());
        Ok(Self {
            records,
            names,
            digest,
            charge,
        })
    }
}
pub(crate) fn identity(r: &Record) -> io::Result<Digest> {
    let mut r = r.clone();
    r.ttl = 0;
    r.class &= 0x7fff;
    fn canon(n: &mut Name) {
        *n = Name::from_labels(
            n.labels()
                .iter()
                .map(|l| l.iter().map(u8::to_ascii_lowercase).collect())
                .collect(),
        )
        .unwrap();
    }
    canon(&mut r.name);
    match &mut r.data {
        Rdata::Name(n)
        | Rdata::Srv { target: n, .. }
        | Rdata::Preference { name: n, .. }
        | Rdata::Nsec { next: n, .. }
        | Rdata::Sig { signer: n, .. }
        | Rdata::Svcb { target: n, .. } => canon(n),
        Rdata::TwoNames { first, second } => {
            canon(first);
            canon(second);
        }
        Rdata::Px {
            map822, mapx400, ..
        } => {
            canon(map822);
            canon(mapx400);
        }
        Rdata::Soa { mname, rname, .. } => {
            canon(mname);
            canon(rname);
        }
        _ => {}
    }
    let mut m = Message::new(0, 0);
    m.answers.push(r);
    Ok(crate::srp::wire::fingerprint(&m.encode()?))
}
fn record_charge(r: &Record) -> io::Result<usize> {
    let mut m = Message::new(0, 0x8400);
    m.answers.push(r.clone());
    let n = m.encode()?.len();
    if m.encode_context(Context::Mdns)?.len() > 8952 {
        return Err(invalid());
    }
    // Includes the projected record, output work copy, and per-record sent digest.
    Ok(256 + n * 8)
}
impl Publisher {
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.publications.len(),
            self.publications.values().map(|p| p.count).sum(),
            self.publications.values().map(|p| p.charge).sum::<usize>()
                + self.goodbyes.iter().map(|g| g.charge).sum::<usize>(),
        )
    }
    pub fn ready(&self, id: u64) -> bool {
        self.up && self.publications.get(&id).is_some_and(|p| p.state.ready())
    }
    pub fn replace(
        &mut self,
        id: u64,
        old: &[Record],
        new: &[Record],
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let old = Prepared::new(old)?;
        let new = Prepared::new(new)?;
        let existing = self.publications.get(&id);
        if existing.is_some_and(|p| p.digest != old.digest)
            || (existing.is_none() && !old.records.is_empty())
        {
            return Err(invalid());
        }
        let (mut count, mut records, mut bytes) = self.counts();
        if let Some(p) = existing {
            count -= 1;
            records -= p.count;
            bytes -= p.charge;
        }
        let mut goodbyes = vec![];
        if self.up && existing.is_some_and(|p| p.state.ready()) {
            for r in &old.records {
                if !new.records.iter().any(|n| same(n, r))
                    && (r.class & 0x8000 == 0
                        || !new.names.contains(&(r.name.clone(), r.class & 0x7fff)))
                {
                    let mut r = r.clone();
                    r.ttl = 0;
                    goodbyes.push(r);
                }
            }
        }
        let goodbye_charge = goodbyes
            .iter()
            .map(record_charge)
            .collect::<io::Result<Vec<_>>>()?
            .iter()
            .sum::<usize>();
        if count + usize::from(!new.records.is_empty()) > 128
            || records + new.records.len() > 4096
            || bytes + new.charge + goodbye_charge > BYTES
            || (!goodbyes.is_empty() && self.goodbyes.len() >= 128)
        {
            return Err(capacity());
        }
        if existing.is_some_and(|p| p.digest == new.digest) {
            return Ok(());
        }
        let state = match existing {
            Some(p) if p.state.ready() && p.names == new.names => {
                State::Announce { sent: 0, next: now }
            }
            Some(Publication {
                state: State::Failed { until, .. },
                ..
            }) => State::Probe {
                sent: 0,
                next: now.saturating_add(rng.sample(250)?).max(*until),
            },
            _ if new.names.is_empty() => State::Announce { sent: 0, next: now },
            _ => State::Probe {
                sent: 0,
                next: now.saturating_add(rng.sample(250)?),
            },
        };
        let history = self
            .publications
            .remove(&id)
            .map(|p| p.history)
            .unwrap_or_default()
            .into_iter()
            .filter(|(h, _)| {
                new.records
                    .iter()
                    .any(|r| identity(r).ok().as_ref() == Some(h))
            })
            .collect();
        if !new.records.is_empty() {
            self.publications.insert(
                id,
                Publication {
                    digest: new.digest,
                    names: new.names,
                    count: new.records.len(),
                    charge: new.charge,
                    state,
                    history,
                },
            );
        }
        if !goodbyes.is_empty() {
            self.goodbyes.push_back(Goodbye {
                records: goodbyes,
                charge: goodbye_charge,
                next: now,
            });
        }
        self.offered = None;
        Ok(())
    }
    pub fn available(
        &mut self,
        up: bool,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if self.up != up {
            self.up = up;
            self.offered = None;
            self.goodbyes.clear();
            for p in self.publications.values_mut() {
                p.history.clear();
                p.state = if p.names.is_empty() {
                    State::Announce { sent: 0, next: now }
                } else {
                    State::Probe {
                        sent: 0,
                        next: now.saturating_add(rng.sample(250)?),
                    }
                };
            }
        }
        Ok(())
    }
    pub fn next_deadline(&self) -> Option<Time> {
        if !self.up {
            return None;
        }
        self.publications
            .values()
            .filter_map(|p| p.state.next())
            .chain(self.goodbyes.front().map(|g| g.next))
            .min()
    }
    pub fn poll(
        &mut self,
        source: &impl Fn(u64, Time) -> Vec<Record>,
        now: Time,
    ) -> io::Result<Option<Outbound>> {
        if !self.up {
            return Ok(None);
        }
        let (messages, offered) = if let Some(g) = self.goodbyes.front().filter(|g| g.next <= now) {
            (pack(&g.records, false)?, Offered::Goodbye)
        } else {
            let Some((&id, p)) = self
                .publications
                .iter()
                .filter(|(_, p)| p.state.next().is_some_and(|t| t <= now))
                .min_by_key(|(id, p)| (p.state.next(), *id))
            else {
                return Ok(None);
            };
            let data = Prepared::new(&source(id, now))?;
            if data.digest != p.digest {
                return Err(invalid());
            }
            let probe = matches!(p.state, State::Probe { sent: 0..=2, .. });
            let records: Vec<_> = data
                .records
                .into_iter()
                .filter(|r| !probe || r.class & 0x8000 != 0)
                .collect();
            let ids = records.iter().map(identity).collect::<io::Result<_>>()?;
            (
                pack(&records, probe)?,
                Offered::Publication {
                    id,
                    probe,
                    records: ids,
                },
            )
        };
        self.next_token = self.next_token.checked_add(1).ok_or_else(capacity)?;
        self.offered = Some((self.next_token, offered));
        Ok(Some(Outbound {
            token: self.next_token,
            messages,
        }))
    }
    pub fn sent(&mut self, token: u64, success: bool, now: Time) {
        if !self.offered.as_ref().is_some_and(|(t, _)| *t == token) {
            return;
        }
        match self.offered.take().unwrap().1 {
            Offered::Goodbye => {
                if success {
                    self.goodbyes.pop_front();
                } else if let Some(g) = self.goodbyes.front_mut() {
                    g.next = now.saturating_add(100);
                }
            }
            Offered::Publication { id, probe, records } => {
                if let Some(p) = self.publications.get_mut(&id) {
                    if !success {
                        match &mut p.state {
                            State::Probe { next, .. } | State::Announce { next, .. } => {
                                *next = now.saturating_add(100)
                            }
                            _ => {}
                        }
                        return;
                    }
                    if probe {
                        if let State::Probe { sent, .. } = p.state {
                            p.state = State::Probe {
                                sent: sent + 1,
                                next: now.saturating_add(250),
                            };
                        }
                    } else {
                        for r in records {
                            p.history.insert(r, now);
                        }
                        p.state = if matches!(p.state, State::Announce { sent: 1, .. }) {
                            State::Ready
                        } else {
                            State::Announce {
                                sent: 1,
                                next: now.saturating_add(1000),
                            }
                        };
                    }
                }
            }
        }
    }
    pub(crate) fn all_ready(
        &self,
        source: &impl Fn(u64, Time) -> Vec<Record>,
        now: Time,
    ) -> io::Result<Vec<(u64, Record)>> {
        let mut out = vec![];
        if !self.up {
            return Ok(out);
        }
        for (id, p) in &self.publications {
            if !p.state.ready() {
                continue;
            }
            let data = Prepared::new(&source(*id, now))?;
            if data.digest != p.digest {
                return Err(invalid());
            }
            out.extend(data.records.into_iter().map(|r| (*id, r)));
        }
        Ok(out)
    }
    pub(crate) fn last(&self, id: u64, record: &Digest) -> Option<Time> {
        self.publications.get(&id)?.history.get(record).copied()
    }
    pub(crate) fn note(&mut self, records: &[(u64, Digest)], now: Time) {
        for (id, record) in records {
            if let Some(p) = self.publications.get_mut(id) {
                if p.history.contains_key(record) || p.history.len() < p.count {
                    p.history.insert(*record, now);
                }
            }
        }
    }
    pub fn take_conflict(&mut self) -> Option<u64> {
        for (id, p) in &mut self.publications {
            if let State::Failed { notice, .. } = &mut p.state {
                if *notice {
                    *notice = false;
                    return Some(*id);
                }
            }
        }
        None
    }
    pub fn receive(
        &mut self,
        d: &Datagram,
        source: &impl Fn(u64, Time) -> Vec<Record>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if !self.up {
            return Ok(());
        }
        for (id, p) in &mut self.publications {
            let probing = matches!(p.state, State::Probe { sent: 1.., .. });
            if !probing && !p.state.ready() {
                continue;
            }
            let data = Prepared::new(&source(*id, now))?;
            if data.digest != p.digest {
                return Err(invalid());
            }
            if d.message.flags & 0x8000 != 0 {
                let conflict = d
                    .message
                    .answers
                    .iter()
                    .chain(&d.message.authority)
                    .chain(&d.message.additional)
                    .filter(|r| r.ttl > 0 && cacheable(r))
                    .any(|r| {
                        p.names.contains(&(r.name.clone(), r.class & 0x7fff))
                            && !data.records.iter().any(|own| same(own, r))
                            && (probing
                                || data.records.iter().any(|own| {
                                    own.name == r.name
                                        && own.kind == r.kind
                                        && own.class & 0x7fff == r.class & 0x7fff
                                }))
                    });
                if conflict {
                    p.state = if probing {
                        State::Failed {
                            until: now.saturating_add(5000),
                            notice: true,
                        }
                    } else {
                        State::Probe {
                            sent: 0,
                            next: now.saturating_add(rng.sample(250)?),
                        }
                    };
                    self.offered = None;
                }
            } else if probing {
                for q in &d.message.questions {
                    if !p.names.contains(&(q.name.clone(), q.class & 0x7fff)) {
                        continue;
                    }
                    let theirs: Vec<_> = d
                        .message
                        .authority
                        .iter()
                        .filter(|r| matches(q, r))
                        .collect();
                    if theirs.is_empty() {
                        continue;
                    }
                    let ours: Vec<_> = data.records.iter().filter(|r| matches(q, r)).collect();
                    if tie(&ours)? < tie(&theirs)? {
                        p.state = State::Probe {
                            sent: 0,
                            next: now.saturating_add(1000),
                        };
                        self.offered = None;
                        break;
                    }
                }
            }
        }
        Ok(())
    }
}
fn tie(rrs: &[&Record]) -> io::Result<Vec<Vec<u8>>> {
    let mut out = vec![];
    for r in rrs {
        let mut m = Message::new(0, 0);
        m.answers.push((*r).clone());
        let bytes = m.encode()?;
        let m = Message::parse(&bytes, Context::Mdns)?;
        let mut key = (r.class & 0x7fff).to_be_bytes().to_vec();
        key.extend(r.kind.to_be_bytes());
        key.extend(&bytes[m.record_spans()[0].rdata.clone()]);
        out.push(key);
    }
    out.sort();
    out.dedup();
    Ok(out)
}
pub(crate) fn pack(records: &[Record], probe: bool) -> io::Result<Vec<Message>> {
    let mut out = vec![];
    let mut current = Message::new(0, if probe { 0 } else { 0x8400 });
    for r in records {
        let mut r = r.clone();
        if probe {
            r.class &= 0x7fff;
        }
        let before = current.clone();
        append(&mut current, r.clone(), probe);
        if current.encode_context(Context::Mdns)?.len() > 1200
            && before.answers.len() + before.authority.len() > 0
        {
            out.push(before);
            current = Message::new(0, if probe { 0 } else { 0x8400 });
            append(&mut current, r, probe);
        }
        if current.encode_context(Context::Mdns)?.len() > 8952 || current.questions.len() > 128 {
            return Err(invalid());
        }
    }
    if !current.answers.is_empty() || !current.authority.is_empty() {
        out.push(current);
    }
    Ok(out)
}
fn append(m: &mut Message, r: Record, probe: bool) {
    if probe {
        let q = Question {
            name: r.name.clone(),
            kind: 255,
            class: r.class | 0x8000,
        };
        if !m.questions.contains(&q) {
            m.questions.push(q);
        }
        m.authority.push(r);
    } else {
        m.answers.push(r);
    }
}
