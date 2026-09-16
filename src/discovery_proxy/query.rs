use super::{invalid, usable, Reachability, TranslatedQuestion, Zone};
use crate::{
    dns::wire::{Context, Message, Question, Rdata, Record},
    mdns::{
        cache::{charge, matches, same, Cache},
        query::Querier,
    },
    time::{RandomSource, Time},
};
use std::{collections::BTreeMap, io};
struct Job {
    query: TranslatedQuestion,
    until: Time,
    multicast: Option<u64>,
    cancelled: bool,
    bytes: usize,
}
pub struct Completion {
    pub id: u64,
    pub answer: Message,
}
pub struct Proxy {
    zone: Zone,
    reachability: Reachability,
    jobs: BTreeMap<u64, Job>,
    sequence: u64,
    again: bool,
}
fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "Discovery Proxy query capacity")
}
impl Proxy {
    pub fn new(zone: Zone) -> Self {
        Self {
            zone,
            reachability: Reachability::default(),
            jobs: BTreeMap::new(),
            sequence: 0,
            again: false,
        }
    }
    pub fn set_reachability(&mut self, reachability: Reachability) {
        self.reachability = reachability;
    }
    pub fn counts(&self) -> (usize, usize) {
        (self.jobs.len(), self.jobs.values().map(|j| j.bytes).sum())
    }
    pub fn start(&mut self, question: Question, now: Time) -> io::Result<u64> {
        let query = self.zone.question(&question)?.ok_or_else(invalid)?;
        if let Some((id, _)) = self
            .jobs
            .iter()
            .find(|(_, j)| !j.cancelled && j.until > now && j.query.original == question)
        {
            return Ok(*id);
        }
        let bytes = 2048
            + [&query.original.name, &query.multicast.name]
                .iter()
                .map(|n| n.canonical().len() * 4 + n.labels().len() * 128)
                .sum::<usize>();
        if self.jobs.len() == 128 || self.counts().1 + bytes > 4 * 1024 * 1024 {
            return Err(capacity());
        }
        self.sequence = self.sequence.checked_add(1).ok_or_else(capacity)?;
        self.jobs.insert(
            self.sequence,
            Job {
                query,
                until: now.saturating_add(6000),
                multicast: None,
                cancelled: false,
                bytes,
            },
        );
        Ok(self.sequence)
    }
    pub fn cancel(&mut self, id: u64) {
        if let Some(j) = self.jobs.get_mut(&id) {
            j.cancelled = true;
        }
    }
    pub fn next_deadline(&self, now: Time) -> Option<Time> {
        self.jobs
            .values()
            .map(|j| {
                if j.cancelled || j.multicast.is_none() || self.again {
                    now
                } else {
                    j.until
                }
            })
            .min()
    }
    pub fn poll(
        &mut self,
        querier: &mut Querier,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Completion>> {
        self.poll_with_local(querier, &|_| vec![], now, rng)
    }
    pub fn poll_with_local(
        &mut self,
        querier: &mut Querier,
        local: &impl Fn(&Question) -> Vec<Record>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Completion>> {
        self.again = false;
        let ids: Vec<_> = self.jobs.keys().copied().collect();
        let mut out = vec![];
        let mut bytes = 0;
        for id in ids {
            if out.len() == 16 {
                self.again = true;
                break;
            }
            let mut job = self.jobs.remove(&id).unwrap();
            if job.cancelled {
                if let Some(q) = job.multicast {
                    querier.stop(q);
                }
                continue;
            }
            let mut answer =
                self.answer(&job.query, &mut querier.cache, local, now, now >= job.until)?;
            if answer.is_none() && job.multicast.is_none() {
                match querier.start(job.query.multicast.clone(), job.until, now, rng) {
                    Ok(id) => job.multicast = Some(id),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        let mut m = Message::new(0, 0x8402);
                        m.questions.push(job.query.original.clone());
                        answer = Some(m);
                    }
                    Err(e) => {
                        self.jobs.insert(id, job);
                        return Err(e);
                    }
                }
            }
            if let Some(mut answer) = answer {
                bound_answer(&mut answer)?;
                let cost = answer_cost(&answer);
                if bytes + cost > 4 * 1024 * 1024 && !out.is_empty() {
                    self.jobs.insert(id, job);
                    self.again = true;
                    break;
                }
                bytes += cost;
                if let Some(q) = job.multicast {
                    querier.stop(q);
                }
                out.push(Completion { id, answer });
            } else {
                self.jobs.insert(id, job);
            }
        }
        Ok(out)
    }
    fn answer(
        &self,
        q: &TranslatedQuestion,
        cache: &mut Cache,
        local: &impl Fn(&Question) -> Vec<Record>,
        now: Time,
        timeout: bool,
    ) -> io::Result<Option<Message>> {
        if let Some(m) = self.zone.metadata(&q.original)? {
            return Ok(Some(m));
        }
        let negative = cache.negative(&q.multicast, now);
        let mut lookup = |q: &Question| {
            let mut out = cache.answers(q, now);
            for r in local(q) {
                if !out.iter().any(|old| same(old, &r)) {
                    out.push(r);
                }
            }
            out
        };
        let raw = lookup(&q.multicast);
        if raw.is_empty() && !negative && !timeout {
            return Ok(None);
        }
        let mut m = Message::new(0, 0x8400);
        m.questions.push(q.original.clone());
        if matches!(q.original.kind, 47 | 50) {
            m.answers
                .push(self.zone.denial(q, &raw, &self.reachability)?);
            return Ok(Some(m));
        }
        let mut records: Vec<(Record, bool)> = vec![];
        for r in raw
            .iter()
            .filter(|r| r.kind != 47 && matches(&q.multicast, r))
        {
            if self.service_usable(r, &mut lookup) {
                if records.len() == 512 {
                    m.flags |= 0x200;
                    break;
                }
                records.push((r.clone(), false));
            }
        }
        let mut cursor = 0;
        while cursor < records.len() {
            let r = records[cursor].0.clone();
            cursor += 1;
            let queries = match &r.data {
                Rdata::Name(n) if r.kind == 12 && !matches!(q.scope, super::Scope::Reverse(_)) => {
                    vec![(n.clone(), 33), (n.clone(), 16)]
                }
                Rdata::Srv { target, .. } => vec![(target.clone(), 1), (target.clone(), 28)],
                Rdata::Name(n) if r.kind == 5 && records[cursor - 1].1 => {
                    vec![(n.clone(), 1), (n.clone(), 28)]
                }
                _ => vec![],
            };
            for (name, kind) in queries {
                for extra in lookup(&Question {
                    name,
                    kind,
                    class: 1,
                })
                .into_iter()
                .filter(|r| r.kind != 47)
                {
                    if records.iter().any(|(r, _)| same(r, &extra))
                        || !self.service_usable(&extra, &mut lookup)
                    {
                        continue;
                    }
                    if records.len() == 512 {
                        m.flags |= 0x200;
                        break;
                    }
                    records.push((extra, true));
                }
            }
        }
        for (r, additional) in records {
            if let Some(r) = self.zone.rewrite(&r, q, additional, &self.reachability)? {
                if additional {
                    m.additional.push(r);
                } else {
                    m.answers.push(r);
                }
            }
        }
        if m.answers.is_empty() {
            m.additional.clear();
            m.authority.push(self.zone.soa(q.scope)?);
        }
        Ok(Some(m))
    }
    fn service_usable(
        &self,
        r: &Record,
        lookup: &mut impl FnMut(&Question) -> Vec<Record>,
    ) -> bool {
        if self.reachability.include_unusable {
            return true;
        }
        if let Rdata::Srv { target, .. } = &r.data {
            return self.host_usable(target, lookup);
        }
        if let Rdata::Name(target) = &r.data {
            if r.kind == 12 {
                let records: Vec<_> = lookup(&Question {
                    name: target.clone(),
                    kind: 33,
                    class: 1,
                })
                .into_iter()
                .filter(|r| r.kind == 33)
                .collect();
                return records.is_empty()
                    || records.iter().any(|r| {
                        if let Rdata::Srv { target, .. } = &r.data {
                            self.host_usable(target, lookup)
                        } else {
                            true
                        }
                    });
            }
        }
        true
    }
    fn host_usable(
        &self,
        name: &crate::dns::wire::Name,
        lookup: &mut impl FnMut(&Question) -> Vec<Record>,
    ) -> bool {
        if name.labels().is_empty() {
            return false;
        }
        let mut any = false;
        for kind in [1, 28] {
            for r in lookup(&Question {
                name: name.clone(),
                kind,
                class: 1,
            })
            .iter()
            .filter(|r| matches!(r.kind, 1 | 28))
            {
                any = true;
                if usable(r, &self.reachability) {
                    return true;
                }
            }
        }
        !any
    }
}
fn answer_cost(m: &Message) -> usize {
    m.answers
        .iter()
        .chain(&m.authority)
        .chain(&m.additional)
        .fold(4096usize, |n, r| {
            n.saturating_add(charge(r).unwrap_or(4 * 1024 * 1024))
        })
}
fn bound_answer(m: &mut Message) -> io::Result<()> {
    loop {
        if answer_cost(m) <= 4 * 1024 * 1024
            && m.encode_context(Context::Unicast)
                .is_ok_and(|b| b.len() <= 65535)
        {
            return Ok(());
        }
        m.flags |= 0x200;
        if m.additional
            .pop()
            .or_else(|| m.answers.pop())
            .or_else(|| m.authority.pop())
            .is_none()
        {
            return Err(invalid());
        }
    }
}
