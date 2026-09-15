//! Bounded multicast questions with explicit transmission feedback.
use super::{
    cache::{matches, same, Cache},
    wire::Datagram,
};
use crate::{
    dns::wire::{Context, Message, Question},
    time::{RandomSource, Time},
};
use std::{collections::BTreeMap, io, net::IpAddr};
struct Active {
    question: Question,
    until: Time,
    next: Time,
    interval: Time,
    sent: bool,
    qu: Option<Time>,
    offered: bool,
    retry: Option<Time>,
    reconfirm: bool,
}
pub struct Batch {
    pub id: u64,
    pub messages: Vec<Message>,
}
pub struct Querier {
    pub cache: Cache,
    questions: BTreeMap<u64, Active>,
    rates: BTreeMap<IpAddr, (Time, u8)>,
    global: (Time, u16),
    next_id: u64,
    up: bool,
}
impl Default for Querier {
    fn default() -> Self {
        Self {
            cache: Cache::default(),
            questions: BTreeMap::new(),
            rates: BTreeMap::new(),
            global: (0, 0),
            next_id: 0,
            up: true,
        }
    }
}
impl Querier {
    pub fn counts(&self) -> (usize, usize) {
        (self.questions.len(), self.rates.len())
    }
    fn reserve(&mut self) {
        self.cache
            .reserve(self.questions.len() * 8192 + self.rates.len() * 256);
    }
    pub fn start(
        &mut self,
        mut question: Question,
        until: Time,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<u64> {
        self.expire(now);
        if self.questions.len() >= 128
            || until <= now
            || question.class & 0x7fff == 0
            || question.kind == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "mDNS question capacity or deadline",
            ));
        }
        question.class &= 0x7fff;
        let next = now.saturating_add(20 + rng.sample(100)?);
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("mDNS query ID exhausted"))?;
        self.questions.insert(
            self.next_id,
            Active {
                question,
                until,
                next,
                interval: 1000,
                sent: false,
                qu: None,
                offered: false,
                retry: None,
                reconfirm: false,
            },
        );
        self.reserve();
        Ok(self.next_id)
    }
    pub fn stop(&mut self, id: u64) {
        self.questions.remove(&id);
        self.reserve();
    }
    pub fn reconfirm(
        &mut self,
        question: Question,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<u64> {
        let id = self.start(question.clone(), now.saturating_add(10000), now, rng)?;
        self.questions.get_mut(&id).unwrap().reconfirm = true;
        self.cache.suspect(&question, now);
        Ok(id)
    }
    pub fn available(
        &mut self,
        up: bool,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if self.up != up {
            self.up = up;
            self.cache.clear();
            self.rates.clear();
            self.global = (now, 0);
            for q in self.questions.values_mut() {
                q.sent = false;
                q.qu = None;
                q.offered = false;
                q.retry = None;
                q.interval = 1000;
                q.next = now.saturating_add(20 + rng.sample(100)?);
            }
            self.reserve();
        }
        Ok(())
    }
    fn due(&self, q: &Active, now: Time) -> Option<Time> {
        if let Some(t) = q.retry {
            return Some(t);
        }
        let (unique, refresh) = self.cache.timing(&q.question, now);
        if unique && !q.reconfirm {
            refresh
        } else {
            Some(refresh.map_or(q.next, |r| r.min(q.next)))
        }
    }
    pub fn next_deadline(&self, now: Time) -> Option<Time> {
        self.cache
            .next_deadline()
            .into_iter()
            .chain(self.questions.values().flat_map(|q| {
                [Some(q.until), if self.up { self.due(q, now) } else { None }]
                    .into_iter()
                    .flatten()
            }))
            .min()
    }
    fn expire(&mut self, now: Time) {
        self.questions.retain(|_, q| q.until > now);
        self.rates.retain(|_, r| now.saturating_sub(r.0) < 60000);
        self.cache.expire(now);
        self.reserve();
    }
    pub fn poll(&mut self, now: Time) -> io::Result<Option<Batch>> {
        self.expire(now);
        if !self.up {
            return Ok(None);
        }
        let Some(id) = self
            .questions
            .iter()
            .filter_map(|(id, q)| self.due(q, now).filter(|t| *t <= now).map(|t| (*id, t)))
            .min_by_key(|(id, t)| (*t, *id))
            .map(|(id, _)| id)
        else {
            return Ok(None);
        };
        let q = self.questions.get_mut(&id).unwrap();
        let mut question = q.question.clone();
        if !q.sent {
            question.class |= 0x8000;
        }
        let known = self.cache.known(&q.question, now);
        let mut current = Message::new(0, 0);
        current.questions.push(question);
        let mut messages = vec![];
        for r in known {
            current.answers.push(r);
            let length = current.encode_context(Context::Mdns)?.len();
            if length > 1200 && current.answers.len() > 1 {
                let last = current.answers.pop().unwrap();
                current.flags |= 0x200;
                messages.push(current);
                current = Message::new(0, 0);
                current.answers.push(last);
            }
            if current.encode_context(Context::Mdns)?.len() > 8952 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mDNS known answer exceeds IP limit",
                ));
            }
        }
        messages.push(current);
        q.offered = true;
        Ok(Some(Batch { id, messages }))
    }
    pub fn sent(&mut self, id: u64, success: bool, now: Time) {
        if let Some(q) = self.questions.get_mut(&id).filter(|q| q.offered) {
            q.offered = false;
            if !success {
                q.retry = Some(now.saturating_add(100));
                return;
            }
            if !q.sent {
                q.qu = Some(now);
            }
            advance(q, now);
            self.cache.refreshed(&q.question, now);
        }
    }
    fn admit(&mut self, source: IpAddr, now: Time) -> bool {
        if now.saturating_sub(self.global.0) >= 1000 {
            self.global = (now, 0);
        }
        if self.global.1 >= 128 {
            return false;
        }
        self.global.1 += 1;
        if !self.rates.contains_key(&source) && self.rates.len() >= 32 {
            let oldest = *self.rates.iter().min_by_key(|(_, r)| r.0).unwrap().0;
            self.rates.remove(&oldest);
        }
        let r = self.rates.entry(source).or_insert((now, 0));
        if now.saturating_sub(r.0) >= 1000 {
            *r = (now, 0);
        }
        if r.1 >= 32 {
            return false;
        }
        r.1 += 1;
        self.reserve();
        true
    }
    pub fn receive(
        &mut self,
        d: &Datagram,
        on_link: bool,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<bool> {
        if !self.up || d.destination.port() != 5353 || !self.admit(d.source.ip(), now) {
            return Ok(false);
        }
        let m = &d.message;
        if m.flags & 0x8000 != 0 {
            if !d.destination.ip().is_multicast()
                && (!on_link
                    || !self.questions.values().any(|q| {
                        q.qu.is_some_and(|t| now >= t && now - t <= 2000)
                            && q.until > now
                            && m.answers
                                .iter()
                                .chain(&m.additional)
                                .any(|r| matches(&q.question, r))
                    }))
            {
                return Ok(false);
            }
            self.cache.receive(m, now, rng)?;
        } else if d.destination.ip().is_multicast() && d.source.port() == 5353 {
            for question in &m.questions {
                self.cache.observe_question(question, &m.answers, now);
                if question.class & 0x8000 != 0 || m.flags & 0x200 != 0 {
                    continue;
                }
                let own = self.cache.known(question, now);
                if m.answers.iter().all(|r| own.iter().any(|o| same(r, o))) {
                    for q in self
                        .questions
                        .values_mut()
                        .filter(|q| q.question == *question && q.until > now)
                    {
                        advance(q, now);
                    }
                    self.cache.refreshed(question, now);
                }
            }
        }
        Ok(true)
    }
}
fn advance(q: &mut Active, now: Time) {
    q.next = now.saturating_add(q.interval);
    q.interval = q.interval.saturating_mul(2).min(3600000);
    q.sent = true;
    q.offered = false;
    q.retry = None;
}
