//! Bounded forwarding transactions. Packet and stream adapters execute the returned actions.
mod discovery;
use super::wire::{Context, Message, Name, Question, Rdata, Record};
use crate::{
    srp::wire::{CryptoBudget, Error as SrpError, Update, Validator},
    time::RandomSource,
};
use discovery::Discovered;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, SocketAddr},
};
const PENDING: usize = 128;
const WAITERS: usize = 256;
const CACHE_SETS: usize = 1024;
const BYTES: usize = 4 * 1024 * 1024;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS request")
}
fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "DNS capacity")
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Client {
    pub address: SocketAddr,
    pub connection: Option<usize>,
    pub local: Option<IpAddr>,
}
impl Client {
    pub fn udp(address: SocketAddr) -> Self {
        Self {
            address,
            connection: None,
            local: None,
        }
    }
    pub fn tcp(address: SocketAddr, connection: usize) -> Self {
        Self {
            address,
            connection: Some(connection),
            local: None,
        }
    }
}
#[derive(Clone, Debug)]
pub struct UpstreamQuery {
    pub exchange: u64,
    pub server: SocketAddr,
    pub source_port: u16,
    pub tcp: bool,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug)]
pub enum Action {
    Upstream(UpstreamQuery),
    Register { client: Client, update: Update },
    Reply { client: Client, bytes: Vec<u8> },
}
struct Waiter {
    client: Client,
    id: u16,
    limit: usize,
}
struct Pending {
    key: Vec<u8>,
    original: Message,
    query: UpstreamQuery,
    question: Question,
    waiters: Vec<Waiter>,
    deadline: u64,
    retry: u64,
    attempt: u8,
    base: Option<Vec<u8>>,
    forward_cache: bool,
    aliases: BTreeSet<Name>,
}
impl Pending {
    fn charge(&self) -> usize {
        1024 + self.key.len()
            + 16 * self.original.original().len()
            + 16 * self.query.bytes.len()
            + 16 * self.base.as_ref().map_or(0, Vec::len)
            + alias_charge(&self.aliases)
            + 1024 * self.waiters.len()
    }
}
struct Cache {
    wire: Vec<u8>,
    inserted: u64,
    expires: u64,
    last: u64,
    sets: usize,
}
pub struct Resolver {
    additional_a: bool,
    zones: Option<super::inventory::Zones>,
    inventory: Option<super::inventory::Inventory>,
    local_zones: Vec<Name>,
    upstreams: Vec<SocketAddr>,
    pending: BTreeMap<u64, Pending>,
    discovered: BTreeMap<u64, Discovered>,
    discovery: Option<crate::discovery_proxy::Proxy>,
    cache: BTreeMap<Vec<u8>, Cache>,
    next: u64,
    rates: BTreeMap<IpAddr, (u64, u8)>,
    srp_clock: (u64, u64),
    crypto: CryptoBudget,
    srp_validator: Validator,
    registrar: Option<crate::srp::service::Registrar>,
    srp_sources: Vec<crate::wire::Prefix>,
}
impl Resolver {
    pub fn new(additional_a: bool) -> Self {
        Self {
            additional_a,
            zones: None,
            inventory: None,
            local_zones: vec![],
            upstreams: vec![],
            pending: BTreeMap::new(),
            discovered: BTreeMap::new(),
            discovery: None,
            cache: BTreeMap::new(),
            next: 0,
            rates: BTreeMap::new(),
            srp_clock: (0, 0),
            crypto: CryptoBudget::default(),
            srp_validator: Validator::new(&[]).unwrap(),
            registrar: None,
            srp_sources: vec![],
        }
    }
    pub fn configure_zones(&mut self, zones: super::inventory::Zones) -> io::Result<()> {
        if self.registrar.is_some()
            || self.pending_count() != 0
            || self.discovery.as_ref().is_some_and(|d| d.counts().0 != 0)
        {
            return Err(io::Error::other("cannot change active DNS namespaces"));
        }
        let inventory = super::inventory::Inventory::new(zones.clone())?;
        let proxy = zones.proxy()?;
        let validator =
            Validator::new(std::slice::from_ref(&zones.registrar)).map_err(|_| invalid())?;
        self.set_local_zones(&[zones.registrar.clone(), zones.hostname.clone()])?;
        self.discovery = Some(crate::discovery_proxy::Proxy::new(proxy));
        self.srp_validator = validator;
        self.inventory = Some(inventory);
        self.zones = Some(zones);
        Ok(())
    }
    pub fn set_service_ready(
        &mut self,
        addresses: &[IpAddr],
        dns: Option<u16>,
        tls: Option<u16>,
    ) -> io::Result<()> {
        if let Some(i) = &mut self.inventory {
            let registered = self.registrar.is_some();
            i.set_ready(
                addresses,
                dns.filter(|_| registered),
                tls.filter(|_| registered),
            )?;
        }
        Ok(())
    }
    pub fn set_inventory_contexts(&mut self, contexts: &[Name]) -> io::Result<()> {
        if let Some(i) = &mut self.inventory {
            i.set_contexts(contexts)?;
        }
        Ok(())
    }
    pub fn zones(&self) -> Option<&super::inventory::Zones> {
        self.zones.as_ref()
    }
    pub fn enable_srp(
        &mut self,
        store: Box<dyn crate::persist::StateStore>,
        now: u64,
        wall: u64,
    ) -> io::Result<()> {
        if self.registrar.is_some() {
            return Err(io::Error::other("SRP registrar already owns a store"));
        }
        let mut registrar = crate::srp::service::Registrar::open(store, now, wall)?;
        if let Some(zones) = &self.zones {
            registrar.set_zone(zones.registrar.clone())?;
        }
        self.registrar = Some(registrar);
        self.set_srp_clock(wall, now);
        self.cache.clear();
        Ok(())
    }
    pub fn advertised(&self, id: u64, now: u64) -> Vec<Record> {
        self.registrar
            .as_ref()
            .map(|r| r.advertised(id, now))
            .unwrap_or_default()
    }
    pub fn sync_advertising(
        &mut self,
        engine: &mut crate::mdns::Engine,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        if let Some(r) = &mut self.registrar {
            r.sync_advertising(engine, now, rng)?;
        }
        Ok(())
    }
    pub fn registry(&self) -> Option<&crate::srp::registry::Registry> {
        self.registrar.as_ref().map(|r| &r.registry)
    }
    pub fn set_srp_policy(&mut self, policy: crate::srp::registry::LeasePolicy) -> io::Result<()> {
        self.registrar
            .as_mut()
            .ok_or_else(|| io::Error::other("SRP is not enabled"))?
            .registry
            .set_policy(policy)
    }
    pub fn take_srp_changed(&mut self) -> bool {
        self.registrar.as_mut().is_some_and(|r| r.take_changed())
    }
    pub fn set_srp_sources(&mut self, prefixes: &[crate::wire::Prefix]) -> io::Result<()> {
        if prefixes.len() > 64 || prefixes.iter().any(|p| p.length != 64 || !p.routable()) {
            return Err(invalid());
        }
        self.srp_sources = prefixes.to_vec();
        Ok(())
    }
    fn srp_source(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V6(a) => {
                crate::wire::link_local(a)
                    || a.is_loopback()
                    || self.srp_sources.iter().any(|p| p.contains(a))
            }
            IpAddr::V4(a) => a.is_loopback(),
        }
    }
    pub fn set_srp_clock(&mut self, wall: u64, monotonic: u64) {
        self.srp_clock = (wall, monotonic);
    }
    pub fn reset_crypto_budget(&mut self) {
        self.crypto = CryptoBudget::default();
    }
    pub fn set_local_zones(&mut self, zones: &[Name]) -> io::Result<()> {
        if zones.len() > 8 || zones.iter().any(|z| z.labels().is_empty()) {
            return Err(invalid());
        }
        self.local_zones = zones.to_vec();
        self.cache.clear();
        Ok(())
    }
    /// An authoritative view supplies its A lookup without entering the forwarding cache.
    pub fn answer_local(
        &self,
        client: Client,
        query: &[u8],
        answer: &[u8],
        mut lookup: impl FnMut(&Question) -> io::Result<Vec<u8>>,
    ) -> io::Result<Action> {
        let q = Message::parse(query, Context::Unicast)?;
        let m = Message::parse(answer, Context::Unicast)?;
        if q.questions.len() != 1
            || q.flags & 0xf800 != 0
            || m.flags & 0xf800 != 0x8000
            || m.questions != q.questions
        {
            return Err(invalid());
        }
        let mut bytes = answer.to_vec();
        if let Some(aq) = additional_question(&m, &q.questions[0], self.additional_a) {
            if let Ok(a) = lookup(&aq).and_then(|b| Message::parse(&b, Context::Unicast)) {
                if a.flags & 0xf800 == 0x8000 && a.questions == [aq.clone()] {
                    bytes = augment(&bytes, &a, &aq.name).unwrap_or(bytes);
                }
            }
        }
        deliver(
            Waiter {
                limit: client_limit(&client, &q),
                client,
                id: q.id,
            },
            &bytes,
        )
    }
    pub fn set_additional_a(&mut self, enabled: bool) {
        if self.additional_a != enabled {
            self.cache.clear();
        }
        self.additional_a = enabled;
    }
    pub fn set_upstreams(&mut self, endpoints: &[SocketAddr]) -> io::Result<()> {
        if endpoints.len() > 8
            || endpoints
                .iter()
                .any(|a| a.port() == 0 || a.ip().is_unspecified() || a.ip().is_multicast())
        {
            return Err(invalid());
        }
        let mut unique = vec![];
        for ep in endpoints {
            if !unique.contains(ep) {
                unique.push(*ep);
            }
        }
        if unique != self.upstreams {
            self.cache.clear();
        }
        self.upstreams = unique;
        Ok(())
    }
    pub fn queries(&self) -> impl Iterator<Item = &UpstreamQuery> {
        self.pending.values().map(|p| &p.query)
    }
    pub fn cancel_connection(&mut self, id: usize) {
        for p in self.pending.values_mut() {
            p.waiters.retain(|w| w.client.connection != Some(id));
        }
        self.pending.retain(|_, p| !p.waiters.is_empty());
        for p in self.discovered.values_mut() {
            p.waiters.retain(|w| w.client.connection != Some(id));
        }
        self.discovered.retain(|_, p| !p.waiters.is_empty());
        self.cancel_unused_discovery();
    }
    pub fn connection_pending(&self, id: usize) -> bool {
        self.waiters().any(|w| w.client.connection == Some(id))
    }
    pub fn rate_entries(&self) -> usize {
        self.rates.len()
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len() + self.discovered.len()
    }
    pub fn waiter_count(&self) -> usize {
        self.waiters().count()
    }
    pub fn pending_bytes(&self) -> usize {
        self.pending.values().map(Pending::charge).sum::<usize>()
            + self
                .discovered
                .values()
                .map(Discovered::charge)
                .sum::<usize>()
            + self.discovery.as_ref().map_or(0, |d| d.counts().1)
    }
    pub fn cache_sets(&self) -> usize {
        self.cache.values().map(|c| c.sets).sum()
    }
    pub fn cache_bytes(&self) -> usize {
        self.cache
            .iter()
            .map(|(k, c)| k.len() + c.wire.len() + 128)
            .sum()
    }
    pub fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.pending
            .values()
            .map(|p| p.retry.min(p.deadline))
            .chain(self.cache.values().map(|c| c.expires))
            .chain(self.discovery.as_ref().and_then(|d| d.next_deadline(0)))
            .chain(self.registry().and_then(|r| r.next_deadline()))
            .chain(
                self.registrar
                    .as_ref()
                    .and_then(|r| r.advertising_deadline()),
            )
            .min()
    }
    fn admit(&mut self, source: IpAddr, now: u64) -> io::Result<()> {
        self.rates.retain(|_, (until, _)| *until > now);
        if !self.rates.contains_key(&source) && self.rates.len() >= 32 {
            return Err(capacity());
        }
        let (_, count) = self
            .rates
            .entry(source)
            .or_insert((now.saturating_add(1000), 0));
        if *count >= 32 {
            return Err(capacity());
        }
        *count += 1;
        Ok(())
    }
    pub fn submit(
        &mut self,
        client: Client,
        bytes: &[u8],
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        let m = Message::parse(bytes, Context::Unicast)?;
        if client.address.port() == 0
            || client.address.ip().is_multicast()
            || client.address.ip().is_unspecified()
        {
            return Err(invalid());
        }
        self.admit(client.address.ip(), now)?;
        if m.flags & 0xf800 == 0x2800 {
            let error = |client, error| {
                registration_reply(
                    client,
                    m.id,
                    m.questions.first().map(|q| q.name.clone()),
                    error,
                )
            };
            if !self.srp_source(client.address.ip()) {
                return Ok(vec![error(client, SrpError::Refused)?]);
            }
            if let Some(grant) = self.registry().and_then(|r| r.cached(bytes, now)) {
                return Ok(vec![Action::Reply {
                    client,
                    bytes: grant.response(&m)?,
                }]);
            }
            let wall = self
                .srp_clock
                .0
                .saturating_add(now.saturating_sub(self.srp_clock.1) / 1000);
            let registrar = &self.registrar;
            let zones = &self.zones;
            return match self
                .srp_validator
                .verify(bytes, wall, &mut self.crypto, |name| {
                    registrar.as_ref().and_then(|r| {
                        let canonical = match zones {
                            Some(zones) => zones.registration_name(name).ok()?,
                            None => name.clone(),
                        };
                        r.registry.key(&canonical, now).cloned()
                    })
                }) {
                Ok(update) => {
                    let update = match &self.zones {
                        Some(zones) => match zones.registration(update) {
                            Ok(update) => update,
                            Err(_) => return Ok(vec![error(client, SrpError::ServFail)?]),
                        },
                        None => update,
                    };
                    if let Some(registrar) = &mut self.registrar {
                        match registrar.apply(&update, now, wall) {
                            Ok(grant) => Ok(vec![Action::Reply {
                                client,
                                bytes: grant.response(&m)?,
                            }]),
                            Err(e) => Ok(vec![error(client, e)?]),
                        }
                    } else {
                        Ok(vec![Action::Register { client, update }])
                    }
                }
                Err(e) => Ok(vec![error(client, e)?]),
            };
        }
        if m.flags & 0xf800 != 0
            || m.questions.len() != 1
            || !m.answers.is_empty()
            || !m.authority.is_empty()
            || m.additional.iter().any(|r| r.kind != 41)
            || client.address.port() == 0
            || client.address.ip().is_multicast()
            || client.address.ip().is_unspecified()
        {
            return Err(invalid());
        }
        if m.additional.iter().any(|r| (r.ttl >> 16) & 255 != 0) {
            let mut answer = Message::new(m.id, 0x8080 | (m.flags & 0x110));
            answer.questions = m.questions.clone();
            answer.additional.push(Record {
                name: Name::root(),
                kind: 41,
                class: 4096,
                ttl: 1 << 24,
                data: Rdata::Opt(vec![]),
            });
            let waiter = Waiter {
                limit: client_limit(&client, &m),
                client,
                id: m.id,
            };
            return Ok(vec![deliver(waiter, &answer.encode()?)?]);
        }
        if let Some(registry) = self.registry() {
            let q = &m.questions[0];
            let ds_exception = in_zone(&q.name, &"service.arpa.".parse().unwrap())
                && q.kind == 43
                && m.additional
                    .iter()
                    .any(|r| r.kind == 41 && r.ttl & 0x8000 != 0);
            if !ds_exception && q.class == 1 && !registry.records(&q.name, 255, now).is_empty() {
                let answer = |q: &Question| {
                    let mut a = Message::new(m.id, 0x8400 | (m.flags & 0x100));
                    a.questions.push(q.clone());
                    a.answers = registry.records(&q.name, q.kind, now);
                    a.encode()
                };
                return Ok(vec![self.answer_local(
                    client,
                    bytes,
                    &answer(q)?,
                    answer,
                )?]);
            }
        }
        let ds_exception = in_zone(&m.questions[0].name, &"service.arpa.".parse().unwrap())
            && m.questions[0].kind == 43
            && m.additional
                .iter()
                .any(|r| r.kind == 41 && r.ttl & 0x8000 != 0);
        if !ds_exception {
            if let Some(inventory) = &self.inventory {
                if let Some(mut answer) = inventory.answer(&m.questions[0], now)? {
                    answer.flags |= m.flags & 0x110;
                    return Ok(vec![self.answer_local(
                        client,
                        bytes,
                        &answer.encode()?,
                        |q| inventory.answer(q, now)?.ok_or_else(invalid)?.encode(),
                    )?]);
                }
            }
        }
        let key = query_key(&m)?;
        let waiter = Waiter {
            limit: client_limit(&client, &m),
            client,
            id: m.id,
        };
        let service_arpa = in_zone(&m.questions[0].name, &"service.arpa.".parse().unwrap());
        let ds_exception = service_arpa
            && m.questions[0].kind == 43
            && m.additional
                .iter()
                .any(|r| r.kind == 41 && r.ttl & 0x8000 != 0);
        if !ds_exception
            && self
                .discovery
                .as_ref()
                .is_some_and(|d| d.accepts(&m.questions[0]))
        {
            return self.submit_discovery(m, key, waiter, now);
        }
        if !ds_exception
            && (service_arpa
                || self
                    .local_zones
                    .iter()
                    .any(|z| in_zone(&m.questions[0].name, z)))
        {
            return Ok(vec![deliver(waiter, &failure(&m, 3)?)?]);
        }
        self.cache.retain(|_, c| c.expires > now);
        if let Some(c) = self.cache.get_mut(&key) {
            c.last = now;
            let b = decay(&c.wire, now.saturating_sub(c.inserted) / 1000)?;
            return Ok(vec![deliver(waiter, &b)?]);
        }
        if self.waiter_count() >= WAITERS
            || self
                .waiters()
                .filter(|w| w.client.address.ip() == waiter.client.address.ip())
                .count()
                >= 8
            || self.pending_bytes() + 1024 > BYTES
        {
            return Err(capacity());
        }
        if let Some(p) = self.pending.values_mut().find(|p| p.key == key) {
            p.waiters.push(waiter);
            return Ok(vec![]);
        }
        if self.upstreams.is_empty() {
            return Ok(vec![deliver(waiter, &failure(&m, 2)?)?]);
        }
        if self.pending_count() >= PENDING {
            return Err(capacity());
        }
        let query = self.make_query(bytes, self.upstreams[0], rng)?;
        let p = Pending {
            key,
            question: m.questions[0].clone(),
            original: m,
            query: query.clone(),
            waiters: vec![waiter],
            deadline: now.saturating_add(10000),
            retry: now.saturating_add(1000),
            attempt: 0,
            base: None,
            forward_cache: true,
            aliases: BTreeSet::new(),
        };
        if self.pending_bytes() + p.charge() > BYTES {
            return Err(capacity());
        }
        self.pending.insert(query.exchange, p);
        Ok(vec![Action::Upstream(query)])
    }
    fn make_query(
        &mut self,
        bytes: &[u8],
        server: SocketAddr,
        rng: &mut impl RandomSource,
    ) -> io::Result<UpstreamQuery> {
        let mut random = [0; 4];
        rng.fill(&mut random)?;
        let id = u16::from_le_bytes([random[0], random[1]]);
        let start = usize::from(u16::from_le_bytes([random[2], random[3]])) % 16384;
        let source_port = (0..16384)
            .map(|n| 49152 + ((start + n) % 16384) as u16)
            .find(|port| !self.pending.values().any(|p| p.query.source_port == *port))
            .ok_or_else(capacity)?;
        self.next = self.next.wrapping_add(1);
        let mut bytes = bytes.to_vec();
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        bytes[3] &= !0x20;
        Ok(UpstreamQuery {
            exchange: self.next,
            server,
            source_port,
            tcp: bytes.len() > 4096,
            bytes,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn receive(
        &mut self,
        exchange: u64,
        server: SocketAddr,
        source_port: u16,
        tcp: bool,
        bytes: &[u8],
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Action>> {
        let Some(p) = self.pending.get(&exchange) else {
            return Ok(vec![]);
        };
        if server != p.query.server
            || source_port != p.query.source_port
            || tcp != p.query.tcp
            || now >= p.deadline
        {
            return Ok(vec![]);
        }
        let Ok(m) = Message::parse(bytes, Context::Unicast) else {
            return Ok(vec![]);
        };
        if m.flags & 0xf800 != 0x8000
            || m.id != u16::from_be_bytes([p.query.bytes[0], p.query.bytes[1]])
            || m.questions != [p.question.clone()]
        {
            return Ok(vec![]);
        }
        if m.flags & 0x200 != 0 {
            if tcp {
                return Ok(vec![]);
            }
            let p = self.pending.get_mut(&exchange).unwrap();
            p.query.tcp = true;
            p.retry = p.deadline;
            return Ok(vec![Action::Upstream(p.query.clone())]);
        }
        let mut p = self.pending.remove(&exchange).unwrap();
        if let Some(base) = p.base.take() {
            if let Some(next) = additional_alias(&m, &p.question, &mut p.aliases) {
                return self.continue_additional(Discovered::from_pending(p), next, base, now, rng);
            }
            let b = augment(&base, &m, &p.question.name).unwrap_or(base);
            return self.finish(p, b, now);
        }
        if let Some(aq) = additional_question(&m, &p.question, self.additional_a) {
            return self.continue_additional(
                Discovered::from_pending(p),
                aq,
                bytes.to_vec(),
                now,
                rng,
            );
        }
        self.finish(p, bytes.to_vec(), now)
    }
    fn finish(&mut self, p: Pending, b: Vec<u8>, now: u64) -> io::Result<Vec<Action>> {
        if p.forward_cache {
            self.store(p.key, &b, now)?;
        }
        p.waiters.into_iter().map(|w| deliver(w, &b)).collect()
    }
    fn store(&mut self, key: Vec<u8>, b: &[u8], now: u64) -> io::Result<()> {
        let m = Message::parse(b, Context::Unicast)?;
        let records: Vec<_> = m
            .answers
            .iter()
            .chain(&m.authority)
            .chain(&m.additional)
            .filter(|r| r.kind != 41)
            .collect();
        let positive = m.answers.iter().any(|r| r.kind == m.questions[0].kind);
        let life = if rcode(&m) == 0 && positive {
            records.iter().map(|r| r.ttl).min()
        } else if rcode(&m) == 0 || rcode(&m) == 3 {
            m.authority
                .iter()
                .filter_map(|r| {
                    if let Rdata::Soa { minimum, .. } = r.data {
                        Some(r.ttl.min(minimum))
                    } else {
                        None
                    }
                })
                .min()
        } else {
            None
        };
        let life = life.map(|ttl| {
            records
                .iter()
                .map(|r| r.ttl)
                .min()
                .map_or(ttl, |r| r.min(ttl))
        });
        let Some(life) = life.filter(|t| *t > 0) else {
            return Ok(());
        };
        let sets = records
            .iter()
            .map(|r| (&r.name, r.kind, r.class))
            .collect::<BTreeSet<_>>()
            .len()
            .max(1);
        let mut wire = b.to_vec();
        if !positive {
            for (r, span) in m
                .answers
                .iter()
                .chain(&m.authority)
                .chain(&m.additional)
                .zip(m.record_spans())
            {
                if r.kind == 6 {
                    wire[span.ttl..span.ttl + 4].copy_from_slice(&r.ttl.min(life).to_be_bytes());
                }
            }
        }
        let size = key.len() + wire.len() + 128;
        if sets > CACHE_SETS || size > BYTES {
            return Ok(());
        }
        self.cache.remove(&key);
        while self.cache_sets() + sets > CACHE_SETS || self.cache_bytes() + size > BYTES {
            let Some(old) = self
                .cache
                .iter()
                .min_by_key(|(_, c)| c.last)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.cache.remove(&old);
        }
        self.cache.insert(
            key,
            Cache {
                wire,
                inserted: now,
                expires: now.saturating_add(u64::from(life) * 1000),
                last: now,
                sets,
            },
        );
        Ok(())
    }
    pub fn tick(&mut self, now: u64, rng: &mut impl RandomSource) -> io::Result<Vec<Action>> {
        if let Some(r) = &mut self.registrar {
            r.expire(now);
        }
        self.rates.retain(|_, (until, _)| *until > now);
        self.cache.retain(|_, c| c.expires > now);
        let ids: Vec<_> = self.pending.keys().copied().collect();
        let mut out = vec![];
        for id in ids {
            let mut p = self.pending.remove(&id).unwrap();
            if now >= p.deadline {
                let b = match p.base.take() {
                    Some(b) => b,
                    None => failure(&p.original, 2)?,
                };
                out.extend(self.finish(p, b, now)?);
                continue;
            }
            if now >= p.retry && !p.query.tcp {
                p.attempt += 1;
                let index = usize::from(p.attempt) % self.upstreams.len().max(1);
                let server = self.upstreams.get(index).copied().unwrap_or(p.query.server);
                let q = self.make_query(&p.query.bytes, server, rng)?;
                p.query = q.clone();
                p.retry = now
                    .saturating_add(1000u64 << p.attempt.min(3))
                    .min(p.deadline);
                out.push(Action::Upstream(q));
            }
            self.pending.insert(p.query.exchange, p);
        }
        Ok(out)
    }
}
fn query_key(m: &Message) -> io::Result<Vec<u8>> {
    let mut q = Message::new(0, m.flags & 0x110);
    q.questions = m.questions.clone();
    q.questions[0].name = Name::from_labels(
        q.questions[0]
            .name
            .labels()
            .iter()
            .map(|l| l.iter().map(u8::to_ascii_lowercase).collect())
            .collect(),
    )?;
    q.additional = m.additional.clone();
    q.encode()
}
fn client_limit(c: &Client, m: &Message) -> usize {
    if c.connection.is_some() {
        65535
    } else {
        m.additional
            .iter()
            .find(|r| r.kind == 41)
            .map_or(512, |r| usize::from(r.class).clamp(512, 4096))
    }
}
fn failure(q: &Message, rcode: u16) -> io::Result<Vec<u8>> {
    let mut m = Message::new(q.id, 0x8080 | (q.flags & 0x110) | rcode);
    m.questions = q.questions.clone();
    m.encode()
}
fn deliver(w: Waiter, b: &[u8]) -> io::Result<Action> {
    let mut bytes = if b.len() > w.limit {
        let m = Message::parse(b, Context::Unicast)?;
        let mut q = Message::new(w.id, (m.flags | 0x280) & !0x20);
        q.questions = m.questions;
        q.encode()?
    } else {
        b.to_vec()
    };
    bytes[..2].copy_from_slice(&w.id.to_be_bytes());
    bytes[3] &= !0x20;
    if bytes[2] & 0x78 == 0 {
        bytes[3] |= 0x80;
    }
    Ok(Action::Reply {
        client: w.client,
        bytes,
    })
}
fn canonical(m: &Message, start: &Name) -> io::Result<Name> {
    let mut name = start.clone();
    let mut seen = BTreeSet::new();
    for depth in 0..=16 {
        if !seen.insert(name.clone()) {
            return Err(invalid());
        }
        let mut targets = m
            .answers
            .iter()
            .filter(|r| r.name == name && r.kind == 5)
            .filter_map(|r| {
                if let Rdata::Name(n) = &r.data {
                    Some(n)
                } else {
                    None
                }
            });
        let Some(target) = targets.next() else {
            return Ok(name);
        };
        if depth == 16 || targets.any(|n| n != target) {
            return Err(invalid());
        }
        name = target.clone();
    }
    Err(invalid())
}
fn augment(base: &[u8], a: &Message, start: &Name) -> io::Result<Vec<u8>> {
    if rcode(a) != 0 {
        return Ok(base.to_vec());
    }
    let target = canonical(a, start)?;
    let m = Message::parse(base, Context::Unicast)?;
    let mut wire = base.to_vec();
    let mut records = m.additional.clone();
    let mut added = 0u16;
    for r in a.answers.iter().filter(|r| r.name == target && r.kind == 1) {
        if records
            .iter()
            .any(|x| x.name == r.name && x.kind == r.kind && x.class == r.class && x.data == r.data)
        {
            continue;
        }
        let bytes = record_bytes(r)?;
        if wire.len() + bytes.len() > 65535 {
            break;
        }
        wire.extend(bytes);
        records.push(r.clone());
        added += 1;
    }
    let count = u16::from_be_bytes([wire[10], wire[11]])
        .checked_add(added)
        .ok_or_else(invalid)?;
    wire[10..12].copy_from_slice(&count.to_be_bytes());
    Message::parse(&wire, Context::Unicast)?;
    Ok(wire)
}
fn record_bytes(r: &Record) -> io::Result<Vec<u8>> {
    let mut m = Message::new(0, 0x8000);
    m.additional.push(r.clone());
    let b = m.encode()?;
    Ok(b[12..].to_vec())
}
fn decay(b: &[u8], elapsed: u64) -> io::Result<Vec<u8>> {
    let m = Message::parse(b, Context::Unicast)?;
    let mut b = b.to_vec();
    for (r, s) in m
        .answers
        .iter()
        .chain(&m.authority)
        .chain(&m.additional)
        .zip(m.record_spans())
    {
        if r.kind != 41 {
            b[s.ttl..s.ttl + 4]
                .copy_from_slice(&(u64::from(r.ttl).saturating_sub(elapsed) as u32).to_be_bytes());
        }
    }
    Ok(b)
}

fn rcode(m: &Message) -> u16 {
    (m.flags & 15)
        | (m.additional
            .iter()
            .find(|r| r.kind == 41)
            .map_or(0, |r| (r.ttl >> 24) as u16)
            << 4)
}

fn in_zone(name: &Name, zone: &Name) -> bool {
    let n = name.labels();
    let z = zone.labels();
    n.len() >= z.len()
        && n[n.len() - z.len()..]
            .iter()
            .zip(z)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}
fn additional_question(m: &Message, q: &Question, enabled: bool) -> Option<Question> {
    if !enabled || q.kind != 28 || rcode(m) == 3 || m.answers.iter().any(|r| r.kind == 28) {
        return None;
    }
    Some(Question {
        name: canonical(m, &q.name).ok()?,
        kind: 1,
        class: q.class,
    })
}

/// A small UPDATE response, independent of the query cache and Additional-A wrapper.
pub fn registration_reply(
    client: Client,
    id: u16,
    zone: Option<Name>,
    error: SrpError,
) -> io::Result<Action> {
    let mut m = Message::new(id, 0xa800 | error as u16);
    if let Some(name) = zone {
        m.questions.push(Question {
            name,
            kind: 6,
            class: 1,
        });
    }
    Ok(Action::Reply {
        client,
        bytes: m.encode()?,
    })
}

fn alias_charge(names: &BTreeSet<Name>) -> usize {
    names
        .iter()
        .map(|n| 512 + n.canonical().len() + 128 * n.labels().len())
        .sum()
}
// Seventeen names permit sixteen CNAME edges over all A-lookup responses.
fn additional_alias(m: &Message, q: &Question, seen: &mut BTreeSet<Name>) -> Option<Question> {
    if rcode(m) != 0 || q.kind != 1 {
        return None;
    }
    let mut name = q.name.clone();
    loop {
        let mut targets = m
            .answers
            .iter()
            .filter(|r| r.name == name && r.kind == 5)
            .filter_map(|r| {
                if let Rdata::Name(n) = &r.data {
                    Some(n)
                } else {
                    None
                }
            });
        let Some(target) = targets.next() else {
            break;
        };
        if targets.any(|n| n != target) || seen.len() >= 17 || !seen.insert(target.clone()) {
            return None;
        }
        name = target.clone();
    }
    (name != q.name && !m.answers.iter().any(|r| r.name == name && r.kind == 1)).then_some(
        Question {
            name,
            kind: 1,
            class: q.class,
        },
    )
}
