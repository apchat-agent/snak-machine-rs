//! Shared transport binding/session indexes. A live mapping is never evicted.
mod tcp;
use crate::{
    service_io::ports::{Lease, Owner, Ports},
    time::RandomSource,
};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{Ipv6Addr, SocketAddrV4},
};
type Key = (u8, Ipv6Addr, u16);
type SessionKey = (Key, SocketAddrV4);
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum UdpFiltering {
    #[default]
    AddressDependent,
    EndpointIndependent,
}
struct Binding {
    _port: Lease,
    port: u16,
    sessions: usize,
}
struct Session {
    expires: u64,
    tcp: Option<super::tcp::State>,
    probe: bool,
    syn_quote: Vec<u8>,
}
pub struct Bindings {
    ports: Ports,
    bindings: BTreeMap<Key, Binding>,
    reverse: BTreeMap<(u8, u16), Key>,
    sessions: BTreeMap<SessionKey, Session>,
    hosts: BTreeMap<Ipv6Addr, (usize, usize)>,
    next: Option<u64>,
    udp_filtering: UdpFiltering,
    udp_seconds: u32,
    tcp_timeouts: VecDeque<Vec<u8>>,
    tcp_quote_bytes: usize,
}
impl Default for Bindings {
    fn default() -> Self {
        Self {
            ports: Ports::default(),
            bindings: BTreeMap::new(),
            reverse: BTreeMap::new(),
            sessions: BTreeMap::new(),
            hosts: BTreeMap::new(),
            next: None,
            udp_filtering: UdpFiltering::default(),
            udp_seconds: 300,
            tcp_timeouts: VecDeque::new(),
            tcp_quote_bytes: 0,
        }
    }
}
fn full() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "NAT64 binding/session/port capacity",
    )
}
impl Bindings {
    pub fn with_ports(ports: Ports) -> Self {
        Self {
            ports,
            ..Self::default()
        }
    }
    pub fn owns(&self, protocol: u8, port: u16) -> bool {
        self.reverse.contains_key(&(protocol, port))
    }
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.bindings.len(), self.sessions.len(), self.hosts.len())
    }
    pub fn charged_bytes(&self) -> usize {
        self.bindings.len() * 192
            + self.reverse.len() * 96
            + self.sessions.len() * 256
            + self.hosts.len() * 128
            + self.tcp_timeouts.len() * 128
            + self.tcp_quote_bytes
    }
    pub fn next_deadline(&self) -> Option<u64> {
        if !self.tcp_timeouts.is_empty() || self.sessions.values().any(|s| s.probe) {
            Some(0)
        } else {
            self.next
        }
    }
    pub fn set_udp_filtering(&mut self, filter: UdpFiltering) {
        self.udp_filtering = filter;
    }
    pub fn set_udp_timeout(&mut self, seconds: u32) -> io::Result<()> {
        if !(120..=86400).contains(&seconds) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP timeout must be 120..86400 seconds",
            ));
        }
        self.udp_seconds = seconds;
        Ok(())
    }
    pub fn expire(&mut self, now: u64) -> Vec<(u8, u16)> {
        if self.next.is_none_or(|t| t > now) {
            return vec![];
        }
        for s in self.sessions.values_mut() {
            if s.expires <= now && s.tcp == Some(super::tcp::State::Established) {
                s.tcp = Some(super::tcp::State::Transitory);
                s.expires = s.expires.saturating_add(super::tcp::TRANSITORY);
                s.probe = s.expires > now;
            }
        }
        let old: Vec<_> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.expires <= now)
            .map(|(k, _)| *k)
            .collect();
        let mut released = vec![];
        for key in old {
            let s = self.sessions.remove(&key).unwrap();
            self.tcp_quote_bytes -= s.syn_quote.len();
            if s.tcp == Some(super::tcp::State::V4Init)
                && !s.syn_quote.is_empty()
                && self.tcp_timeouts.len() < 32
            {
                self.tcp_timeouts.push_back(s.syn_quote);
            }
            let b = self.bindings.get_mut(&key.0).unwrap();
            b.sessions -= 1;
            let host = self.hosts.get_mut(&key.0 .1).unwrap();
            host.1 -= 1;
            if b.sessions == 0 {
                let port = b.port;
                self.bindings.remove(&key.0);
                self.reverse.remove(&(key.0 .0, port));
                released.push((key.0 .0, port));
                host.0 -= 1;
            }
            if host.0 == 0 {
                self.hosts.remove(&key.0 .1);
            }
        }
        self.next = self.sessions.values().map(|s| s.expires).min();
        released
    }
    pub fn clear(&mut self) -> Vec<(u8, u16)> {
        let ports = self.reverse.keys().copied().collect();
        self.bindings.clear();
        self.reverse.clear();
        self.sessions.clear();
        self.hosts.clear();
        self.next = None;
        self.tcp_timeouts.clear();
        self.tcp_quote_bytes = 0;
        ports
    }
    fn admit(&self, key: Key, remote: SocketAddrV4) -> io::Result<()> {
        let (bindings, sessions) = self.hosts.get(&key.1).copied().unwrap_or_default();
        let bytes = usize::from(!self.bindings.contains_key(&key)) * 288
            + usize::from(!self.hosts.contains_key(&key.1)) * 128
            + usize::from(!self.sessions.contains_key(&(key, remote))) * 256;
        if self.charged_bytes() + bytes > 4 * 1024 * 1024
            || !self.bindings.contains_key(&key) && (self.bindings.len() >= 4096 || bindings >= 128)
            || !self.sessions.contains_key(&(key, remote))
                && (self.sessions.len() >= 8192 || sessions >= 256)
        {
            return Err(full());
        }
        Ok(())
    }
    fn udp_session(&mut self, key: Key, remote: SocketAddrV4, now: u64) {
        let expires = now.saturating_add(u64::from(self.udp_seconds) * 1000);
        if self
            .sessions
            .insert(
                (key, remote),
                Session {
                    expires,
                    tcp: None,
                    probe: false,
                    syn_quote: vec![],
                },
            )
            .is_none()
        {
            self.bindings.get_mut(&key).unwrap().sessions += 1;
            self.hosts.get_mut(&key.1).unwrap().1 += 1;
        }
        self.next = Some(self.next.map_or(expires, |old| old.min(expires)));
    }
    #[allow(clippy::too_many_arguments)]
    pub fn udp_out(
        &mut self,
        source: Ipv6Addr,
        port: u16,
        remote: SocketAddrV4,
        now: u64,
        rng: &mut impl RandomSource,
        occupied: impl Fn(u16) -> bool,
    ) -> io::Result<u16> {
        self.expire(now);
        let key = (17, source, port);
        self.admit(key, remote)?;
        let assigned = if let Some(b) = self.bindings.get(&key) {
            b.port
        } else {
            let allocated = self.allocate(17, port, rng, occupied)?;
            let lease = self.ports.claim(17, allocated, Owner::Translation)?;
            self.bindings.insert(
                key,
                Binding {
                    _port: lease,
                    port: allocated,
                    sessions: 0,
                },
            );
            self.reverse.insert((17, allocated), key);
            self.hosts.entry(source).or_default().0 += 1;
            allocated
        };
        self.udp_session(key, remote, now);
        Ok(assigned)
    }
    pub fn udp_in(
        &mut self,
        port: u16,
        remote: SocketAddrV4,
        now: u64,
    ) -> io::Result<Option<(Ipv6Addr, u16)>> {
        self.expire(now);
        let Some(key) = self.reverse.get(&(17, port)).copied() else {
            return Ok(None);
        };
        if self.udp_filtering == UdpFiltering::AddressDependent {
            let low = (key, SocketAddrV4::new(*remote.ip(), 0));
            let high = (key, SocketAddrV4::new(*remote.ip(), u16::MAX));
            if self.sessions.range(low..=high).next().is_none() {
                return Ok(None);
            }
        }
        self.admit(key, remote)?;
        self.udp_session(key, remote, now);
        Ok(Some((key.1, key.2)))
    }
    fn allocate(
        &self,
        protocol: u8,
        port: u16,
        rng: &mut impl RandomSource,
        occupied: impl Fn(u16) -> bool,
    ) -> io::Result<u16> {
        let free = |p| {
            !self.reverse.contains_key(&(protocol, p))
                && !self.ports.occupied(protocol, p)
                && !occupied(p)
        };
        if port != 0 && free(port) {
            return Ok(port);
        }
        for high in [port >= 1024, port < 1024] {
            for parity in [port % 2, 1 - port % 2] {
                let first = if high {
                    1024 + parity
                } else if parity == 0 {
                    2
                } else {
                    1
                };
                let count = if high {
                    32256u32
                } else if parity == 0 {
                    511
                } else {
                    512
                };
                let start = rng.sample(u64::from(count - 1))? as u32;
                for n in 0..count.min(8192) {
                    let candidate = first + (((start + n) % count) * 2) as u16;
                    if free(candidate) {
                        return Ok(candidate);
                    }
                }
            }
        }
        Err(full())
    }
}
