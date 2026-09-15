//! IP-medium service sockets; route and neighbor decisions belong to Driver.
use super::{instant, IpDevice, IP_QUEUE_BYTES};
use crate::{
    time::RandomSource,
    wire::{envelope, transport, FrameKind},
};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::{tcp, udp},
    time::Duration,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{collections::BTreeMap, io, net::IpAddr};
const CONNECTIONS: usize = 64;
const LISTENERS: usize = 8;
const TCP_BUFFER: usize = 65536;
const UDP_BUFFER: usize = 4096;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid service IP packet")
}
fn capacity() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "service socket capacity")
}
struct Connection {
    handle: SocketHandle,
    last_io: u64,
}
#[derive(Debug)]
pub struct Datagram {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: u16,
    pub destination_port: u16,
    pub bytes: Vec<u8>,
}
pub struct Stack {
    device: IpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    addresses: Vec<IpAddr>,
    listeners: BTreeMap<u16, SocketHandle>,
    udp: BTreeMap<u16, SocketHandle>,
    connections: BTreeMap<usize, Connection>,
    next_id: usize,
    now: u64,
    reassembly: crate::ip_reassembly::Reassembler,
    fragment_id: u32,
    connection_limit: usize,
}
impl Stack {
    pub fn new(now: u64, rng: &mut impl RandomSource) -> io::Result<Self> {
        let mut device = IpDevice::default();
        let mut cfg = Config::new(HardwareAddress::Ip);
        let mut seed = [0; 8];
        rng.fill(&mut seed)?;
        cfg.random_seed = u64::from_le_bytes(seed);
        let iface = Interface::new(cfg, &mut device, instant(now));
        Ok(Self {
            device,
            iface,
            sockets: SocketSet::new(vec![]),
            addresses: vec![],
            listeners: BTreeMap::new(),
            udp: BTreeMap::new(),
            connections: BTreeMap::new(),
            next_id: 0,
            now,
            reassembly: Default::default(),
            fragment_id: u32::from_le_bytes(seed[..4].try_into().unwrap()),
            connection_limit: CONNECTIONS,
        })
    }
    pub fn set_addresses(&mut self, addresses: &[IpAddr]) -> io::Result<()> {
        if addresses.len() > 32
            || addresses
                .iter()
                .any(|a| a.is_unspecified() || a.is_multicast() || a.is_loopback())
        {
            return Err(invalid());
        }
        self.addresses = addresses.to_vec();
        self.iface.update_ip_addrs(|ips| {
            ips.clear();
            for a in addresses {
                // /0 delegates off-link route selection to our authoritative router.
                ips.push(IpCidr::new(IpAddress::from(*a), 0)).unwrap();
            }
        });
        let remove: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, c)| {
                self.sockets
                    .get::<tcp::Socket>(c.handle)
                    .local_endpoint()
                    .is_none_or(|e| !addresses.contains(&e.addr.into()))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in remove {
            let c = self.connections.remove(&id).unwrap();
            self.sockets.remove(c.handle);
        }
        if addresses.is_empty() {
            self.device.rx.clear();
            self.device.tx.clear();
        }
        Ok(())
    }
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    fn tcp_socket(&mut self) -> SocketHandle {
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        );
        s.set_timeout(Some(Duration::from_secs(120)));
        self.sockets.add(s)
    }
    pub fn listen_tcp(&mut self, port: u16) -> io::Result<()> {
        if port == 0 || self.port_owned(6, port) || self.listeners.len() >= LISTENERS {
            return Err(capacity());
        }
        let h = self.tcp_socket();
        self.sockets
            .get_mut::<tcp::Socket>(h)
            .listen(port)
            .map_err(io::Error::other)?;
        self.listeners.insert(port, h);
        Ok(())
    }
    pub fn listen_udp(&mut self, port: u16) -> io::Result<()> {
        if port == 0 || self.udp.contains_key(&port) || self.udp.len() >= LISTENERS {
            return Err(capacity());
        }
        let buffer =
            || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; UDP_BUFFER]);
        let mut s = udp::Socket::new(buffer(), buffer());
        s.bind(port).map_err(io::Error::other)?;
        let h = self.sockets.add(s);
        self.udp.insert(port, h);
        Ok(())
    }
    pub fn port_owned(&self, protocol: u8, port: u16) -> bool {
        match protocol {
            17 => self.udp.contains_key(&port),
            6 => {
                self.listeners.contains_key(&port)
                    || self.connections.values().any(|c| {
                        self.sockets
                            .get::<tcp::Socket>(c.handle)
                            .local_endpoint()
                            .is_some_and(|e| e.port == port)
                    })
            }
            _ => false,
        }
    }
    pub fn connect(
        &mut self,
        source: IpAddr,
        port: u16,
        destination: IpAddr,
        dest_port: u16,
        now: u64,
    ) -> io::Result<usize> {
        if !self.addresses.contains(&source)
            || source.is_ipv4() != destination.is_ipv4()
            || port == 0
            || dest_port == 0
            || self.port_owned(6, port)
            || self.connections.len() >= self.connection_limit
            || self.peer_count(destination) >= 4
        {
            return Err(capacity());
        }
        let h = self.tcp_socket();
        if let Err(e) = self.sockets.get_mut::<tcp::Socket>(h).connect(
            self.iface.context(),
            (IpAddress::from(destination), dest_port),
            (IpAddress::from(source), port),
        ) {
            self.sockets.remove(h);
            return Err(io::Error::other(e));
        }
        self.insert_connection(h, now)
    }
    fn insert_connection(&mut self, handle: SocketHandle, now: u64) -> io::Result<usize> {
        let id = self.next_id;
        self.next_id = self.next_id.checked_add(1).ok_or_else(capacity)?;
        self.connections.insert(
            id,
            Connection {
                handle,
                last_io: now,
            },
        );
        Ok(id)
    }
    fn peer_count(&self, peer: IpAddr) -> usize {
        self.connections
            .values()
            .filter(|c| {
                self.sockets
                    .get::<tcp::Socket>(c.handle)
                    .remote_endpoint()
                    .is_some_and(|e| IpAddr::from(e.addr) == peer)
            })
            .count()
    }
    pub fn connections(&self) -> Vec<usize> {
        self.connections.keys().copied().collect()
    }
    pub(crate) fn set_connection_limit(&mut self, limit: usize) {
        self.connection_limit = limit.min(CONNECTIONS);
    }
    pub fn endpoints(&self, id: usize) -> Option<(std::net::SocketAddr, std::net::SocketAddr)> {
        let c = self.connections.get(&id)?;
        let s = self.sockets.get::<tcp::Socket>(c.handle);
        let l = s.local_endpoint()?;
        let r = s.remote_endpoint()?;
        Some((
            std::net::SocketAddr::new(l.addr.into(), l.port),
            std::net::SocketAddr::new(r.addr.into(), r.port),
        ))
    }
    pub fn established(&self, id: usize) -> bool {
        self.connections.get(&id).is_some_and(|c| {
            self.sockets.get::<tcp::Socket>(c.handle).state() == tcp::State::Established
        })
    }
    pub fn send_tcp(&mut self, id: usize, bytes: &[u8]) -> io::Result<usize> {
        let c = self.connections.get_mut(&id).ok_or_else(capacity)?;
        let n = self
            .sockets
            .get_mut::<tcp::Socket>(c.handle)
            .send_slice(bytes)
            .map_err(io::Error::other)?;
        if n > 0 {
            c.last_io = self.now;
        }
        Ok(n)
    }
    pub fn receive_tcp(&mut self, id: usize) -> Vec<u8> {
        let Some(c) = self.connections.get_mut(&id) else {
            return vec![];
        };
        let b = self
            .sockets
            .get_mut::<tcp::Socket>(c.handle)
            .recv(|bytes| (bytes.len(), bytes.to_vec()))
            .unwrap_or_default();
        if !b.is_empty() {
            c.last_io = self.now;
        }
        b
    }
    pub fn close(&mut self, id: usize) {
        if let Some(c) = self.connections.get(&id) {
            self.sockets.get_mut::<tcp::Socket>(c.handle).close();
        }
    }
    pub fn abort(&mut self, id: usize) {
        if let Some(c) = self.connections.get(&id) {
            self.sockets.get_mut::<tcp::Socket>(c.handle).abort();
        }
    }
    pub fn send_udp(
        &mut self,
        source: IpAddr,
        source_port: u16,
        dest: IpAddr,
        dest_port: u16,
        bytes: &[u8],
    ) -> io::Result<()> {
        if !self.addresses.contains(&source)
            || source.is_ipv4() != dest.is_ipv4()
            || bytes.len() > UDP_BUFFER
            || dest_port == 0
        {
            return Err(capacity());
        }
        let h = *self.udp.get(&source_port).ok_or_else(capacity)?;
        let meta = udp::UdpMetadata {
            endpoint: (IpAddress::from(dest), dest_port).into(),
            local_address: Some(source.into()),
            meta: Default::default(),
        };
        self.sockets
            .get_mut::<udp::Socket>(h)
            .send_slice(bytes, meta)
            .map_err(io::Error::other)
    }
    pub fn receive_udp(&mut self) -> Option<Datagram> {
        for (port, h) in &self.udp {
            if let Ok((bytes, meta)) = self.sockets.get_mut::<udp::Socket>(*h).recv() {
                return Some(Datagram {
                    source: meta.endpoint.addr.into(),
                    destination: meta.local_address?.into(),
                    source_port: meta.endpoint.port,
                    destination_port: *port,
                    bytes: bytes.to_vec(),
                });
            }
        }
        None
    }
    pub fn input(&mut self, b: &[u8], now: u64) -> io::Result<()> {
        // Check ownership before retaining even the first fragment.
        let destination = match b.first().map(|v| v >> 4) {
            Some(6) => IpAddr::V6(
                envelope(FrameKind::RawIpv6, b)
                    .map_err(|_| invalid())?
                    .destination,
            ),
            Some(4) => IpAddr::V4(crate::ipv4::wire::Packet::parse(b)?.destination),
            _ => return Err(invalid()),
        };
        if !self.addresses.contains(&destination) {
            return Err(invalid());
        }
        let Some(packet) = self.reassembly.input(b, now)? else {
            return Ok(());
        };
        let b = packet.as_slice();
        let (source, dest, proto, len) = match b.first().map(|v| v >> 4) {
            Some(6) => {
                let e = envelope(FrameKind::RawIpv6, b).map_err(|_| invalid())?;
                let t = transport(&e).map_err(|_| invalid())?;
                if t.fragmented || (t.protocol == 58 && t.bytes.first().is_none_or(|t| *t >= 128)) {
                    return Err(invalid());
                }
                (
                    IpAddr::V6(e.source),
                    IpAddr::V6(e.destination),
                    t.protocol,
                    e.packet.len(),
                )
            }
            Some(4) => {
                let p = crate::ipv4::wire::Packet::parse(b)?;
                if p.more_fragments || p.fragment_offset != 0 {
                    return Err(invalid());
                }
                (
                    IpAddr::V4(p.source),
                    IpAddr::V4(p.destination),
                    p.protocol,
                    p.bytes.len(),
                )
            }
            _ => return Err(invalid()),
        };
        if len != b.len()
            || source.is_unspecified()
            || source.is_multicast()
            || source.is_loopback()
            || !self.addresses.contains(&dest)
            || ![6, 17, 1, 58].contains(&proto)
        {
            return Err(invalid());
        }
        if !self.device.space(b.len()) {
            return Err(capacity());
        }
        self.device.rx.push_back(b.to_vec());
        Ok(())
    }
    pub fn poll(&mut self, now: u64) -> io::Result<()> {
        self.now = now;
        self.reassembly.expire(now);
        // Reap elapsed application/handshake deadlines before the stack can retransmit.
        let timed_out: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, c)| {
                let state = self.sockets.get::<tcp::Socket>(c.handle).state();
                now >= c.last_io.saturating_add(
                    if matches!(state, tcp::State::SynSent | tcp::State::SynReceived) {
                        10000
                    } else {
                        120000
                    },
                )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in timed_out {
            let c = self.connections.remove(&id).unwrap();
            self.sockets.remove(c.handle);
        }
        self.iface
            .poll(instant(now), &mut self.device, &mut self.sockets);
        let accepted: Vec<_> = self
            .listeners
            .iter()
            .filter(|(_, h)| self.sockets.get::<tcp::Socket>(**h).state() != tcp::State::Listen)
            .map(|(p, h)| (*p, *h))
            .collect();
        for (port, h) in accepted {
            let remote = self.sockets.get::<tcp::Socket>(h).remote_endpoint();
            if remote.is_some_and(|r| {
                self.connections.len() < self.connection_limit && self.peer_count(r.addr.into()) < 4
            }) {
                self.insert_connection(h, now)?;
            } else {
                self.sockets.remove(h);
            }
            let fresh = self.tcp_socket();
            self.sockets
                .get_mut::<tcp::Socket>(fresh)
                .listen(port)
                .map_err(io::Error::other)?;
            self.listeners.insert(port, fresh);
        }
        let expired: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, c)| {
                let s = self.sockets.get::<tcp::Socket>(c.handle);
                s.state() == tcp::State::Closed
                    || now
                        >= c.last_io.saturating_add(
                            if matches!(s.state(), tcp::State::SynSent | tcp::State::SynReceived) {
                                10000
                            } else {
                                120000
                            },
                        )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            let c = self.connections.remove(&id).unwrap();
            self.sockets.remove(c.handle);
        }
        Ok(())
    }
    pub fn output(&mut self) -> Option<Vec<u8>> {
        let packet = self.device.tx.pop_front()?;
        if packet.len() <= super::MTU {
            return Some(packet);
        }
        let fragments =
            crate::ip_reassembly::fragment(&packet, super::MTU, self.fragment_id).ok()?;
        self.fragment_id = self.fragment_id.wrapping_add(1);
        if self.device.rx.len() + self.device.tx.len() + fragments.len() > super::IP_QUEUE_PACKETS
            || self.device.bytes() + fragments.iter().map(Vec::len).sum::<usize>() > IP_QUEUE_BYTES
        {
            return None;
        }
        for f in fragments.into_iter().rev() {
            self.device.tx.push_front(f);
        }
        self.device.tx.pop_front()
    }
    pub fn queued_bytes(&self) -> usize {
        self.device.bytes()
    }
    pub fn buffer_limit(&self) -> usize {
        IP_QUEUE_BYTES
    }
}
