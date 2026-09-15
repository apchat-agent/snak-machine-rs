pub mod families;
use crate::{
    wire::{envelope, FrameKind},
    Link,
};
use std::{
    collections::{BTreeSet, VecDeque},
    io,
    net::{Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod virtual_link;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFraming {
    Tap,
    Utun,
    RawIpv6,
}
pub trait PacketPort {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>>;
    fn send(&mut self, bytes: &[u8]) -> io::Result<usize>;
}
pub trait CaptureApi {
    fn next_packet(&mut self) -> io::Result<Option<&[u8]>>;
    fn inject(&mut self, bytes: &[u8]) -> io::Result<usize>;
}
pub struct CapturePort<C> {
    pub api: C,
}
impl<C> CapturePort<C> {
    pub fn new(api: C) -> Self {
        Self { api }
    }
}
impl<C: CaptureApi> PacketPort for CapturePort<C> {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.api.next_packet()?.map(<[u8]>::to_vec))
    }
    fn send(&mut self, b: &[u8]) -> io::Result<usize> {
        self.api.inject(b)
    }
}
pub struct Device<P> {
    pub port: P,
    framing: NativeFraming,
    own_mac: Option<[u8; 6]>,
    pub discarded: u64,
}
impl<P: PacketPort> Device<P> {
    pub fn new(port: P, framing: NativeFraming, own_mac: Option<[u8; 6]>) -> Self {
        Self {
            port,
            framing,
            own_mac,
            discarded: 0,
        }
    }
    pub fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let packet = match self.port.receive() {
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                self.discarded = self.discarded.saturating_add(1);
                return Ok(None);
            }
            result => result?,
        };
        let Some(mut p) = packet else {
            return Ok(None);
        };
        if self.framing == NativeFraming::Utun {
            if p.len() < 4 || p[..4] != [0, 0, 0, 30] {
                self.discarded = self.discarded.saturating_add(1);
                return Ok(None);
            }
            p.drain(..4);
        }
        if self.framing == NativeFraming::Tap
            && p.len() >= 14
            && self.own_mac.is_some_and(|m| p[6..12] == m)
        {
            return Ok(None);
        }
        Ok(Some(p))
    }
    pub fn send(&mut self, p: &[u8]) -> io::Result<()> {
        let kind = if self.framing == NativeFraming::Tap {
            FrameKind::Ethernet
        } else {
            FrameKind::RawIpv6
        };
        if kind == FrameKind::Ethernet {
            if families::ethernet_family(p).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported Ethernet family",
                ));
            }
            if families::ethernet_family(p) == Some(families::Family::Ipv6) {
                envelope(kind, p).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid transmit frame")
                })?;
            }
        } else {
            envelope(kind, p).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid transmit frame")
            })?;
        }
        let mut framed = vec![];
        let bytes = if self.framing == NativeFraming::Utun {
            framed.extend([0, 0, 0, 30]);
            framed.extend(p);
            &framed[..]
        } else {
            p
        };
        let count = self.port.send(bytes)?;
        if count != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short packet write/injection",
            ));
        }
        Ok(())
    }
}
pub trait LinkDevice {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>>;
    fn send(&mut self, b: &[u8]) -> io::Result<()>;
}
impl<P: PacketPort> LinkDevice for Device<P> {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        Device::receive(self)
    }
    fn send(&mut self, b: &[u8]) -> io::Result<()> {
        Device::send(self, b)
    }
}
#[derive(Clone, Debug)]
pub struct LinkInfo {
    pub name: String,
    pub index: u32,
    pub kind: FrameKind,
    pub mtu: u32,
    pub mac: Option<[u8; 6]>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Ingress,
    OwnEgress,
    Unknown,
}
#[derive(Clone, Debug)]
pub struct Received {
    pub link: Link,
    pub bytes: Vec<u8>,
    pub kind: FrameKind,
    pub direction: Direction,
}
pub trait PacketIo {
    fn info(&self, link: Link) -> &LinkInfo;
    fn receive(&mut self, timeout: Duration) -> io::Result<Option<Received>>;
    fn send(&mut self, link: Link, bytes: &[u8]) -> io::Result<()>;
    fn join(&mut self, link: Link, group: Ipv6Addr) -> io::Result<()>;
    fn leave(&mut self, link: Link, group: Ipv6Addr) -> io::Result<()>;
    fn join_v4(&mut self, _link: Link, _group: Ipv4Addr) -> io::Result<()> {
        Err(io::Error::other("IPv4 multicast unsupported"))
    }
    fn leave_v4(&mut self, _link: Link, _group: Ipv4Addr) -> io::Result<()> {
        Err(io::Error::other("IPv4 multicast unsupported"))
    }
    fn link_up(&self, _link: Link) -> io::Result<bool> {
        Ok(true)
    }
}
pub struct Backend {
    ports: [Box<dyn LinkDevice>; 2],
    info: [LinkInfo; 2],
    groups: [crate::platform::Membership; 2],
    next: usize,
}
impl Backend {
    pub fn new(ports: [Box<dyn LinkDevice>; 2], info: [LinkInfo; 2]) -> io::Result<Self> {
        crate::platform::validate_pair(&info)?;
        let groups = [
            crate::platform::Membership::new(info[0].index)?,
            crate::platform::Membership::new(info[1].index)?,
        ];
        Ok(Self {
            ports,
            info,
            groups,
            next: 0,
        })
    }
}
impl PacketIo for Backend {
    fn info(&self, l: Link) -> &LinkInfo {
        &self.info[l.index()]
    }
    fn receive(&mut self, timeout: Duration) -> io::Result<Option<Received>> {
        let until = Instant::now() + timeout;
        loop {
            for _ in 0..2 {
                let n = self.next;
                self.next ^= 1;
                if let Some(bytes) = self.ports[n].receive()? {
                    return Ok(Some(Received {
                        link: if n == 0 { Link::Ail } else { Link::Stub },
                        bytes,
                        kind: self.info[n].kind,
                        direction: Direction::Unknown,
                    }));
                }
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            std::thread::sleep(left.min(Duration::from_millis(10)));
        }
    }
    fn send(&mut self, l: Link, b: &[u8]) -> io::Result<()> {
        self.ports[l.index()].send(b)
    }
    fn join(&mut self, l: Link, g: Ipv6Addr) -> io::Result<()> {
        self.groups[l.index()].join(g)
    }
    fn leave(&mut self, l: Link, g: Ipv6Addr) -> io::Result<()> {
        self.groups[l.index()].leave(g)
    }
    fn join_v4(&mut self, l: Link, g: Ipv4Addr) -> io::Result<()> {
        self.groups[l.index()].join_v4(g)
    }
    fn leave_v4(&mut self, l: Link, g: Ipv4Addr) -> io::Result<()> {
        self.groups[l.index()].leave_v4(g)
    }
    fn link_up(&self, l: Link) -> io::Result<bool> {
        crate::platform::is_up(&self.info(l).name)
    }
}
pub struct MemoryIo {
    pub info: [LinkInfo; 2],
    pub input: VecDeque<Received>,
    pub output: Vec<(Link, Vec<u8>)>,
    pub groups: [BTreeSet<Ipv6Addr>; 2],
    pub ipv4_groups: [BTreeSet<Ipv4Addr>; 2],
    pub fail_send: bool,
    pub fail_group: bool,
    pub up: [bool; 2],
}
impl MemoryIo {
    pub fn new(info: [LinkInfo; 2]) -> Self {
        Self {
            info,
            input: VecDeque::new(),
            output: vec![],
            groups: Default::default(),
            ipv4_groups: Default::default(),
            fail_send: false,
            fail_group: false,
            up: [true; 2],
        }
    }
}
impl PacketIo for MemoryIo {
    fn info(&self, l: Link) -> &LinkInfo {
        &self.info[l.index()]
    }
    fn receive(&mut self, _timeout: Duration) -> io::Result<Option<Received>> {
        Ok(self.input.pop_front())
    }
    fn send(&mut self, l: Link, b: &[u8]) -> io::Result<()> {
        if self.fail_send {
            return Err(io::Error::other("mock send failure"));
        }
        self.output.push((l, b.to_vec()));
        Ok(())
    }
    fn join(&mut self, l: Link, g: Ipv6Addr) -> io::Result<()> {
        if self.fail_group {
            return Err(io::Error::other("mock group failure"));
        }
        self.groups[l.index()].insert(g);
        Ok(())
    }
    fn leave(&mut self, l: Link, g: Ipv6Addr) -> io::Result<()> {
        self.groups[l.index()].remove(&g);
        Ok(())
    }
    fn join_v4(&mut self, l: Link, g: Ipv4Addr) -> io::Result<()> {
        self.ipv4_groups[l.index()].insert(g);
        Ok(())
    }
    fn leave_v4(&mut self, l: Link, g: Ipv4Addr) -> io::Result<()> {
        self.ipv4_groups[l.index()].remove(&g);
        Ok(())
    }
    fn link_up(&self, l: Link) -> io::Result<bool> {
        Ok(self.up[l.index()])
    }
}
