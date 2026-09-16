//! IP-medium endpoints. ND, routing and address readiness remain router-owned.
//! S01 provides one bounded TCP endpoint; Driver integration is step S07.
pub mod identity;
pub mod loopback;
pub mod stack;
pub mod tls;
use crate::{
    time::{RandomSource, Time},
    wire::{envelope, transport, FrameKind},
};
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpCidr},
};
use std::{collections::VecDeque, io, net::Ipv6Addr};

pub const IP_QUEUE_PACKETS: usize = 64;
pub const IP_QUEUE_BYTES: usize = 65536;
const MTU: usize = 1280;
const TCP_BUFFER: usize = 65536;

#[derive(Default)]
struct IpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}
impl IpDevice {
    fn mtu(&self) -> usize {
        if self.mtu == 0 {
            MTU
        } else {
            self.mtu
        }
    }
    fn bytes(&self) -> usize {
        self.rx.iter().chain(&self.tx).map(Vec::len).sum()
    }
    fn space(&self, bytes: usize) -> bool {
        self.rx.len() + self.tx.len() < IP_QUEUE_PACKETS && self.bytes() + bytes <= IP_QUEUE_BYTES
    }
}
struct Receive(Vec<u8>);
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct Transmit<'a>(&'a mut VecDeque<Vec<u8>>, usize);
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        // UDP may exceed the device MTU; Stack fragments it before Driver output.
        assert!(len <= 65575);
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        if len <= self.1 {
            self.0.push_back(bytes);
        }
        result
    }
}
impl Device for IpDevice {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: Instant) -> Option<(Receive, Transmit<'_>)> {
        let len = self.rx.front()?.len();
        if self.bytes() - len + MTU > IP_QUEUE_BYTES {
            return None;
        }
        let packet = self.rx.pop_front()?;
        let remaining = IP_QUEUE_BYTES - self.bytes();
        Some((Receive(packet), Transmit(&mut self.tx, remaining)))
    }
    fn transmit(&mut self, _: Instant) -> Option<Transmit<'_>> {
        let remaining = IP_QUEUE_BYTES - self.bytes();
        self.space(MTU).then_some(Transmit(&mut self.tx, remaining))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu();
        caps.max_burst_size = Some(IP_QUEUE_PACKETS);
        caps
    }
}

pub struct Endpoint {
    address: Ipv6Addr,
    device: IpDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    tcp: SocketHandle,
}
impl Endpoint {
    /// The caller supplies a DAD-ready address. No address is installed in the kernel.
    pub fn new(address: Ipv6Addr, now: Time, rng: &mut impl RandomSource) -> io::Result<Self> {
        if address.is_unspecified() || address.is_multicast() || address.is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid endpoint address",
            ));
        }
        let mut device = IpDevice::default();
        let mut cfg = Config::new(HardwareAddress::Ip);
        let mut seed = [0; 8];
        rng.fill(&mut seed)?;
        cfg.random_seed = u64::from_le_bytes(seed);
        let mut iface = Interface::new(cfg, &mut device, instant(now));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(address), 64))
                .unwrap();
        });
        let mut sockets = SocketSet::new(Vec::new());
        let tcp = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
        ));
        Ok(Self {
            address,
            device,
            iface,
            sockets,
            tcp,
        })
    }
    pub fn address(&self) -> Ipv6Addr {
        self.address
    }
    pub fn listen(&mut self, port: u16) -> io::Result<()> {
        self.sockets
            .get_mut::<tcp::Socket>(self.tcp)
            .listen((self.address, port))
            .map_err(io::Error::other)
    }
    pub fn connect(&mut self, address: Ipv6Addr, port: u16, local_port: u16) -> io::Result<()> {
        self.sockets
            .get_mut::<tcp::Socket>(self.tcp)
            .connect(
                self.iface.context(),
                (address, port),
                (self.address, local_port),
            )
            .map_err(io::Error::other)
    }
    pub fn established(&self) -> bool {
        self.sockets.get::<tcp::Socket>(self.tcp).state() == tcp::State::Established
    }
    pub fn input(&mut self, bytes: &[u8]) -> io::Result<()> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid endpoint packet");
        let packet = envelope(FrameKind::RawIpv6, bytes).map_err(|_| invalid())?;
        let upper = transport(&packet).map_err(|_| invalid())?;
        if packet.packet.len() != bytes.len()
            || bytes.len() > MTU
            || packet.destination != self.address
            || packet.source.is_unspecified()
            || packet.source.is_multicast()
            || packet.source.is_loopback()
            || upper.fragmented
            || upper.protocol != 6
            || upper.bytes.len() < 20
        {
            return Err(invalid());
        }
        if !self.device.space(bytes.len()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "IP queue capacity",
            ));
        }
        self.device.rx.push_back(bytes.to_vec());
        Ok(())
    }
    pub fn poll(&mut self, now: Time) {
        self.iface
            .poll(instant(now), &mut self.device, &mut self.sockets);
    }
    pub fn output(&mut self) -> Option<Vec<u8>> {
        self.device.tx.pop_front()
    }
    pub fn queued_bytes(&self) -> usize {
        self.device.bytes()
    }
    pub fn send(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.sockets
            .get_mut::<tcp::Socket>(self.tcp)
            .send_slice(bytes)
            .map_err(io::Error::other)
    }
    pub fn receive(&mut self) -> Vec<u8> {
        self.sockets
            .get_mut::<tcp::Socket>(self.tcp)
            .recv(|bytes| (bytes.len(), bytes.to_vec()))
            .unwrap_or_default()
    }
}
fn instant(now: Time) -> Instant {
    Instant::from_millis(now.min(i64::MAX as u64) as i64)
}

/// Every TLS configuration explicitly selects the pure Rust provider.
pub fn crypto_provider() -> rustls::crypto::CryptoProvider {
    rustls_rustcrypto::provider()
}
pub fn tls_server(cert: Vec<u8>, key: Vec<u8>) -> Result<rustls::ServerConfig, rustls::Error> {
    rustls::ServerConfig::builder_with_provider(crypto_provider().into())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
}

pub mod ports;
