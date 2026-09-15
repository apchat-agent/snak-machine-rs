//! Nonblocking loopback adapter for the same incremental service byte handlers.
use std::{
    collections::{BTreeMap, VecDeque},
    io::{self, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
};
const BUFFER: usize = 65536;
#[derive(Eq, PartialEq)]
enum WriteState {
    Open,
    Closing,
    Closed,
}
struct Connection {
    stream: TcpStream,
    peer: IpAddr,
    rx: Vec<u8>,
    tx: VecDeque<u8>,
    last: u64,
    eof: bool,
    write: WriteState,
}
pub struct Loopback {
    tcp: TcpListener,
    udp: UdpSocket,
    local: SocketAddr,
    connections: BTreeMap<usize, Connection>,
    next_id: usize,
    cursor: usize,
    datagrams: VecDeque<(SocketAddr, Vec<u8>)>,
    datagram_bytes: usize,
}
impl Loopback {
    pub fn bind(address: IpAddr) -> io::Result<Self> {
        if !address.is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "loopback address required",
            ));
        }
        let udp = UdpSocket::bind((address, 0))?;
        let local = udp.local_addr()?;
        let tcp = TcpListener::bind(local)?;
        udp.set_nonblocking(true)?;
        tcp.set_nonblocking(true)?;
        Ok(Self {
            tcp,
            udp,
            local,
            connections: BTreeMap::new(),
            next_id: 0,
            cursor: 0,
            datagrams: VecDeque::new(),
            datagram_bytes: 0,
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn connections(&self) -> Vec<usize> {
        self.connections.keys().copied().collect()
    }
    pub fn receive_udp(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        let d = self.datagrams.pop_front()?;
        self.datagram_bytes -= d.1.len() + 64;
        Some(d)
    }
    pub fn send_udp(&self, peer: SocketAddr, bytes: &[u8]) -> io::Result<()> {
        if !peer.ip().is_loopback() || bytes.len() > 65507 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid loopback datagram",
            ));
        }
        if self.udp.send_to(bytes, peer)? != bytes.len() {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"));
        }
        Ok(())
    }
    pub fn receive_tcp(&mut self, id: usize) -> Vec<u8> {
        self.connections
            .get_mut(&id)
            .map(|c| std::mem::take(&mut c.rx))
            .unwrap_or_default()
    }
    pub fn send_tcp(&mut self, id: usize, bytes: &[u8]) -> io::Result<usize> {
        let c = self
            .connections
            .get_mut(&id)
            .ok_or_else(|| io::Error::other("closed connection"))?;
        if c.write != WriteState::Open {
            return Err(io::Error::other("closed output"));
        }
        let n = bytes.len().min(BUFFER - c.tx.len());
        c.tx.extend(&bytes[..n]);
        Ok(n)
    }
    pub fn close(&mut self, id: usize) {
        if let Some(c) = self.connections.get_mut(&id) {
            if c.write == WriteState::Open {
                c.write = WriteState::Closing;
            }
        }
    }
    pub fn eof(&self, id: usize) -> bool {
        self.connections.get(&id).is_none_or(|c| c.eof)
    }
    pub fn queued_udp(&self) -> (usize, usize) {
        (self.datagrams.len(), self.datagram_bytes)
    }
    pub fn poll(&mut self, now: u64) -> io::Result<()> {
        self.connections.retain(|_, c| {
            now < c.last.saturating_add(120000)
                && !(c.eof && c.rx.is_empty() && c.write == WriteState::Closed)
        });
        for _ in 0..32 {
            match self.tcp.accept() {
                Ok((stream, peer)) => {
                    if !peer.ip().is_loopback()
                        || self.connections.len() >= 64
                        || self
                            .connections
                            .values()
                            .filter(|c| c.peer == peer.ip())
                            .count()
                            >= 4
                    {
                        continue;
                    }
                    stream.set_nonblocking(true)?;
                    stream.set_nodelay(true)?;
                    let id = self.next_id;
                    self.next_id = self
                        .next_id
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("connection ID exhausted"))?;
                    self.connections.insert(
                        id,
                        Connection {
                            stream,
                            peer: peer.ip(),
                            rx: vec![],
                            tx: VecDeque::new(),
                            last: now,
                            eof: false,
                            write: WriteState::Open,
                        },
                    );
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        let keys: Vec<_> = self.connections.keys().copied().collect();
        for id in keys
            .iter()
            .cycle()
            .skip(self.cursor)
            .take(keys.len().min(8))
        {
            let c = self.connections.get_mut(id).unwrap();
            if !c.eof && c.rx.len() < BUFFER {
                let mut scratch = [0; 8192];
                let count = (BUFFER - c.rx.len()).min(scratch.len());
                match c.stream.read(&mut scratch[..count]) {
                    Ok(0) => c.eof = true,
                    Ok(n) => {
                        c.rx.extend_from_slice(&scratch[..n]);
                        c.last = now;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        c.eof = true;
                        c.write = WriteState::Closed;
                        c.tx.clear();
                    }
                }
            }
            if !c.tx.is_empty() && c.write != WriteState::Closed {
                let (front, _) = c.tx.as_slices();
                match c.stream.write(front) {
                    Ok(n) => {
                        c.tx.drain(..n);
                        if n > 0 {
                            c.last = now;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        c.eof = true;
                        c.write = WriteState::Closed;
                        c.tx.clear();
                    }
                }
            }
            if c.write == WriteState::Closing && c.tx.is_empty() {
                let _ = c.stream.shutdown(Shutdown::Write);
                c.write = WriteState::Closed;
            }
        }
        self.cursor = if keys.is_empty() {
            0
        } else {
            (self.cursor + 8) % keys.len()
        };
        let mut packet = [0; 65536];
        for _ in 0..32 {
            match self.udp.recv_from(&mut packet) {
                Ok((n, peer)) => {
                    if peer.ip().is_loopback()
                        && self.datagrams.len() < 64
                        && self.datagram_bytes + n + 64 <= BUFFER
                    {
                        self.datagram_bytes += n + 64;
                        self.datagrams.push_back((peer, packet[..n].to_vec()));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
