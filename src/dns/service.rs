//! The production DNS byte handler uses the same resolver as loopback fixtures.
use super::{
    resolver::{Action, Client, Resolver},
    wire::TcpFrames,
};
use crate::{service_io::stack::Stack, time::RandomSource};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    net::{IpAddr, SocketAddr},
};
#[derive(Default)]
pub struct Service {
    udp: BTreeMap<u64, (u16, IpAddr)>,
    replies: VecDeque<(Client, Vec<u8>)>,
    bytes: usize,
    incoming: BTreeMap<usize, Stream>,
    outgoing: BTreeMap<u64, (usize, Stream)>,
    cursor: usize,
}
impl Service {
    pub fn counts(&self) -> (usize, usize, usize) {
        (self.udp.len(), self.incoming.len(), self.outgoing.len())
    }
    pub fn queued_replies(&self) -> (usize, usize) {
        (self.replies.len(), self.bytes)
    }
    pub fn queue(&mut self, actions: Vec<Action>) {
        for a in actions {
            if let Action::Reply { client, bytes } = a {
                if let Some(id) = client.connection {
                    if let Some(stream) = self.incoming.get_mut(&id) {
                        stream.enqueue(&bytes);
                    }
                    continue;
                }
                let size = bytes.len() + 128;
                if self.replies.len() < 256 && self.bytes + size <= 65536 {
                    self.bytes += size;
                    self.replies.push_back((client, bytes));
                }
            }
        }
    }
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        (!self.replies.is_empty()
            || self.incoming.values().any(|s| !s.tx.is_empty())
            || self.outgoing.values().any(|(_, s)| !s.tx.is_empty()))
        .then_some(now)
    }
    pub fn poll(
        &mut self,
        r: &mut Resolver,
        stacks: &mut [Stack; 2],
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        self.queue(r.tick(now, rng)?);
        self.poll_tcp(r, stacks, now, rng)?;
        let old: Vec<_> = self
            .udp
            .iter()
            .filter(|(id, (_, source))| {
                !r.queries().any(|q| q.exchange == **id && !q.tcp)
                    || !stacks[0].addresses().contains(source)
            })
            .map(|(id, _)| *id)
            .collect();
        for id in old {
            let (port, _) = self.udp.remove(&id).unwrap();
            stacks[0].unlisten_udp(port);
        }
        for _ in 0..32 {
            let Some(d) = stacks[1].receive_udp_on(53) else {
                break;
            };
            let mut client = Client::udp(SocketAddr::new(d.source, d.source_port));
            client.local = Some(d.destination);
            if let Ok(actions) = r.submit(client, &d.bytes, now, rng) {
                self.queue(actions);
            }
        }
        let bindings: Vec<_> = self
            .udp
            .iter()
            .map(|(id, (port, _))| (*id, *port))
            .collect();
        let mut budget = 32;
        for (id, port) in bindings {
            while budget > 0 {
                let Some(d) = stacks[0].receive_udp_on(port) else {
                    break;
                };
                budget -= 1;
                let actions = r.receive(
                    id,
                    SocketAddr::new(d.source, d.source_port),
                    port,
                    false,
                    &d.bytes,
                    now,
                    rng,
                )?;
                self.queue(actions);
            }
        }
        let queries: Vec<_> = r
            .queries()
            .filter(|q| !q.tcp && !self.udp.contains_key(&q.exchange))
            .cloned()
            .collect();
        for q in queries {
            if self.udp.len() >= 8 {
                break;
            }
            let Some(source) = source_address(&stacks[0], q.server.ip()) else {
                continue;
            };
            if stacks[0].listen_udp(q.source_port).is_err() {
                continue;
            }
            if stacks[0]
                .send_udp(
                    source,
                    q.source_port,
                    q.server.ip(),
                    q.server.port(),
                    &q.bytes,
                )
                .is_ok()
            {
                self.udp.insert(q.exchange, (q.source_port, source));
            } else {
                stacks[0].unlisten_udp(q.source_port);
            }
        }
        for _ in 0..32 {
            let Some((client, b)) = self.replies.pop_front() else {
                break;
            };
            self.bytes -= b.len() + 128;
            if let Some(source) = client.local {
                if let Err(e) =
                    stacks[1].send_udp(source, 53, client.address.ip(), client.address.port(), &b)
                {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        self.bytes += b.len() + 128;
                        self.replies.push_front((client, b));
                        break;
                    }
                }
            }
        }
        self.flush_tcp(r, stacks);
        Ok(())
    }
    fn poll_tcp(
        &mut self,
        r: &mut Resolver,
        stacks: &mut [Stack; 2],
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        let gone: Vec<_> = self
            .incoming
            .keys()
            .filter(|id| !stacks[1].connections().contains(id))
            .copied()
            .collect();
        for id in gone {
            self.incoming.remove(&id);
            r.cancel_connection(id);
        }
        for id in stacks[1].connections() {
            if stacks[1].endpoints(id).is_some_and(|(l, _)| l.port() == 53)
                && self.incoming.len() < 64
            {
                self.incoming.entry(id).or_insert_with(Stream::new);
            }
        }
        let ids: Vec<_> = self.incoming.keys().copied().collect();
        for n in 0..ids.len().min(8) {
            let id = ids[(self.cursor + n) % ids.len()];
            let Some((local, remote)) = stacks[1].endpoints(id) else {
                continue;
            };
            let mut messages = vec![];
            {
                let stream = self.incoming.get_mut(&id).unwrap();
                stream.read(&mut stacks[1], id);
                for _ in 0..4 {
                    let Some(b) = stream.frames.pop() else {
                        break;
                    };
                    messages.push(b);
                }
            }
            for bytes in messages {
                let mut client = Client::tcp(remote, id);
                client.local = Some(local.ip());
                match r.submit(client, &bytes, now, rng) {
                    Ok(actions) => self.queue(actions),
                    Err(_) => self.incoming.get_mut(&id).unwrap().failed = true,
                }
            }
        }
        self.cursor = self.cursor.wrapping_add(8);
        let old: Vec<_> = self
            .outgoing
            .keys()
            .filter(|id| !r.queries().any(|q| q.exchange == **id))
            .copied()
            .collect();
        for id in old {
            let (connection, _) = self.outgoing.remove(&id).unwrap();
            stacks[0].abort(connection);
        }
        let ids: Vec<_> = self.outgoing.keys().copied().collect();
        for exchange in ids {
            let (connection, stream) = self.outgoing.get_mut(&exchange).unwrap();
            stream.read(&mut stacks[0], *connection);
            if let Some(bytes) = stream.frames.pop() {
                let query = r.queries().find(|q| q.exchange == exchange).cloned();
                if let Some(q) = query {
                    let actions =
                        r.receive(exchange, q.server, q.source_port, true, &bytes, now, rng)?;
                    self.queue(actions);
                }
            }
        }
        let queries: Vec<_> = r
            .queries()
            .filter(|q| q.tcp && !self.outgoing.contains_key(&q.exchange))
            .cloned()
            .collect();
        for q in queries {
            if self.outgoing.len() >= 8 {
                break;
            }
            let Some(source) = source_address(&stacks[0], q.server.ip()) else {
                continue;
            };
            if let Ok(id) =
                stacks[0].connect(source, q.source_port, q.server.ip(), q.server.port(), now)
            {
                let mut stream = Stream::new();
                stream.enqueue(&q.bytes);
                self.outgoing.insert(q.exchange, (id, stream));
            }
        }
        Ok(())
    }
    fn flush_tcp(&mut self, r: &mut Resolver, stacks: &mut [Stack; 2]) {
        for (id, stream) in &mut self.incoming {
            stream.flush(&mut stacks[1], *id);
            if stream.failed {
                stacks[1].abort(*id);
                r.cancel_connection(*id);
            } else if stacks[1].tcp_eof(*id) && !r.connection_pending(*id) && stream.tx.is_empty() {
                if stream.frames.buffered() > 0 {
                    stacks[1].abort(*id);
                } else {
                    stacks[1].close(*id);
                }
            }
        }
        for (id, stream) in self.outgoing.values_mut() {
            stream.flush(&mut stacks[0], *id);
            if stream.failed {
                stacks[0].abort(*id);
            }
        }
    }
}
struct Stream {
    frames: TcpFrames,
    tx: VecDeque<u8>,
    failed: bool,
}
impl Stream {
    fn new() -> Self {
        Self {
            frames: TcpFrames::new(65535).unwrap(),
            tx: VecDeque::new(),
            failed: false,
        }
    }
    // Reserve 16 KiB for the TCP rings and 2 KiB for framing/index overhead.
    fn available(&self) -> usize {
        (128 * 1024usize).saturating_sub(18 * 1024 + self.frames.buffered() + self.tx.len())
    }
    fn enqueue(&mut self, b: &[u8]) {
        if b.len() + 2 > self.available() {
            self.failed = true;
            return;
        }
        match TcpFrames::frame(b) {
            Ok(b) => self.tx.extend(b),
            Err(_) => self.failed = true,
        }
    }
    fn read(&mut self, s: &mut Stack, id: usize) {
        let b = s.receive_tcp_limit(id, self.available().min(8192));
        if self.frames.input(&b).is_err() {
            self.failed = true;
        }
    }
    fn flush(&mut self, s: &mut Stack, id: usize) {
        if !self.tx.is_empty() {
            let bytes = self.tx.make_contiguous();
            match s.send_tcp(id, bytes) {
                Ok(n) => {
                    self.tx.drain(..n);
                }
                Err(_) => {
                    if s.established(id) {
                        self.failed = true;
                    }
                }
            }
        }
    }
}
fn source_address(stack: &Stack, dest: IpAddr) -> Option<IpAddr> {
    let mut choices: Vec<_> = stack
        .addresses()
        .iter()
        .copied()
        .filter(|a| a.is_ipv4() == dest.is_ipv4())
        .filter(|a| match (a, dest) {
            (IpAddr::V6(a), IpAddr::V6(d)) => {
                crate::wire::link_local(*a) == crate::wire::link_local(d)
            }
            _ => true,
        })
        .collect();
    choices.sort_by_key(|a| match a {
        IpAddr::V6(a) => a.segments()[0] & 0xe000 != 0x2000,
        _ => false,
    });
    choices.into_iter().next()
}
