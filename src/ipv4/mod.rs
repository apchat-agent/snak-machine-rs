pub mod wire;
use std::{collections::BTreeMap, io, net::Ipv4Addr};
use wire::{Arp, Packet};
#[derive(Clone, Debug)]
struct Neighbor {
    mac: Option<[u8; 6]>,
    deadline: u64,
    attempts: u8,
    queue: Vec<Vec<u8>>,
}
pub struct Ipv4 {
    pub mac: [u8; 6],
    pub address: Option<(Ipv4Addr, u8)>,
    pub gateway: Option<Ipv4Addr>,
    neighbors: BTreeMap<Ipv4Addr, Neighbor>,
}
impl Default for Ipv4 {
    fn default() -> Self {
        Self::new([2, 0, 0, 0, 0, 1])
    }
}
impl Ipv4 {
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            mac,
            address: None,
            gateway: None,
            neighbors: BTreeMap::new(),
        }
    }
    pub fn configure(
        &mut self,
        address: Ipv4Addr,
        length: u8,
        gateway: Option<Ipv4Addr>,
    ) -> io::Result<()> {
        if length > 32
            || !unicast(address)
            || gateway.is_some_and(|g| !unicast(g) || !same_prefix(address, g, length))
        {
            return Err(io::Error::other("invalid IPv4 address/route"));
        }
        self.address = Some((address, length));
        self.gateway = gateway;
        self.neighbors.clear();
        Ok(())
    }
    pub fn unavailable(&mut self) {
        self.address = None;
        self.gateway = None;
        self.neighbors.clear();
    }
    pub fn next_hop(&self, destination: Ipv4Addr) -> Option<Ipv4Addr> {
        let (address, length) = self.address?;
        if !unicast(destination) {
            return None;
        }
        if length < 31 {
            let mask = u32::MAX.checked_shr(length as u32).unwrap_or(0);
            if same_prefix(address, destination, length)
                && (u32::from(destination) & mask == mask || u32::from(destination) & mask == 0)
            {
                return None;
            }
        }
        if same_prefix(address, destination, length) {
            Some(destination)
        } else {
            self.gateway
        }
    }
    fn probe(&self, destination: Ipv4Addr) -> Vec<u8> {
        Arp {
            operation: 1,
            sender_mac: self.mac,
            sender: self.address.unwrap().0,
            target_mac: [0; 6],
            target: destination,
        }
        .encode([255; 6])
    }
    pub fn send(&mut self, packet: &[u8], now: u64) -> io::Result<Vec<Vec<u8>>> {
        let p = Packet::parse(packet)?;
        let next = self
            .next_hop(p.destination)
            .ok_or_else(|| io::Error::other("IPv4 destination unreachable"))?;
        if let Some(n) = self.neighbors.get(&next) {
            if n.deadline > now {
                if let Some(mac) = n.mac {
                    return Ok(vec![ethernet(self.mac, mac, p.bytes)]);
                }
            }
        }
        self.neighbors
            .retain(|_, n| n.mac.is_none() || n.deadline > now);
        let packets: usize = self.neighbors.values().map(|n| n.queue.len()).sum();
        let bytes: usize = self
            .neighbors
            .values()
            .flat_map(|n| &n.queue)
            .map(Vec::len)
            .sum();
        if (!self.neighbors.contains_key(&next) && self.neighbors.len() >= 256)
            || packets >= 64
            || bytes + packet.len() > 256 * 1024
            || self
                .neighbors
                .get(&next)
                .is_some_and(|n| n.queue.len() >= 4)
        {
            return Err(io::Error::other("IPv4 neighbor/queue capacity"));
        }
        let first = !self.neighbors.contains_key(&next);
        let n = self.neighbors.entry(next).or_insert(Neighbor {
            mac: None,
            deadline: now + 1000,
            attempts: 1,
            queue: vec![],
        });
        n.queue.push(p.bytes.to_vec());
        Ok(if first {
            vec![self.probe(next)]
        } else {
            vec![]
        })
    }
    pub fn receive(&mut self, frame: &[u8], now: u64) -> io::Result<Vec<Vec<u8>>> {
        let Some((address, length)) = self.address else {
            return Ok(vec![]);
        };
        let Ok(a) = Arp::parse(frame) else {
            return Ok(vec![]);
        };
        if a.sender_mac == self.mac
            || a.sender == address
            || a.target != address
            || (!a.sender.is_unspecified() && !same_prefix(address, a.sender, length))
        {
            return Ok(vec![]);
        }
        let mut out = vec![];
        if !a.sender.is_unspecified()
            && (self.neighbors.contains_key(&a.sender) || a.operation == 1)
        {
            if self.neighbors.contains_key(&a.sender) || self.neighbors.len() < 256 {
                let n = self.neighbors.entry(a.sender).or_insert(Neighbor {
                    mac: None,
                    deadline: now,
                    attempts: 0,
                    queue: vec![],
                });
                for packet in std::mem::take(&mut n.queue) {
                    out.push(ethernet(self.mac, a.sender_mac, &packet));
                }
                n.mac = Some(a.sender_mac);
                n.deadline = now.saturating_add(60000);
                n.attempts = 0;
            }
        }
        if a.operation == 1 {
            out.push(
                Arp {
                    operation: 2,
                    sender_mac: self.mac,
                    sender: address,
                    target_mac: a.sender_mac,
                    target: a.sender,
                }
                .encode(a.sender_mac),
            );
        }
        Ok(out)
    }
    pub fn poll(&mut self, now: u64) -> Vec<Vec<u8>> {
        let mut destinations = vec![];
        self.neighbors.retain(|ip, n| {
            if now < n.deadline {
                return true;
            }
            if n.mac.is_some() || n.attempts >= 3 {
                return false;
            }
            n.attempts += 1;
            n.deadline = now.saturating_add(1000);
            destinations.push(*ip);
            true
        });
        destinations.into_iter().map(|ip| self.probe(ip)).collect()
    }
    pub fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }
    pub fn queued(&self) -> (usize, usize) {
        (
            self.neighbors.values().map(|n| n.queue.len()).sum(),
            self.neighbors
                .values()
                .flat_map(|n| &n.queue)
                .map(Vec::len)
                .sum(),
        )
    }
}
fn ethernet(source: [u8; 6], destination: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut b = destination.to_vec();
    b.extend(source);
    b.extend([8, 0]);
    b.extend(payload);
    b
}
pub fn unicast(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !ip.is_loopback()
        && ip.octets()[0] != 0
        && ip.octets()[0] < 240
}
fn same_prefix(a: Ipv4Addr, b: Ipv4Addr, length: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - length as u32).unwrap_or(0);
    u32::from(a) & mask == u32::from(b) & mask
}
