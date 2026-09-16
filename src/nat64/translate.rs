use super::{bindings::Bindings, invalid, usable};
use crate::{
    ipv4,
    router::Tx,
    service_io::ports::Ports,
    time::RandomSource,
    wire::{self, FrameKind, Prefix},
    Link,
};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4},
};
pub struct Translator {
    pub bindings: Bindings,
    prefix: Prefix,
    ipv4: Option<Ipv4Addr>,
    identification: u16,
}
impl Translator {
    pub fn new(prefix: Prefix, ipv4: Ipv4Addr, ports: Ports) -> io::Result<Self> {
        if prefix.length != 96 || !usable(prefix) || !ipv4::unicast(ipv4) {
            return Err(invalid());
        }
        Ok(Self {
            bindings: Bindings::with_ports(ports),
            prefix,
            ipv4: Some(ipv4),
            identification: 0,
        })
    }
    pub fn set_ipv4(&mut self, ipv4: Option<Ipv4Addr>) -> io::Result<()> {
        if ipv4.is_some_and(|a| !ipv4::unicast(a)) {
            return Err(invalid());
        }
        if self.ipv4 != ipv4 {
            self.bindings.clear();
            self.ipv4 = ipv4;
        }
        Ok(())
    }
    pub fn outbound(
        &mut self,
        packet: &[u8],
        now: u64,
        rng: &mut impl RandomSource,
        source_allowed: impl Fn(Ipv6Addr) -> bool,
        reachable: impl Fn(Ipv4Addr) -> bool,
    ) -> io::Result<Vec<Tx>> {
        let e = wire::envelope(FrameKind::RawIpv6, packet).map_err(|_| invalid())?;
        if e.packet.len() != packet.len()
            || ![6, 17].contains(&e.next_header)
            || e.hop_limit <= 1
            || e.payload.len() > 65515
        {
            return Err(invalid());
        }
        let protocol = e.next_header;
        let (sport, dport) = ports(protocol, e.payload)?;
        if (protocol == 17 && e.payload[6..8] == [0, 0])
            || wire::checksum(e.source, e.destination, protocol, e.payload) != 0
        {
            return Err(invalid());
        }
        let Some(pool) = self.ipv4 else {
            return Ok(vec![]);
        };
        if !source_allowed(e.source)
            || e.source.is_unspecified()
            || e.source.is_loopback()
            || e.source.is_multicast()
            || wire::link_local(e.source)
            || e.source.to_ipv4_mapped().is_some()
            || self.prefix.contains(e.source)
            || !self.prefix.contains(e.destination)
        {
            return Ok(vec![]);
        }
        let dest = Ipv4Addr::from(<[u8; 4]>::try_from(&e.destination.octets()[12..]).unwrap());
        if !ipv4::unicast(dest) || (dest != pool && !reachable(dest)) {
            return Ok(vec![]);
        }
        let remote = SocketAddrV4::new(dest, dport);
        let assigned = if protocol == 17 {
            self.bindings
                .udp_out(e.source, sport, remote, now, rng, |_| false)?
        } else {
            let Some(port) =
                self.bindings
                    .tcp_out(e.source, sport, remote, e.payload[13], now, rng)?
            else {
                return Ok(vec![]);
            };
            port
        };
        let class = (packet[0] & 15) << 4 | packet[1] >> 4;
        let mut payload = e.payload.to_vec();
        payload[..2].copy_from_slice(&assigned.to_be_bytes());
        if dest == pool {
            // RFC 6146 3.8: apply the outgoing tuple to the inbound filter.
            // This is one router hop; no intermediate IPv4 packet is forwarded.
            let remote = SocketAddrV4::new(pool, assigned);
            let target = if protocol == 17 {
                self.bindings.udp_in(dport, remote, now)?
            } else {
                self.bindings.tcp_in(dport, remote, payload[13], now)?
            };
            let Some((target, port)) = target else {
                return Ok(vec![]);
            };
            payload[2..4].copy_from_slice(&port.to_be_bytes());
            return Ok(vec![Tx {
                link: Link::Stub,
                packet: encode6(
                    protocol,
                    self.synthesize(pool),
                    target,
                    class,
                    e.hop_limit - 1,
                    payload,
                )?,
            }]);
        }
        let at = checksum_offset(protocol);
        payload[at..at + 2].fill(0);
        let sum = checksum4(pool, dest, protocol, &payload);
        payload[at..at + 2].copy_from_slice(&transport_sum(protocol, sum).to_be_bytes());
        let mut out = ipv4::wire::encode(pool, dest, protocol, e.hop_limit - 1, &payload)?;
        out[1] = class;
        out[4..6].copy_from_slice(&self.identification.to_be_bytes());
        self.identification = self.identification.wrapping_add(1);
        if out.len() > 1260 {
            out[6] = 0x40;
        }
        out[10..12].fill(0);
        let sum = ipv4::wire::checksum(&out[..20]);
        out[10..12].copy_from_slice(&sum.to_be_bytes());
        Ok(vec![Tx {
            link: Link::Ail,
            packet: out,
        }])
    }
    pub fn inbound(&mut self, packet: &[u8], now: u64) -> io::Result<Vec<Tx>> {
        let p = ipv4::wire::Packet::parse(packet)?;
        if p.bytes.len() != packet.len()
            || ![6, 17].contains(&p.protocol)
            || p.fragment_offset != 0
            || p.more_fragments
            || p.ttl <= 1
        {
            return Err(invalid());
        }
        let protocol = p.protocol;
        let (sport, dport) = ports(protocol, p.payload)?;
        if (protocol == 6 || p.payload[6..8] != [0, 0])
            && checksum4(p.source, p.destination, protocol, p.payload) != 0
        {
            return Err(invalid());
        }
        if self.ipv4 != Some(p.destination) || !ipv4::unicast(p.source) {
            return Ok(vec![]);
        }
        let remote = SocketAddrV4::new(p.source, sport);
        let target = if protocol == 17 {
            self.bindings.udp_in(dport, remote, now)?
        } else {
            self.bindings.tcp_in(dport, remote, p.payload[13], now)?
        };
        let Some((target, port)) = target else {
            return Ok(vec![]);
        };
        if protocol == 6 && p.payload[13] & 2 != 0 {
            self.bindings.remember_tcp_syn(dport, remote, p.bytes);
        }
        let mut payload = p.payload.to_vec();
        payload[2..4].copy_from_slice(&port.to_be_bytes());
        Ok(vec![Tx {
            link: Link::Stub,
            packet: encode6(
                protocol,
                self.synthesize(p.source),
                target,
                p.traffic_class,
                p.ttl - 1,
                payload,
            )?,
        }])
    }
    pub fn poll(&mut self, now: u64) -> io::Result<Vec<Tx>> {
        self.bindings.expire(now);
        let Some(pool) = self.ipv4 else {
            return Ok(vec![]);
        };
        let mut output = vec![];
        for (source, port, _, remote) in self.bindings.take_tcp_probes(32) {
            let mut tcp = vec![0; 20];
            tcp[..2].copy_from_slice(&remote.port().to_be_bytes());
            tcp[2..4].copy_from_slice(&port.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = 16;
            output.push(Tx {
                link: Link::Stub,
                packet: encode6(6, self.synthesize(*remote.ip()), source, 0, 64, tcp)?,
            });
        }
        for quote in self.bindings.take_tcp_timeouts(32 - output.len()) {
            let p = ipv4::wire::Packet::quoted(&quote)?;
            let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
            icmp.extend(&quote);
            let sum = ipv4::wire::checksum(&icmp);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            output.push(Tx {
                link: Link::Ail,
                packet: ipv4::wire::encode(pool, p.source, 1, 64, &icmp)?,
            });
        }
        Ok(output)
    }
    fn synthesize(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        (u128::from(self.prefix.address) | u128::from(u32::from(ipv4))).into()
    }
}
fn ports(protocol: u8, b: &[u8]) -> io::Result<(u16, u16)> {
    if protocol == 6 {
        super::tcp::ports(b)
    } else {
        udp(b)
    }
}
fn checksum_offset(protocol: u8) -> usize {
    if protocol == 6 {
        16
    } else {
        6
    }
}
fn transport_sum(protocol: u8, sum: u16) -> u16 {
    if protocol == 17 {
        nonzero(sum)
    } else {
        sum
    }
}
fn udp(b: &[u8]) -> io::Result<(u16, u16)> {
    if b.len() < 8 || usize::from(u16::from_be_bytes([b[4], b[5]])) != b.len() {
        return Err(invalid());
    }
    let source = u16::from_be_bytes([b[0], b[1]]);
    let dest = u16::from_be_bytes([b[2], b[3]]);
    if dest == 0 {
        return Err(invalid());
    }
    Ok((source, dest))
}
fn checksum4(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, b: &[u8]) -> u16 {
    let mut pseudo = source.octets().to_vec();
    pseudo.extend(destination.octets());
    pseudo.extend([0, protocol]);
    pseudo.extend((b.len() as u16).to_be_bytes());
    pseudo.extend(b);
    ipv4::wire::checksum(&pseudo)
}
fn nonzero(value: u16) -> u16 {
    if value == 0 {
        65535
    } else {
        value
    }
}
fn encode6(
    protocol: u8,
    source: Ipv6Addr,
    dest: Ipv6Addr,
    class: u8,
    hop: u8,
    mut payload: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let at = checksum_offset(protocol);
    payload[at..at + 2].fill(0);
    let sum = wire::checksum(source, dest, protocol, &payload);
    payload[at..at + 2].copy_from_slice(&transport_sum(protocol, sum).to_be_bytes());
    let mut out =
        wire::ipv6_packet(source, dest, protocol, hop, &payload).map_err(|_| invalid())?;
    out[0] |= class >> 4;
    out[1] = class << 4;
    Ok(out)
}
