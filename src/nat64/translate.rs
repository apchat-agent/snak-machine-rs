mod errors;
mod headers;
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
    mtus: [u32; 2],
    lowest_ipv6_mtu: u32,
    error_window: u64,
    error_count: u8,
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
            mtus: [1500; 2],
            lowest_ipv6_mtu: 1280,
            error_window: 0,
            error_count: 0,
        })
    }
    pub(crate) fn set_mtus(&mut self, mtus: [u32; 2]) {
        self.mtus = mtus;
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
        self.outbound_datagram(
            &crate::ip_reassembly::Datagram {
                packet: packet.to_vec(),
                fragment_id: None,
            },
            now,
            rng,
            source_allowed,
            reachable,
        )
    }
    pub(crate) fn outbound_datagram(
        &mut self,
        d: &crate::ip_reassembly::Datagram,
        now: u64,
        rng: &mut impl RandomSource,
        source_allowed: impl Fn(Ipv6Addr) -> bool,
        reachable: impl Fn(Ipv4Addr) -> bool,
    ) -> io::Result<Vec<Tx>> {
        let packet = d.packet.as_slice();
        let mut e = wire::envelope(FrameKind::RawIpv6, packet).map_err(|_| invalid())?;
        if e.packet.len() != packet.len() {
            return Err(invalid());
        }
        let (protocol, offset, problem) = headers::transport6(packet)?;
        e.next_header = protocol;
        e.payload = &packet[offset..];
        if e.payload.len() > 65515 {
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
        if protocol == 58 && e.payload.first().is_some_and(|kind| *kind < 128) {
            if e.hop_limit <= 1 || problem.is_some() {
                return Ok(vec![]);
            }
            return self.error6(&e, now);
        }
        if let Some(pointer) = problem {
            return self.generate6(&e, 4, 0, pointer, now);
        }
        if ![6, 17, 58].contains(&protocol) {
            return self.generate6(&e, 1, 4, 0, now);
        }
        let (sport, dport) = ports(protocol, e.payload)?;
        if (protocol == 17 && e.payload[6..8] == [0, 0])
            || wire::checksum(e.source, e.destination, protocol, e.payload) != 0
        {
            return Err(invalid());
        }
        if e.hop_limit <= 1 {
            return self.generate6(&e, 3, 0, 0, now);
        }
        if e.payload.len() + 20 > self.mtus[0] as usize
            && e.payload.len() + 20 > 1260
            && dest != pool
            && d.fragment_id.is_none()
        {
            return self.generate6(&e, 2, 0, self.mtus[0].saturating_add(20).max(1280), now);
        }
        let remote = SocketAddrV4::new(dest, dport);
        let assigned = if protocol == 17 {
            self.bindings
                .udp_out(e.source, sport, remote, now, rng, |_| false)?
        } else if protocol == 58 {
            self.bindings.icmp_out(e.source, sport, dest, now, rng)?
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
        if protocol == 58 {
            payload[4..6].copy_from_slice(&assigned.to_be_bytes());
        } else {
            payload[..2].copy_from_slice(&assigned.to_be_bytes());
        }
        if dest == pool {
            // RFC 6146 3.8: apply the outgoing tuple to the inbound filter.
            // This is one router hop; no intermediate IPv4 packet is forwarded.
            let remote = SocketAddrV4::new(pool, assigned);
            let target = if protocol == 17 {
                self.bindings.udp_in(dport, remote, now)?
            } else if protocol == 58 {
                self.bindings.icmp_in(assigned, pool, now)?
            } else {
                self.bindings.tcp_in(dport, remote, payload[13], now)?
            };
            let Some((target, port)) = target else {
                return Ok(vec![]);
            };
            if protocol == 58 {
                payload[4..6].copy_from_slice(&port.to_be_bytes());
            } else {
                payload[2..4].copy_from_slice(&port.to_be_bytes());
            }
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
        let protocol = if protocol == 58 {
            payload[0] = if payload[0] == 128 { 8 } else { 0 };
            1
        } else {
            protocol
        };
        let at = checksum_offset(protocol);
        payload[at..at + 2].fill(0);
        let sum = checksum4(pool, dest, protocol, &payload);
        payload[at..at + 2].copy_from_slice(&transport_sum(protocol, sum).to_be_bytes());
        let mut out = ipv4::wire::encode(pool, dest, protocol, e.hop_limit - 1, &payload)?;
        out[1] = class;
        out[4..6].copy_from_slice(
            &(d.fragment_id.map_or(self.identification, |id| id as u16)).to_be_bytes(),
        );
        self.identification = self.identification.wrapping_add(1);
        if out.len() > 1260 && d.fragment_id.is_none() {
            out[6] = 0x40;
        }
        out[10..12].fill(0);
        let sum = ipv4::wire::checksum(&out[..20]);
        out[10..12].copy_from_slice(&sum.to_be_bytes());
        let id = u32::from(u16::from_be_bytes([out[4], out[5]]));
        Ok(
            crate::ip_reassembly::fragment(&out, self.mtus[0] as usize, id)?
                .into_iter()
                .map(|packet| Tx {
                    link: Link::Ail,
                    packet,
                })
                .collect(),
        )
    }
    pub fn inbound(&mut self, packet: &[u8], now: u64) -> io::Result<Vec<Tx>> {
        let p = ipv4::wire::Packet::parse(packet)?;
        if p.bytes.len() != packet.len()
            || ![1, 6, 17].contains(&p.protocol)
            || p.fragment_offset != 0
            || p.more_fragments
        {
            return Err(invalid());
        }
        let protocol = p.protocol;
        if protocol == 1 && p.payload.first().is_some_and(|kind| ![0, 8].contains(kind)) {
            if p.ttl <= 1 {
                return Ok(vec![]);
            }
            return self.error4(&p, now);
        }
        let (sport, dport) = ports(protocol, p.payload)?;
        if (protocol != 17 || p.payload[6..8] != [0, 0])
            && checksum4(p.source, p.destination, protocol, p.payload) != 0
        {
            return Err(invalid());
        }
        if self.ipv4 != Some(p.destination) || !ipv4::unicast(p.source) {
            return Ok(vec![]);
        }
        let remote = SocketAddrV4::new(p.source, sport);
        if p.ttl <= 1 || p.dont_fragment && p.payload.len() + 40 > self.mtus[1] as usize {
            let (port, remote) = if protocol == 1 {
                (sport, SocketAddrV4::new(p.source, 0))
            } else {
                (dport, remote)
            };
            if self
                .bindings
                .error_in(protocol, port, remote, now)
                .is_none()
            {
                return Ok(vec![]);
            }
            return if p.ttl <= 1 {
                self.generate4(&p, 11, 0, 0, now)
            } else {
                self.generate4(&p, 3, 4, self.mtus[1].saturating_sub(20).max(68), now)
            };
        }
        let target = if protocol == 17 {
            self.bindings.udp_in(dport, remote, now)?
        } else if protocol == 1 {
            self.bindings.icmp_in(sport, p.source, now)?
        } else {
            self.bindings
                .tcp_in_packet(dport, remote, p.payload[13], now, p.bytes)?
        };
        let Some((target, port)) = target else {
            return Ok(vec![]);
        };
        let mut payload = p.payload.to_vec();
        let protocol = if protocol == 1 {
            payload[4..6].copy_from_slice(&port.to_be_bytes());
            payload[0] = if payload[0] == 8 { 128 } else { 129 };
            58
        } else {
            payload[2..4].copy_from_slice(&port.to_be_bytes());
            protocol
        };
        let out = encode6(
            protocol,
            self.synthesize(p.source),
            target,
            p.traffic_class,
            p.ttl - 1,
            payload,
        )?;
        let mtu = if p.dont_fragment {
            self.mtus[1]
        } else {
            self.mtus[1].min(self.lowest_ipv6_mtu)
        };
        Ok(
            crate::ip_reassembly::fragment(&out, mtu as usize, u32::from(p.id))?
                .into_iter()
                .map(|packet| Tx {
                    link: Link::Stub,
                    packet,
                })
                .collect(),
        )
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
    match protocol {
        6 => super::tcp::ports(b),
        17 => udp(b),
        1 | 58 => {
            let types = if protocol == 1 { [0, 8] } else { [128, 129] };
            if b.len() < 8 || b[1] != 0 || !types.contains(&b[0]) {
                return Err(invalid());
            }
            let id = u16::from_be_bytes([b[4], b[5]]);
            Ok((id, id))
        }
        _ => Err(invalid()),
    }
}
fn checksum_offset(protocol: u8) -> usize {
    if protocol == 6 {
        16
    } else if protocol == 17 {
        6
    } else {
        2
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
    if protocol == 1 {
        return ipv4::wire::checksum(b);
    }
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
