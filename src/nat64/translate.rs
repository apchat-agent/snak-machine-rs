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
            || e.next_header != 17
            || e.hop_limit <= 1
            || e.payload.len() > 65515
        {
            return Err(invalid());
        }
        let (sport, dport) = udp(e.payload)?;
        if e.payload[6..8] == [0, 0] || wire::checksum(e.source, e.destination, 17, e.payload) != 0
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
        let assigned = self.bindings.udp_out(
            e.source,
            sport,
            SocketAddrV4::new(dest, dport),
            now,
            rng,
            |_| false,
        )?;
        let class = (packet[0] & 15) << 4 | packet[1] >> 4;
        let mut payload = e.payload.to_vec();
        payload[..2].copy_from_slice(&assigned.to_be_bytes());
        if dest == pool {
            // RFC 6146 3.8: apply the outgoing tuple to the inbound filter.
            // This is one router hop; no intermediate IPv4 packet is forwarded.
            let Some((target, port)) =
                self.bindings
                    .udp_in(dport, SocketAddrV4::new(pool, assigned), now)?
            else {
                return Ok(vec![]);
            };
            payload[2..4].copy_from_slice(&port.to_be_bytes());
            return Ok(vec![Tx {
                link: Link::Stub,
                packet: encode6(
                    self.synthesize(pool),
                    target,
                    class,
                    e.hop_limit - 1,
                    payload,
                )?,
            }]);
        }
        payload[6..8].fill(0);
        let sum = checksum4(pool, dest, 17, &payload);
        payload[6..8].copy_from_slice(&nonzero(sum).to_be_bytes());
        let mut out = ipv4::wire::encode(pool, dest, 17, e.hop_limit - 1, &payload)?;
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
            || p.protocol != 17
            || p.fragment_offset != 0
            || p.more_fragments
            || p.ttl <= 1
        {
            return Err(invalid());
        }
        let (sport, dport) = udp(p.payload)?;
        if p.payload[6..8] != [0, 0] && checksum4(p.source, p.destination, 17, p.payload) != 0 {
            return Err(invalid());
        }
        if self.ipv4 != Some(p.destination) || !ipv4::unicast(p.source) {
            return Ok(vec![]);
        }
        let Some((target, port)) =
            self.bindings
                .udp_in(dport, SocketAddrV4::new(p.source, sport), now)?
        else {
            return Ok(vec![]);
        };
        let mut payload = p.payload.to_vec();
        payload[2..4].copy_from_slice(&port.to_be_bytes());
        Ok(vec![Tx {
            link: Link::Stub,
            packet: encode6(
                self.synthesize(p.source),
                target,
                p.traffic_class,
                p.ttl - 1,
                payload,
            )?,
        }])
    }
    fn synthesize(&self, ipv4: Ipv4Addr) -> Ipv6Addr {
        (u128::from(self.prefix.address) | u128::from(u32::from(ipv4))).into()
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
    source: Ipv6Addr,
    dest: Ipv6Addr,
    class: u8,
    hop: u8,
    mut payload: Vec<u8>,
) -> io::Result<Vec<u8>> {
    payload[6..8].fill(0);
    let sum = wire::checksum(source, dest, 17, &payload);
    payload[6..8].copy_from_slice(&nonzero(sum).to_be_bytes());
    let mut out = wire::ipv6_packet(source, dest, 17, hop, &payload).map_err(|_| invalid())?;
    out[0] |= class >> 4;
    out[1] = class << 4;
    Ok(out)
}
