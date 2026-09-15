//! mDNS datagrams after IP reassembly; multicast and unicast policy lives in the engine.
use crate::{
    dns::wire::{Context, Message},
    ipv4, wire, Link,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or excessive mDNS datagram",
    )
}
pub fn multicast(v6: bool) -> IpAddr {
    if v6 {
        "ff02::fb".parse().unwrap()
    } else {
        "224.0.0.251".parse().unwrap()
    }
}
#[derive(Clone)]
pub struct Datagram {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub message: Message,
}
impl Datagram {
    pub fn parse(link: Link, packet: &[u8]) -> io::Result<Self> {
        if link != Link::Ail || packet.len() > 9000 {
            return Err(invalid());
        }
        let (source, destination, udp) = match packet.first().map(|b| b >> 4) {
            Some(4) => {
                let p = ipv4::wire::Packet::parse(packet)?;
                if p.bytes.len() != packet.len()
                    || p.ttl != 255
                    || p.protocol != 17
                    || p.more_fragments
                    || p.fragment_offset != 0
                {
                    return Err(invalid());
                }
                (IpAddr::V4(p.source), IpAddr::V4(p.destination), p.payload)
            }
            Some(6) => {
                let p = wire::envelope(wire::FrameKind::RawIpv6, packet).map_err(|_| invalid())?;
                let t = wire::transport(&p).map_err(|_| invalid())?;
                if p.packet.len() != packet.len()
                    || p.hop_limit != 255
                    || t.protocol != 17
                    || t.fragmented
                {
                    return Err(invalid());
                }
                (IpAddr::V6(p.source), IpAddr::V6(p.destination), t.bytes)
            }
            _ => return Err(invalid()),
        };
        if !unicast(source)
            || destination.is_unspecified()
            || (destination.is_multicast() && destination != multicast(source.is_ipv6()))
            || udp.len() < 20
        {
            return Err(invalid());
        }
        let source = SocketAddr::new(source, u16::from_be_bytes([udp[0], udp[1]]));
        let destination = SocketAddr::new(destination, u16::from_be_bytes([udp[2], udp[3]]));
        if source.port() == 0
            || destination.port() == 0
            || usize::from(u16::from_be_bytes([udp[4], udp[5]])) != udp.len()
        {
            return Err(invalid());
        }
        let check = u16::from_be_bytes([udp[6], udp[7]]);
        if (check == 0 && source.is_ipv6())
            || (check != 0 && udp_checksum(source.ip(), destination.ip(), udp)? != 0)
        {
            return Err(invalid());
        }
        counts(&udp[8..])?;
        let message = Message::parse(&udp[8..], Context::Mdns)?;
        if message.flags & 0x780f != 0
            || (message.flags & 0x8000 != 0 && source.port() != 5353)
            || (message.flags & 0x8000 == 0 && destination.port() != 5353)
        {
            return Err(invalid());
        }
        Ok(Self {
            source,
            destination,
            message,
        })
    }
}
fn counts(b: &[u8]) -> io::Result<()> {
    if b.len() < 12 {
        return Err(invalid());
    }
    let n = |at| usize::from(u16::from_be_bytes([b[at], b[at + 1]]));
    if n(4) > 128 || n(6) + n(8) + n(10) > 512 {
        return Err(invalid());
    }
    Ok(())
}
fn unicast(a: IpAddr) -> bool {
    match a {
        IpAddr::V4(a) => ipv4::unicast(a),
        IpAddr::V6(a) => {
            !a.is_unspecified()
                && !a.is_multicast()
                && !a.is_loopback()
                && a.to_ipv4_mapped().is_none()
        }
    }
}
pub fn encode(
    source: SocketAddr,
    destination: SocketAddr,
    message: &Message,
) -> io::Result<Vec<u8>> {
    if !unicast(source.ip())
        || source.port() == 0
        || destination.port() == 0
        || source.is_ipv6() != destination.is_ipv6()
        || destination.ip().is_unspecified()
        || (destination.ip().is_multicast() && destination.ip() != multicast(source.is_ipv6()))
        || message.flags & 0x780f != 0
        || (message.flags & 0x8000 == 0 && destination.port() != 5353)
        || (message.flags & 0x8000 != 0 && source.port() != 5353)
    {
        return Err(invalid());
    }
    if message.questions.len() > 128
        || message.answers.len() + message.authority.len() + message.additional.len() > 512
    {
        return Err(invalid());
    }
    let body = message.encode_context(if destination.port() == 5353 {
        Context::Mdns
    } else {
        Context::Unicast
    })?;
    if body.len() + 8 + if source.is_ipv6() { 40 } else { 20 } > 9000 {
        return Err(invalid());
    }
    let mut udp = source.port().to_be_bytes().to_vec();
    udp.extend(destination.port().to_be_bytes());
    udp.extend(((body.len() + 8) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(body);
    let checksum = udp_checksum(source.ip(), destination.ip(), &udp)?;
    udp[6..8].copy_from_slice(&if checksum == 0 { u16::MAX } else { checksum }.to_be_bytes());
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => ipv4::wire::encode(s, d, 17, 255, &udp),
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            wire::ipv6_packet(s, d, 17, 255, &udp).map_err(|_| invalid())
        }
        _ => Err(invalid()),
    }
}
fn udp_checksum(source: IpAddr, destination: IpAddr, udp: &[u8]) -> io::Result<u16> {
    match (source, destination) {
        (IpAddr::V6(s), IpAddr::V6(d)) => Ok(wire::checksum(s, d, 17, udp)),
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut pseudo = Vec::with_capacity(12 + udp.len());
            pseudo.extend(s.octets());
            pseudo.extend(d.octets());
            pseudo.extend([0, 17]);
            pseudo.extend((udp.len() as u16).to_be_bytes());
            pseudo.extend(udp);
            Ok(ipv4::wire::checksum(&pseudo))
        }
        _ => Err(invalid()),
    }
}
