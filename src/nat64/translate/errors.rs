use super::*;
use crate::nat64::icmp;
impl Translator {
    fn allow_error(&mut self, now: u64) -> bool {
        if now.saturating_sub(self.error_window) >= 1000 {
            self.error_window = now;
            self.error_count = 0;
        }
        if self.error_count == 32 {
            return false;
        }
        self.error_count += 1;
        true
    }
    pub(super) fn error4(&mut self, p: &ipv4::wire::Packet<'_>, now: u64) -> io::Result<Vec<Tx>> {
        let b = p.payload;
        if b.len() < 8 || ipv4::wire::checksum(b) != 0 {
            return Err(invalid());
        }
        if self.ipv4 != Some(p.destination) || !ipv4::unicast(p.source) {
            return Ok(vec![]);
        }
        let (quoted, extension) = split_extensions(b, true)?;
        let q = ipv4::wire::Packet::quoted(quoted)?;
        if q.payload.len() < 8 {
            return Err(invalid());
        }
        let value = if b[0] == 12 {
            u32::from(b[4])
        } else {
            u32::from(u16::from_be_bytes([b[6], b[7]]))
        };
        let Some((kind, code, value)) = icmp::v4_to_v6(
            b[0],
            b[1],
            value,
            u32::from(u16::from_be_bytes([b[10], b[11]])),
            self.mtus[0],
            self.mtus[1],
        ) else {
            return Ok(vec![]);
        };
        if q.source != p.destination || !ipv4::unicast(q.destination) || q.fragment_offset != 0 {
            return Ok(vec![]);
        }
        let Some((sport, dport)) = quoted_ports(q.protocol, q.payload) else {
            return Ok(vec![]);
        };
        let remote = SocketAddrV4::new(q.destination, if q.protocol == 1 { 0 } else { dport });
        let Some((host, port)) = self.bindings.error_in(q.protocol, sport, remote, now) else {
            return Ok(vec![]);
        };
        self.bindings.domain = self.bindings.domain_for(q.protocol, sport).unwrap();
        let quote = quote4_to_6(&q, host, self.synthesize(q.destination), port)?;
        let body = join_extensions(kind, code, value, quote, extension, false);
        if !self.allow_error(now) {
            return Ok(vec![]);
        }
        Ok(vec![Tx {
            link: Link::Stub,
            packet: encode6(
                58,
                self.synthesize(p.source),
                host,
                p.traffic_class,
                p.ttl - 1,
                body,
            )?,
        }])
    }
    pub(super) fn error6(&mut self, e: &wire::Envelope<'_>, now: u64) -> io::Result<Vec<Tx>> {
        let b = e.payload;
        if b.len() < 8 || wire::checksum(e.source, e.destination, 58, b) != 0 {
            return Err(invalid());
        }
        let Some(pool) = self.ipv4 else {
            return Ok(vec![]);
        };
        if !crate::wire::Prefix::new(self.bindings.domain, 96)
            .unwrap()
            .contains(e.destination)
            || crate::wire::Prefix::new(self.bindings.domain, 96)
                .unwrap()
                .contains(e.source)
            || e.source.is_multicast()
            || e.source.is_unspecified()
            || e.source.is_loopback()
            || wire::link_local(e.source)
        {
            return Ok(vec![]);
        }
        let (quoted, extension) = split_extensions(b, false)?;
        let q = Quote6::parse(quoted)?;
        if q.non_initial
            || !crate::wire::Prefix::new(self.bindings.domain, 96)
                .unwrap()
                .contains(q.source)
            || q.source != e.destination
        {
            return Ok(vec![]);
        }
        let dest = extract(q.source);
        if !ipv4::unicast(dest) {
            return Ok(vec![]);
        }
        let Some((sport, dport)) = quoted_ports(q.protocol, q.payload) else {
            return Ok(vec![]);
        };
        let protocol = if q.protocol == 58 { 1 } else { q.protocol };
        let remote = SocketAddrV4::new(dest, if protocol == 1 { 0 } else { sport });
        let Some(port) = self
            .bindings
            .error_out(protocol, q.dest, dport, remote, now)
        else {
            return Ok(vec![]);
        };
        let adjustment = if b[0] == 2 && q.fragment.is_some() {
            8
        } else {
            0
        };
        let Some((kind, code, value)) = icmp::v6_to_v4(
            b[0],
            b[1],
            u32::from_be_bytes(b[4..8].try_into().unwrap()).saturating_sub(adjustment),
            self.mtus[0],
            self.mtus[1].saturating_sub(adjustment),
        ) else {
            return Ok(vec![]);
        };
        let quote = quote6_to_4(&q, dest, pool, port)?;
        let body = join_extensions(
            kind,
            code,
            if kind == 12 { value << 24 } else { value },
            quote,
            extension,
            true,
        );
        if dest == pool {
            // Complete exactly one hairpin pass. error4 performs the final
            // tuple validation and rate admission; no recursive input dispatch.
            let packet = ipv4::wire::encode(pool, pool, 1, e.hop_limit, &icmp4_checksum(body))?;
            return self.error4(&ipv4::wire::Packet::parse(&packet)?, now);
        }
        if !self.allow_error(now) {
            return Ok(vec![]);
        }
        Ok(vec![Tx {
            link: Link::Ail,
            packet: ipv4::wire::encode(pool, dest, 1, e.hop_limit - 1, &icmp4_checksum(body))?,
        }])
    }
}
fn extract(a: Ipv6Addr) -> Ipv4Addr {
    Ipv4Addr::from(<[u8; 4]>::try_from(&a.octets()[12..]).unwrap())
}
fn icmp4_checksum(mut b: Vec<u8>) -> Vec<u8> {
    let c = ipv4::wire::checksum(&b);
    b[2..4].copy_from_slice(&c.to_be_bytes());
    b
}
fn quoted_ports(protocol: u8, b: &[u8]) -> Option<(u16, u16)> {
    if b.len() < 8 {
        return None;
    }
    match protocol {
        6 | 17 => Some((
            u16::from_be_bytes([b[0], b[1]]),
            u16::from_be_bytes([b[2], b[3]]),
        )),
        1 | 58
            if b[1] == 0
                && if protocol == 1 {
                    [0, 8].contains(&b[0])
                } else {
                    [128, 129].contains(&b[0])
                } =>
        {
            let id = u16::from_be_bytes([b[4], b[5]]);
            Some((id, id))
        }
        _ => None,
    }
}
struct Quote6<'a> {
    source: Ipv6Addr,
    dest: Ipv6Addr,
    protocol: u8,
    hop: u8,
    class: u8,
    len: usize,
    payload: &'a [u8],
    fragment: Option<(u32, bool)>,
    non_initial: bool,
}
impl<'a> Quote6<'a> {
    fn parse(b: &'a [u8]) -> io::Result<Self> {
        if b.len() < 48 || b[0] >> 4 != 6 {
            return Err(invalid());
        }
        let total = usize::from(u16::from_be_bytes([b[4], b[5]]));
        let (mut protocol, mut offset, problem) = super::headers::transport6(b)?;
        if problem.is_some() {
            return Err(invalid());
        }
        let mut fragment = None;
        let mut non_initial = false;
        if protocol == 44 {
            if offset + 8 > b.len() || b[offset + 1] != 0 {
                return Err(invalid());
            }
            let flags = u16::from_be_bytes([b[offset + 2], b[offset + 3]]);
            if flags & 6 != 0 || [0, 43, 44, 51, 60].contains(&b[offset]) {
                return Err(invalid());
            }
            non_initial = flags & 0xfff8 != 0;
            fragment = Some((
                u32::from_be_bytes(b[offset + 4..offset + 8].try_into().unwrap()),
                flags & 1 != 0,
            ));
            protocol = b[offset];
            offset += 8;
        }
        let len = total.checked_sub(offset - 40).ok_or_else(invalid)?;
        if !(8..=65515).contains(&len) || b.len() < offset + 8 {
            return Err(invalid());
        }
        Ok(Self {
            source: Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap()),
            dest: Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).unwrap()),
            protocol,
            hop: b[7],
            class: ((b[0] & 15) << 4) | (b[1] >> 4),
            len,
            payload: &b[offset..b.len().min(offset + len)],
            fragment,
            non_initial,
        })
    }
}
fn pseudo4(src: Ipv4Addr, dst: Ipv4Addr, p: u8, len: usize) -> Vec<u8> {
    if p == 1 {
        return vec![];
    }
    let mut b = src.octets().to_vec();
    b.extend(dst.octets());
    b.extend([0, p]);
    b.extend((len as u16).to_be_bytes());
    b
}
fn pseudo6(src: Ipv6Addr, dst: Ipv6Addr, p: u8, len: usize) -> Vec<u8> {
    let mut b = src.octets().to_vec();
    b.extend(dst.octets());
    b.extend((len as u32).to_be_bytes());
    b.extend([0, 0, 0, p]);
    b
}
fn adjust(
    p: u8,
    old: &[u8],
    b: &mut [u8],
    mut before: Vec<u8>,
    mut after: Vec<u8>,
    len: usize,
) -> io::Result<()> {
    let at = checksum_offset(p);
    if b.len() < at + 2 {
        return Ok(());
    }
    let c = u16::from_be_bytes([old[at], old[at + 1]]);
    if p == 17 && c == 0 {
        if b.len() != len {
            return Err(invalid());
        }
        after.extend_from_slice(b);
        b[at..at + 2].copy_from_slice(&nonzero(ipv4::wire::checksum(&after)).to_be_bytes());
        return Ok(());
    }
    before.extend(old);
    after.extend_from_slice(b);
    let mut sum = u32::from(!c);
    for chunk in before.chunks(2) {
        sum += u32::from(!u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    for chunk in after.chunks(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]));
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    let c = transport_sum(p, !(sum as u16));
    b[at..at + 2].copy_from_slice(&c.to_be_bytes());
    Ok(())
}
fn quote4_to_6(
    q: &ipv4::wire::Packet<'_>,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    port: u16,
) -> io::Result<Vec<u8>> {
    let len = usize::from(u16::from_be_bytes([q.bytes[2], q.bytes[3]])) - q.header_len;
    let mut b = q.payload.to_vec();
    let p = if q.protocol == 1 { 58 } else { q.protocol };
    if p == 58 {
        b[0] = if b[0] == 8 { 128 } else { 129 };
        b[4..6].copy_from_slice(&port.to_be_bytes());
    } else {
        b[..2].copy_from_slice(&port.to_be_bytes());
    }
    adjust(
        p,
        q.payload,
        &mut b,
        pseudo4(q.source, q.destination, q.protocol, len),
        pseudo6(src, dst, p, len),
        len,
    )?;
    let mut out = wire::ipv6_packet(src, dst, p, q.ttl, &b).map_err(|_| invalid())?;
    out[0] |= q.traffic_class >> 4;
    out[1] = q.traffic_class << 4;
    out[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    if q.more_fragments {
        out[6] = 44;
        out[4..6].copy_from_slice(&u16::try_from(len + 8).map_err(|_| invalid())?.to_be_bytes());
        let mut fragment = vec![p, 0, 0, 1];
        fragment.extend(u32::from(q.id).to_be_bytes());
        out.splice(40..40, fragment);
    }
    Ok(out)
}
fn quote6_to_4(q: &Quote6<'_>, src: Ipv4Addr, dst: Ipv4Addr, port: u16) -> io::Result<Vec<u8>> {
    let mut b = q.payload.to_vec();
    let p = if q.protocol == 58 { 1 } else { q.protocol };
    if p == 1 {
        b[0] = if b[0] == 128 { 8 } else { 0 };
        b[4..6].copy_from_slice(&port.to_be_bytes());
    } else {
        b[2..4].copy_from_slice(&port.to_be_bytes());
    }
    adjust(
        p,
        q.payload,
        &mut b,
        pseudo6(q.source, q.dest, q.protocol, q.len),
        pseudo4(src, dst, p, q.len),
        q.len,
    )?;
    let mut out = ipv4::wire::encode(src, dst, p, q.hop, &b)?;
    out[1] = q.class;
    out[2..4].copy_from_slice(&((q.len + 20) as u16).to_be_bytes());
    if let Some((id, more)) = q.fragment {
        out[4..6].copy_from_slice(&(id as u16).to_be_bytes());
        out[6] = if more { 0x20 } else { 0 };
    } else if q.len + 20 > 1260 {
        out[6] = 0x40;
    }
    out[10..12].fill(0);
    let c = ipv4::wire::checksum(&out[..20]);
    out[10..12].copy_from_slice(&c.to_be_bytes());
    Ok(out)
}
impl Translator {
    pub(super) fn generate6(
        &mut self,
        e: &wire::Envelope<'_>,
        kind: u8,
        code: u8,
        value: u32,
        now: u64,
    ) -> io::Result<Vec<Tx>> {
        if !self.allow_error(now) {
            return Ok(vec![]);
        }
        let mut body = vec![kind, code, 0, 0];
        body.extend(value.to_be_bytes());
        body.extend(e.packet.iter().take(1232));
        Ok(vec![Tx {
            link: Link::Stub,
            packet: encode6(58, e.destination, e.source, 0, 64, body)?,
        }])
    }
    pub(super) fn generate4(
        &mut self,
        p: &ipv4::wire::Packet<'_>,
        kind: u8,
        code: u8,
        value: u32,
        now: u64,
    ) -> io::Result<Vec<Tx>> {
        if !self.allow_error(now) {
            return Ok(vec![]);
        }
        let mut body = vec![kind, code, 0, 0];
        body.extend(value.to_be_bytes());
        body.extend(p.bytes.iter().take(548));
        Ok(vec![Tx {
            link: Link::Ail,
            packet: ipv4::wire::encode(p.destination, p.source, 1, 64, &icmp4_checksum(body))?,
        }])
    }
}
// RFC 4884: the field's units differ by IP family. Never interpret extension
// bytes as quoted transport payload or relocate embedded legacy addresses.
fn split_extensions(b: &[u8], v4: bool) -> io::Result<(&[u8], &[u8])> {
    let supported = if v4 {
        [3, 11, 12].contains(&b[0])
    } else {
        [1, 3].contains(&b[0])
    };
    let units = if supported {
        usize::from(b[if v4 { 5 } else { 4 }])
    } else {
        0
    };
    if units == 0 {
        return Ok((&b[8..], &[]));
    }
    let len = units * if v4 { 4 } else { 8 };
    if len < 128 || 8 + len + 8 > b.len() {
        return Err(invalid());
    }
    let extension = &b[8 + len..];
    if extension[0] >> 4 != 2
        || extension.len() % 4 != 0
        || (extension[2..4] != [0, 0] && ipv4::wire::checksum(extension) != 0)
    {
        return Err(invalid());
    }
    let mut at = 4;
    while at < extension.len() {
        if at + 4 > extension.len() {
            return Err(invalid());
        }
        let n = usize::from(u16::from_be_bytes([extension[at], extension[at + 1]]));
        if n < 4 || n % 4 != 0 || at + n > extension.len() {
            return Err(invalid());
        }
        at += n;
    }
    Ok((&b[8..8 + len], extension))
}
fn join_extensions(
    kind: u8,
    code: u8,
    value: u32,
    mut quote: Vec<u8>,
    extension: &[u8],
    v4: bool,
) -> Vec<u8> {
    let mut body = vec![kind, code, 0, 0];
    body.extend(value.to_be_bytes());
    let cap = if v4 { 548 } else { 1232 };
    let unit = if v4 { 4 } else { 8 };
    let padded = quote.len().max(128).div_ceil(unit) * unit;
    let supported = if v4 {
        [3, 11, 12].contains(&kind)
    } else {
        [1, 3].contains(&kind)
    };
    // RFC 7915 permits truncating an extension that cannot fit. Types without
    // an RFC 4884 length field must use the ordinary bounded quote format.
    if supported && !extension.is_empty() && padded + extension.len() <= cap && padded / unit <= 255
    {
        body[if v4 { 5 } else { 4 }] = (padded / unit) as u8;
        quote.resize(padded, 0);
        body.extend(quote);
        body.extend(extension);
    } else {
        body.extend(quote.into_iter().take(cap));
    }
    body
}
