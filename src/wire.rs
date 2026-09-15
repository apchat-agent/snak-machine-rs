use std::net::Ipv6Addr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameKind {
    Ethernet,
    RawIpv6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Truncated,
    Invalid,
    Unsupported,
    Capacity,
}
#[derive(Debug)]
pub struct Envelope<'a> {
    pub packet: &'a [u8],
    pub payload: &'a [u8],
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
}
pub fn envelope(kind: FrameKind, frame: &[u8]) -> Result<Envelope<'_>, WireError> {
    let p = match kind {
        FrameKind::RawIpv6 => frame,
        FrameKind::Ethernet => {
            if frame.len() < 14 {
                return Err(WireError::Truncated);
            }
            if frame[12..14] != [0x86, 0xdd] {
                return Err(WireError::Unsupported);
            }
            &frame[14..]
        }
    };
    if p.len() < 40 {
        return Err(WireError::Truncated);
    }
    if p[0] >> 4 != 6 {
        return Err(WireError::Invalid);
    }
    let end = 40 + u16::from_be_bytes([p[4], p[5]]) as usize;
    let packet = p.get(..end).ok_or(WireError::Truncated)?;
    Ok(Envelope {
        packet,
        payload: &packet[40..],
        source: Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap()),
        destination: Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap()),
        next_header: p[6],
        hop_limit: p[7],
    })
}

pub fn link_local(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}
pub fn solicited_node(a: Ipv6Addr) -> Ipv6Addr {
    Ipv6Addr::from(0xff0200000000000000000001ff000000u128 | (u128::from(a) & 0xffffff))
}
pub fn checksum(source: Ipv6Addr, destination: Ipv6Addr, next: u8, data: &[u8]) -> u16 {
    fn add(n: &mut u32, b: &[u8]) {
        for p in b.chunks(2) {
            *n += ((p[0] as u32) << 8) | *p.get(1).unwrap_or(&0) as u32;
        }
    }
    let mut n = 0;
    add(&mut n, &source.octets());
    add(&mut n, &destination.octets());
    add(&mut n, &(data.len() as u32).to_be_bytes());
    n += next as u32;
    add(&mut n, data);
    while n >> 16 != 0 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
#[derive(Debug)]
pub struct Transport<'a> {
    pub protocol: u8,
    pub bytes: &'a [u8],
    pub fragmented: bool,
}
pub fn transport<'a>(e: &Envelope<'a>) -> Result<Transport<'a>, WireError> {
    let mut next = e.next_header;
    let mut p = e.payload;
    let mut fragmented = false;
    for _ in 0..16 {
        let n = match next {
            0 | 43 | 60 => {
                if p.len() < 2 {
                    return Err(WireError::Truncated);
                }
                (p[1] as usize + 1) * 8
            }
            44 => {
                fragmented = true;
                8
            }
            51 => {
                if p.len() < 2 {
                    return Err(WireError::Truncated);
                }
                (p[1] as usize + 2) * 4
            }
            _ => {
                return Ok(Transport {
                    protocol: next,
                    bytes: p,
                    fragmented,
                })
            }
        };
        if p.len() < n {
            return Err(WireError::Truncated);
        }
        let nonfirst = next == 44 && u16::from_be_bytes([p[2], p[3]]) & 0xfff8 != 0;
        next = p[0];
        p = &p[n..];
        if nonfirst {
            return Ok(Transport {
                protocol: next,
                bytes: p,
                fragmented,
            });
        }
    }
    Err(WireError::Invalid)
}
#[derive(Clone, Copy, Debug)]
pub struct NdOption<'a> {
    pub kind: u8,
    pub bytes: &'a [u8],
}
#[derive(Debug)]
pub struct Nd<'a> {
    pub kind: u8,
    pub body: &'a [u8],
    pub options: Vec<NdOption<'a>>,
}
pub fn decode_nd<'a>(e: &Envelope<'a>) -> Result<Nd<'a>, WireError> {
    let t = transport(e)?;
    let b = t.bytes;
    if t.protocol != 58
        || t.fragmented
        || e.hop_limit != 255
        || b.len() < 4
        || b[1] != 0
        || checksum(e.source, e.destination, 58, b) != 0
    {
        return Err(WireError::Invalid);
    }
    let base = match b[0] {
        133 => 8,
        134 => 16,
        135 | 136 => 24,
        _ => return Err(WireError::Unsupported),
    };
    if b.len() < base {
        return Err(WireError::Truncated);
    }
    if b[0] == 134 && !link_local(e.source) {
        return Err(WireError::Invalid);
    }
    if e.source.is_multicast() {
        return Err(WireError::Invalid);
    }
    let mut options = Vec::new();
    let mut rest = &b[base..];
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(WireError::Truncated);
        }
        let n = rest[1] as usize * 8;
        if n == 0 || n > rest.len() {
            return Err(WireError::Invalid);
        }
        options.push(NdOption {
            kind: rest[0],
            bytes: &rest[..n],
        });
        rest = &rest[n..];
    }
    if (b[0] == 133 || b[0] == 135)
        && e.source.is_unspecified()
        && options.iter().any(|o| o.kind == 1)
    {
        return Err(WireError::Invalid);
    }
    if b[0] >= 135 {
        let target = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).unwrap());
        if target.is_multicast() || target.is_unspecified() {
            return Err(WireError::Invalid);
        }
        if b[0] == 135 && e.source.is_unspecified() && e.destination != solicited_node(target) {
            return Err(WireError::Invalid);
        }
        if b[0] == 136
            && (e.source.is_unspecified() || (e.destination.is_multicast() && b[4] & 0x40 != 0))
        {
            return Err(WireError::Invalid);
        }
    }
    Ok(Nd {
        kind: b[0],
        body: b,
        options,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Prefix {
    pub address: Ipv6Addr,
    pub length: u8,
}
impl Prefix {
    pub fn new(address: Ipv6Addr, length: u8) -> Option<Self> {
        if length > 128 {
            return None;
        }
        let mask = if length == 0 {
            0
        } else {
            u128::MAX << (128 - length)
        };
        Some(Self {
            address: Ipv6Addr::from(u128::from(address) & mask),
            length,
        })
    }
    pub fn contains(self, address: Ipv6Addr) -> bool {
        Self::new(address, self.length) == Some(self)
    }
    pub fn ula(self) -> bool {
        self.address.octets()[0] & 0xfe == 0xfc
    }
    pub fn routable(self) -> bool {
        self.length > 0
            && !link_local(self.address)
            && !self.address.is_multicast()
            && !self.address.is_unspecified()
            && !self.address.is_loopback()
    }
}
pub fn u32_at(b: &[u8], n: usize) -> u32 {
    u32::from_be_bytes(b[n..n + 4].try_into().unwrap())
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pio {
    pub prefix: Prefix,
    pub flags: u8,
    pub preferred: u32,
    pub valid: u32,
}
impl Pio {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 32 || b[0] != 3 || b[1] != 4 {
            return None;
        }
        Some(Self {
            prefix: Prefix::new(Ipv6Addr::from(<[u8; 16]>::try_from(&b[16..32]).ok()?), b[2])?,
            flags: b[3],
            preferred: u32_at(b, 8),
            valid: u32_at(b, 4),
        })
    }
    pub fn on_link(self) -> bool {
        self.flags & 0x80 != 0
    }
    pub fn suitable(self) -> bool {
        self.prefix.length == 64
            && self.prefix.routable()
            && self.on_link()
            && self.flags & 0x50 != 0
            && self.preferred >= 1800
            && self.preferred <= self.valid
    }
    pub fn encode(self) -> Vec<u8> {
        let mut b = vec![3, 4, self.prefix.length, self.flags];
        b.extend(self.valid.to_be_bytes());
        b.extend(self.preferred.to_be_bytes());
        b.extend([0; 4]);
        b.extend(self.prefix.address.octets());
        b
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Preference {
    Low,
    Medium,
    High,
}
impl Preference {
    pub fn decode(flags: u8) -> Option<Self> {
        match flags & 0x18 {
            0 => Some(Self::Medium),
            8 => Some(Self::High),
            24 => Some(Self::Low),
            _ => None,
        }
    }
    pub fn bits(self) -> u8 {
        match self {
            Self::Low => 24,
            Self::Medium => 0,
            Self::High => 8,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rio {
    pub prefix: Prefix,
    pub preference: Preference,
    pub lifetime: u32,
}
impl Rio {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 8
            || b[0] != 24
            || !(1..=3).contains(&b[1])
            || b.len() != b[1] as usize * 8
            || b[2] > 128
            || (b[2] > 0 && b[1] < 2)
            || (b[2] > 64 && b[1] < 3)
        {
            return None;
        }
        let mut a = [0; 16];
        a[..b.len() - 8].copy_from_slice(&b[8..]);
        Some(Self {
            prefix: Prefix::new(Ipv6Addr::from(a), b[2])?,
            preference: Preference::decode(b[3])?,
            lifetime: u32_at(b, 4),
        })
    }
    pub fn encode(self) -> Vec<u8> {
        let n = if self.prefix.length == 0 {
            1
        } else if self.prefix.length <= 64 {
            2
        } else {
            3
        };
        let mut b = vec![24, n, self.prefix.length, self.preference.bits()];
        b.extend(self.lifetime.to_be_bytes());
        b.extend(&self.prefix.address.octets()[..(n as usize - 1) * 8]);
        b
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Pref64 {
    pub prefix: Prefix,
    pub lifetime: u32,
}
impl Pref64 {
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != 16 || b[0] != 38 || b[1] != 2 {
            return None;
        }
        let word = u16::from_be_bytes([b[2], b[3]]);
        let length = *[96, 64, 56, 48, 40, 32].get((word & 7) as usize)?;
        let mut a = [0; 16];
        a[..12].copy_from_slice(&b[4..]);
        Some(Self {
            prefix: Prefix::new(Ipv6Addr::from(a), length)?,
            lifetime: (word & 0xfff8) as u32,
        })
    }
}

pub fn ipv6_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next: u8,
    hop: u8,
    payload: &[u8],
) -> Result<Vec<u8>, WireError> {
    let len = u16::try_from(payload.len()).map_err(|_| WireError::Capacity)?;
    let mut b = vec![0; 40];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&len.to_be_bytes());
    b[6] = next;
    b[7] = hop;
    b[8..24].copy_from_slice(&source.octets());
    b[24..40].copy_from_slice(&destination.octets());
    b.extend(payload);
    Ok(b)
}
pub fn icmp_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    hop: u8,
    mut body: Vec<u8>,
) -> Result<Vec<u8>, WireError> {
    if body.len() < 4 {
        return Err(WireError::Invalid);
    }
    body[2] = 0;
    body[3] = 0;
    let c = checksum(source, destination, 58, &body);
    body[2..4].copy_from_slice(&c.to_be_bytes());
    ipv6_packet(source, destination, 58, hop, &body)
}
#[derive(Clone, Debug)]
pub struct Advertisement {
    pub link: crate::Link,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub mac: Option<[u8; 6]>,
    pub mtu: u32,
    pub mo: u8,
    pub default_lifetime: u16,
    pub pios: Vec<Pio>,
    pub rios: Vec<Rio>,
}
impl Advertisement {
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        if self.mtu < 1280 || !link_local(self.source) {
            return Err(WireError::Invalid);
        }
        let ail = self.link == crate::Link::Ail;
        let mut b = vec![134, 0, 0, 0, 0, if ail { 2 | (self.mo & 0xc0) } else { 0 }];
        b.extend(
            if ail {
                0
            } else {
                self.default_lifetime.min(1800)
            }
            .to_be_bytes(),
        );
        b.extend([0; 8]);
        if let Some(mac) = self.mac {
            b.extend([1, 1]);
            b.extend(mac);
        }
        if !ail {
            b.extend([5, 1, 0, 0]);
            b.extend(self.mtu.to_be_bytes());
        }
        let mut pios = self.pios.clone();
        pios.sort_by_key(|p| p.prefix);
        for p in pios {
            b.extend(p.encode());
        }
        let mut rios = self.rios.clone();
        rios.sort_by_key(|r| r.prefix);
        rios.dedup_by_key(|r| r.prefix);
        for r in rios {
            b.extend(r.encode());
        }
        if b.len() + 40 > 1280 {
            return Err(WireError::Capacity);
        }
        icmp_packet(self.source, self.destination, 255, b)
    }
}
pub mod dhcpv6;
