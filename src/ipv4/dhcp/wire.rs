//! Checked DHCPv4 replies. Limits apply before allocating concatenated options.
use super::{Configuration, Lease};
use crate::ipv4::{
    unicast,
    wire::{checksum, Packet},
    Route,
};
use std::{collections::BTreeMap, io, net::Ipv4Addr};
pub const OPTION_BYTES: usize = 4096;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DHCPv4 reply")
}
fn ip(b: &[u8]) -> io::Result<Ipv4Addr> {
    let a: [u8; 4] = b.try_into().map_err(|_| invalid())?;
    Ok(a.into())
}
#[derive(Clone, Debug)]
pub struct Message {
    pub kind: u8,
    pub xid: u32,
    pub mac: [u8; 6],
    pub address: Ipv4Addr,
    pub server: Ipv4Addr,
    options: BTreeMap<u8, Vec<u8>>,
}
impl Message {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > OPTION_BYTES + 300 {
            return Err(invalid());
        }
        let p = Packet::parse(bytes)?;
        if p.protocol != 17
            || p.ttl == 0
            || p.fragment_offset != 0
            || p.more_fragments
            || p.payload.len() < 248
            || !unicast(p.source)
        {
            return Err(invalid());
        }
        let udp = p.payload;
        if udp[..4] != [0, 67, 0, 68] || u16::from_be_bytes([udp[4], udp[5]]) as usize != udp.len()
        {
            return Err(invalid());
        }
        if udp[6..8] != [0, 0] {
            let mut pseudo = p.source.octets().to_vec();
            pseudo.extend(p.destination.octets());
            pseudo.extend([0, 17]);
            pseudo.extend((udp.len() as u16).to_be_bytes());
            pseudo.extend(udp);
            if checksum(&pseudo) != 0 {
                return Err(invalid());
            }
        }
        let b = &udp[8..];
        if b[..3] != [2, 1, 6]
            || b[236..240] != [99, 130, 83, 99]
            || b[28] & 1 != 0
            || b[28..34] == [0; 6]
            || b[10] & 0x7f != 0
            || b[11] != 0
        {
            return Err(invalid());
        }
        let mut options = BTreeMap::new();
        let mut budget = 0;
        parse_options(&b[240..], &mut options, &mut budget, false)?;
        if let Some(o) = options.get(&52) {
            if o.len() != 1 || !(1..=3).contains(&o[0]) {
                return Err(invalid());
            }
            let flags = o[0];
            if flags & 1 != 0 {
                parse_options(&b[108..236], &mut options, &mut budget, true)?;
            }
            if flags & 2 != 0 {
                parse_options(&b[44..108], &mut options, &mut budget, true)?;
            }
        }
        let kind = options
            .get(&53)
            .filter(|v| v.len() == 1)
            .ok_or_else(invalid)?[0];
        if ![2, 5, 6].contains(&kind) {
            return Err(invalid());
        }
        let server = ip(options.get(&54).ok_or_else(invalid)?)?;
        if !unicast(server) {
            return Err(invalid());
        }
        Ok(Self {
            kind,
            xid: u32::from_be_bytes(b[4..8].try_into().unwrap()),
            mac: b[28..34].try_into().unwrap(),
            address: ip(&b[16..20])?,
            server,
            options,
        })
    }
    fn number(&self, code: u8) -> io::Result<Option<u32>> {
        self.options
            .get(&code)
            .map(|b| {
                Ok(u32::from_be_bytes(
                    b.as_slice().try_into().map_err(|_| invalid())?,
                ))
            })
            .transpose()
    }
    pub fn lease(&self, now: u64, prior: Option<&Lease>) -> io::Result<Lease> {
        let seconds = self.number(51)?.ok_or_else(invalid)?;
        if seconds == 0 || !unicast(self.address) || self.address.is_link_local() {
            return Err(invalid());
        }
        let length = if let Some(b) = self.options.get(&1) {
            let m = u32::from(ip(b)?);
            let n = m.leading_ones();
            if m != u32::MAX.checked_shl(32 - n).unwrap_or(0) {
                return Err(invalid());
            }
            n as u8
        } else {
            prior.ok_or_else(invalid)?.config.length
        };
        let mut v = crate::ipv4::Ipv4::default();
        v.configure(self.address, length, None)?;
        let routes = if let Some(b) = self.options.get(&121) {
            routes(b)?
        } else if let Some(b) = self.options.get(&3) {
            addresses(b, 8)?
                .first()
                .map(|g| Route {
                    network: Ipv4Addr::UNSPECIFIED,
                    length: 0,
                    gateway: *g,
                })
                .into_iter()
                .collect()
        } else {
            prior.map(|l| l.config.routes.clone()).unwrap_or_default()
        };
        v.set_routes(&routes)?;
        let dns = if let Some(b) = self.options.get(&6) {
            addresses(b, 8)?
        } else {
            prior.map(|l| l.config.dns.clone()).unwrap_or_default()
        };
        let search = if let Some(b) = self.options.get(&119) {
            search(b)?
        } else if let Some(b) = self.options.get(&15) {
            domain(b)?
        } else {
            prior.map(|l| l.config.search.clone()).unwrap_or_default()
        };
        let a = self.number(58)?.unwrap_or(seconds / 2);
        let b = self
            .number(59)?
            .unwrap_or((u64::from(seconds) * 7 / 8) as u32);
        let (a, b) = if a > 0 && a < b && b < seconds {
            (a, b)
        } else {
            (seconds / 2, (u64::from(seconds) * 7 / 8) as u32)
        };
        let deadline = |s: u32| now.saturating_add(u64::from(s) * 1000);
        Ok(Lease {
            config: Configuration {
                address: self.address,
                length,
                routes,
                dns,
                search,
            },
            server: self.server,
            t1: deadline(a),
            t2: deadline(b),
            expires: if seconds == u32::MAX {
                u64::MAX
            } else {
                deadline(seconds)
            },
        })
    }
}
fn parse_options(
    b: &[u8],
    options: &mut BTreeMap<u8, Vec<u8>>,
    budget: &mut usize,
    overloaded: bool,
) -> io::Result<()> {
    let mut at = 0;
    while at < b.len() {
        let code = b[at];
        at += 1;
        if code == 0 {
            continue;
        }
        if code == 255 {
            return Ok(());
        }
        if at >= b.len() || (overloaded && code == 52) {
            return Err(invalid());
        }
        let n = b[at] as usize;
        at += 1;
        if n > b.len() - at || *budget + n > OPTION_BYTES {
            return Err(invalid());
        }
        *budget += n;
        options
            .entry(code)
            .or_default()
            .extend_from_slice(&b[at..at + n]);
        at += n;
    }
    Err(invalid())
}
fn addresses(b: &[u8], cap: usize) -> io::Result<Vec<Ipv4Addr>> {
    if b.is_empty() || b.len() % 4 != 0 || b.len() / 4 > cap {
        return Err(invalid());
    }
    b.chunks_exact(4)
        .map(|b| {
            let a = ip(b)?;
            if !unicast(a) {
                return Err(invalid());
            }
            Ok(a)
        })
        .collect()
}
fn routes(b: &[u8]) -> io::Result<Vec<Route>> {
    if b.is_empty() {
        return Err(invalid());
    }
    let mut at = 0;
    let mut out = vec![];
    while at < b.len() {
        let length = b[at];
        at += 1;
        let n = usize::from(length).div_ceil(8);
        if length > 32 || n + 4 > b.len() - at || out.len() >= 64 {
            return Err(invalid());
        }
        let mut network = [0; 4];
        network[..n].copy_from_slice(&b[at..at + n]);
        at += n;
        let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
        let network = Ipv4Addr::from(u32::from_be_bytes(network) & mask);
        let gateway = ip(&b[at..at + 4])?;
        at += 4;
        out.push(Route {
            network,
            length,
            gateway,
        });
    }
    Ok(out)
}
fn domain(b: &[u8]) -> io::Result<Vec<Vec<Vec<u8>>>> {
    let b = b.strip_suffix(b".").unwrap_or(b);
    if b.is_empty()
        || b.len() > 253
        || b.split(|c| *c == b'.').any(|l| {
            l.is_empty()
                || l.len() > 63
                || l.iter().any(|c| !c.is_ascii_alphanumeric() && *c != b'-')
        })
    {
        return Err(invalid());
    }
    Ok(vec![b.split(|c| *c == b'.').map(<[u8]>::to_vec).collect()])
}
fn search(b: &[u8]) -> io::Result<Vec<Vec<Vec<u8>>>> {
    if b.len() > 1024 {
        return Err(invalid());
    }
    let mut out = vec![];
    let mut cursor = 0;
    let mut boundaries = std::collections::BTreeSet::new();
    while cursor < b.len() {
        let start = cursor;
        if out.len() >= 16 {
            return Err(invalid());
        }
        let mut at = cursor;
        let mut consumed = None;
        let mut labels = vec![];
        let mut size = 1;
        for _ in 0..128 {
            let n = *b.get(at).ok_or_else(invalid)? as usize;
            boundaries.insert(at);
            if n == 0 {
                cursor = consumed.unwrap_or(at + 1);
                break;
            }
            if n & 0xc0 == 0xc0 {
                let ptr = ((n & 63) << 8) | usize::from(*b.get(at + 1).ok_or_else(invalid)?);
                if ptr >= at || !boundaries.contains(&ptr) {
                    return Err(invalid());
                }
                consumed.get_or_insert(at + 2);
                at = ptr;
                continue;
            }
            if n > 63 || at + n + 1 > b.len() || size + n + 1 > 255 {
                return Err(invalid());
            }
            labels.push(b[at + 1..at + 1 + n].to_vec());
            size += n + 1;
            at += n + 1;
        }
        if cursor <= start || labels.is_empty() {
            return Err(invalid());
        }
        out.push(labels);
    }
    Ok(out)
}
