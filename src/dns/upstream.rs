//! Resolver discovery is scoped to the AIL and retains each advertiser's lifetime.
use super::wire::Name;
use crate::{
    time::RandomSource,
    wire::{self, dhcpv6, FrameKind},
    Link,
};
use std::{
    collections::BTreeMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS configuration")
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Origin {
    Ra(Ipv6Addr),
    Dhcp6,
    Dhcp4,
}
#[derive(Default)]
pub struct Discovery {
    servers: BTreeMap<(Origin, SocketAddr), u64>,
    domains: BTreeMap<(Origin, Name), u64>,
    configured: Vec<SocketAddr>,
}
impl Discovery {
    pub fn set_configured(&mut self, servers: &[SocketAddr]) -> io::Result<()> {
        if servers.len() > 8
            || servers
                .iter()
                .any(|a| a.port() == 0 || a.ip().is_multicast() || a.ip().is_unspecified())
        {
            return Err(invalid());
        }
        self.configured = servers.to_vec();
        Ok(())
    }
    pub fn explicit(&self) -> bool {
        !self.configured.is_empty()
    }
    pub fn endpoints(&self, now: u64) -> Vec<SocketAddr> {
        if !self.configured.is_empty() {
            return self.configured.clone();
        }
        let mut out = vec![];
        for ((_, a), until) in &self.servers {
            if *until > now && !out.contains(a) {
                out.push(*a);
            }
        }
        out
    }
    pub fn domains(&self, now: u64) -> Vec<Name> {
        let mut out = vec![];
        for ((_, n), until) in &self.domains {
            if *until > now && !out.contains(n) {
                out.push(n.clone());
            }
        }
        out
    }
    pub fn expire(&mut self, now: u64) {
        self.servers.retain(|_, t| *t > now);
        self.domains.retain(|_, t| *t > now);
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.servers
            .values()
            .chain(self.domains.values())
            .copied()
            .min()
    }
    pub fn link_lost(&mut self) {
        self.servers.clear();
        self.domains.clear();
    }
    pub fn receive_ra(&mut self, link: Link, packet: &[u8], now: u64) -> io::Result<()> {
        if link != Link::Ail || packet.len() > 4096 {
            return Err(invalid());
        }
        let e = wire::envelope(FrameKind::RawIpv6, packet).map_err(|_| invalid())?;
        let nd = wire::decode_nd(&e).map_err(|_| invalid())?;
        if nd.kind != 134 {
            return Err(invalid());
        }
        let origin = Origin::Ra(e.source);
        let mut servers = vec![];
        let mut domains = vec![];
        for opt in nd.options {
            let b = opt.bytes;
            match opt.kind {
                25 => {
                    if b.len() < 24 || (b.len() - 8) % 16 != 0 {
                        return Err(invalid());
                    }
                    let until = deadline(now, u32::from_be_bytes(b[4..8].try_into().unwrap()));
                    for chunk in b[8..].chunks_exact(16) {
                        let a = Ipv6Addr::from(<[u8; 16]>::try_from(chunk).unwrap());
                        valid6(a)?;
                        servers.push((SocketAddr::new(a.into(), 53), until));
                    }
                }
                31 => {
                    if b.len() < 16 {
                        return Err(invalid());
                    }
                    let until = deadline(now, u32::from_be_bytes(b[4..8].try_into().unwrap()));
                    for n in names(&b[8..], true)? {
                        domains.push((n, until));
                    }
                }
                _ => {}
            }
        }
        self.apply(origin, &servers, &domains, false, now)
    }
    fn apply(
        &mut self,
        origin: Origin,
        servers: &[(SocketAddr, u64)],
        domains: &[(Name, u64)],
        replace: bool,
        now: u64,
    ) -> io::Result<()> {
        let mut ss = self.servers.clone();
        let mut dd = self.domains.clone();
        ss.retain(|(o, _), t| *t > now && (!replace || *o != origin));
        dd.retain(|(o, _), t| *t > now && (!replace || *o != origin));
        for (a, t) in servers {
            let key = (origin.clone(), *a);
            if *t <= now {
                ss.remove(&key);
            } else {
                ss.insert(key, *t);
            }
        }
        for (n, t) in domains {
            let key = (origin.clone(), n.clone());
            if *t <= now {
                dd.remove(&key);
            } else {
                dd.insert(key, *t);
            }
        }
        if ss.len() > 8 || dd.len() > 64 {
            return Err(invalid());
        }
        self.servers = ss;
        self.domains = dd;
        Ok(())
    }
    pub fn dhcp6(&mut self, c: &DhcpConfiguration, now: u64) -> io::Result<()> {
        let until = deadline(now, c.refresh);
        self.apply(
            Origin::Dhcp6,
            &c.servers
                .iter()
                .map(|a| (SocketAddr::new((*a).into(), 53), until))
                .collect::<Vec<_>>(),
            &c.domains
                .iter()
                .map(|n| (n.clone(), until))
                .collect::<Vec<_>>(),
            true,
            now,
        )
    }
    pub fn dhcp4(
        &mut self,
        c: Option<&crate::ipv4::dhcp::Configuration>,
        now: u64,
    ) -> io::Result<()> {
        let mut servers = vec![];
        let mut domains = vec![];
        if let Some(c) = c {
            for a in &c.dns {
                servers.push((SocketAddr::new(IpAddr::V4(*a), 53), u64::MAX));
            }
            for name in &c.search {
                domains.push((Name::from_labels(name.clone())?, u64::MAX));
            }
        }
        self.apply(Origin::Dhcp4, &servers, &domains, true, now)
    }
}
fn deadline(now: u64, seconds: u32) -> u64 {
    now.saturating_add(u64::from(seconds) * 1000)
}
fn valid6(a: Ipv6Addr) -> io::Result<()> {
    if a.is_unspecified() || a.is_multicast() || a.is_loopback() {
        return Err(invalid());
    }
    Ok(())
}
fn names(b: &[u8], padding: bool) -> io::Result<Vec<Name>> {
    if b.len() > 16384 {
        return Err(invalid());
    }
    let mut at = 0;
    let mut out = vec![];
    while at < b.len() {
        if padding && b[at..].iter().all(|v| *v == 0) {
            break;
        }
        let mut labels = vec![];
        let mut size = 1;
        loop {
            let n = usize::from(*b.get(at).ok_or_else(invalid)?);
            at += 1;
            if n == 0 {
                break;
            }
            if n > 63 {
                return Err(invalid());
            }
            let label = b.get(at..at + n).ok_or_else(invalid)?;
            size += n + 1;
            if size > 255 {
                return Err(invalid());
            }
            labels.push(label.to_vec());
            at += n;
        }
        if labels.is_empty() || out.len() >= 64 {
            return Err(invalid());
        }
        out.push(Name::from_labels(labels)?);
    }
    if out.is_empty() {
        return Err(invalid());
    }
    Ok(out)
}
#[derive(Clone, Debug)]
pub struct DhcpConfiguration {
    pub servers: Vec<Ipv6Addr>,
    pub domains: Vec<Name>,
    pub refresh: u32,
    pub inf_max_rt: Option<u32>,
}
pub fn parse_dhcp_reply(
    b: &[u8],
    xid: [u8; 3],
    duid: &[u8],
    expected_server: Option<&[u8]>,
) -> io::Result<DhcpConfiguration> {
    if b.len() < 4 || b.len() > 4096 || b[0] != 7 || b[1..4] != xid {
        return Err(invalid());
    }
    let opts = dhcpv6::options(&b[4..]).map_err(|_| invalid())?;
    let single = |code| -> io::Result<Option<&[u8]>> {
        let mut i = opts.iter().filter(|(c, _)| *c == code);
        let value = i.next().map(|(_, b)| *b);
        if i.next().is_some() {
            return Err(invalid());
        }
        Ok(value)
    };
    if single(1)? != Some(duid) || duid.is_empty() || duid.len() > 128 {
        return Err(invalid());
    }
    let server = single(2)?.ok_or_else(invalid)?;
    if server.is_empty() || server.len() > 128 || expected_server.is_some_and(|s| s != server) {
        return Err(invalid());
    }
    if let Some(status) = single(13)? {
        if status.len() < 2 || status[..2] != [0, 0] {
            return Err(invalid());
        }
    }
    let mut servers = vec![];
    if let Some(b) = single(23)? {
        if b.is_empty() || b.len() % 16 != 0 || b.len() > 8 * 16 {
            return Err(invalid());
        }
        for c in b.chunks_exact(16) {
            let a = Ipv6Addr::from(<[u8; 16]>::try_from(c).unwrap());
            valid6(a)?;
            if !servers.contains(&a) {
                servers.push(a);
            }
        }
    }
    let domains = single(24)?.map_or_else(|| Ok(vec![]), |b| names(b, false))?;
    let refresh = single(32)?.map_or(Ok(86400), |b| -> io::Result<u32> {
        Ok(u32::from_be_bytes(b.try_into().map_err(|_| invalid())?).max(600))
    })?;
    let inf_max_rt = single(83)?
        .map(|b| -> io::Result<u32> {
            let n = u32::from_be_bytes(b.try_into().map_err(|_| invalid())?);
            if !(60..=86400).contains(&n) {
                return Err(invalid());
            }
            Ok(n)
        })
        .transpose()?;
    Ok(DhcpConfiguration {
        servers,
        domains,
        refresh,
        inf_max_rt,
    })
}
pub struct InformationClient {
    duid: Vec<u8>,
    xid: Option<[u8; 3]>,
    started: u64,
    next: u64,
    interval: u64,
    max: u64,
    reserved_xid: Option<[u8; 3]>,
}
impl InformationClient {
    pub fn new(duid: Vec<u8>, now: u64, rng: &mut impl RandomSource) -> io::Result<Self> {
        if duid.is_empty() || duid.len() > 128 {
            return Err(invalid());
        }
        let mut xid = [0; 3];
        rng.fill(&mut xid)?;
        Ok(Self {
            duid,
            xid: Some(xid),
            started: now,
            next: now.saturating_add(rng.sample(1000)?),
            interval: 0,
            max: 3600000,
            reserved_xid: None,
        })
    }
    pub fn xid(&self) -> Option<[u8; 3]> {
        self.xid
    }
    pub fn avoid_xid(&mut self, xid: [u8; 3], now: u64) {
        self.reserved_xid = Some(xid);
        if self.xid == Some(xid) {
            let mut other = xid;
            other[2] ^= 1;
            self.xid = Some(other);
            self.next = now;
            self.started = now;
            self.interval = 0;
        }
    }
    pub fn next_deadline(&self) -> u64 {
        self.next
    }
    pub fn poll(
        &mut self,
        now: u64,
        source: Ipv6Addr,
        rng: &mut impl RandomSource,
    ) -> io::Result<Option<Vec<u8>>> {
        valid6(source)?;
        if now < self.next {
            return Ok(None);
        }
        if self.xid.is_none() {
            let mut xid = [0; 3];
            rng.fill(&mut xid)?;
            if self.reserved_xid == Some(xid) {
                xid[2] ^= 1;
            }
            self.xid = Some(xid);
            self.started = now;
            self.interval = 0;
        }
        let mut b = vec![11];
        b.extend(self.xid.unwrap());
        b.extend(dhcpv6::option(1, &self.duid));
        b.extend(dhcpv6::option(6, &[0, 23, 0, 24, 0, 32, 0, 83]));
        b.extend(dhcpv6::option(
            8,
            &((now.saturating_sub(self.started) / 10).min(65535) as u16).to_be_bytes(),
        ));
        let base = if self.interval == 0 {
            1000
        } else {
            self.interval
        };
        let nominal = if self.interval == 0 {
            1000
        } else {
            self.interval.saturating_mul(2)
        };
        let (nominal, base) = if nominal > self.max {
            (self.max, self.max)
        } else {
            (nominal, base)
        };
        let jitter = (rng.sample(200)? as i64) - 100;
        self.interval = (nominal as i64 + base as i64 * jitter / 1000) as u64;
        self.next = now.saturating_add(self.interval);
        Ok(Some(
            dhcpv6::udp_packet(source, "ff02::1:2".parse().unwrap(), 546, 547, &b)
                .map_err(|_| invalid())?,
        ))
    }
    pub fn receive(
        &mut self,
        link: Link,
        packet: &[u8],
        now: u64,
    ) -> io::Result<Option<DhcpConfiguration>> {
        if link != Link::Ail {
            return Err(invalid());
        }
        let Some(xid) = self.xid else {
            return Ok(None);
        };
        let e = wire::envelope(FrameKind::RawIpv6, packet).map_err(|_| invalid())?;
        valid6(e.source)?;
        if e.hop_limit == 0 || e.destination.is_multicast() {
            return Err(invalid());
        }
        let b = dhcpv6::udp_payload(&e).map_err(|_| invalid())?;
        let c = parse_dhcp_reply(b, xid, &self.duid, None)?;
        self.xid = None;
        self.next = deadline(now, c.refresh);
        if let Some(max) = c.inf_max_rt {
            self.max = u64::from(max) * 1000;
        }
        Ok(Some(c))
    }
}
