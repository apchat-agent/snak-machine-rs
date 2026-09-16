//! RFC 8766 authoritative view of a single AIL multicast namespace.
mod query;
use crate::{
    dns::wire::{Message, Name, Question, Rdata, Record},
    mdns::advertise::{replace_suffix, rewrite_data, within},
};
pub use query::{Completion, Proxy};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Discovery Proxy configuration or record",
    )
}
#[derive(Clone, Copy, Default, Debug)]
pub struct Reachability {
    pub on_link: bool,
    pub ipv4_link_local: bool,
    pub different_private_realm: bool,
    pub different_ula_realm: bool,
    pub include_unusable: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    Service,
    Host,
    Reverse(usize),
}
#[derive(Clone, Debug)]
pub struct TranslatedQuestion {
    pub original: Question,
    pub multicast: Question,
    scope: Scope,
}
#[derive(Clone)]
pub struct Zone {
    service: Name,
    host: Option<Name>,
    reverse: Vec<Name>,
    nameservers: Vec<Name>,
    mailbox: Name,
}
impl Zone {
    pub fn new(
        service: Name,
        host: Option<Name>,
        reverse: &[Name],
        nameservers: &[Name],
        mailbox: Name,
    ) -> io::Result<Self> {
        if service.labels().is_empty()
            || host.as_ref().is_some_and(|n| !ldh(n))
            || reverse.len() > 64
            || nameservers.is_empty()
            || nameservers.len() > 8
            || reverse.iter().any(|n| {
                !within(n, &"in-addr.arpa.".parse().unwrap())
                    && !within(n, &"ip6.arpa.".parse().unwrap())
            })
            || nameservers.iter().any(|n| {
                n.labels().is_empty()
                    || within(n, &service)
                    || host.as_ref().is_some_and(|h| within(n, h))
                    || reverse.iter().any(|r| within(n, r))
            })
        {
            return Err(invalid());
        }
        Ok(Self {
            service,
            host,
            reverse: reverse.to_vec(),
            nameservers: nameservers.to_vec(),
            mailbox,
        })
    }
    fn scope(&self, name: &Name) -> Option<Scope> {
        // Choose the most specific configured suffix, including overlapping zones.
        std::iter::once((Scope::Service, &self.service))
            .chain(self.host.iter().map(|h| (Scope::Host, h)))
            .chain(
                self.reverse
                    .iter()
                    .enumerate()
                    .map(|(i, n)| (Scope::Reverse(i), n)),
            )
            .filter(|(_, n)| within(name, n))
            .max_by_key(|(_, n)| n.labels().len())
            .map(|(s, _)| s)
    }
    fn domain(&self, scope: Scope) -> io::Result<&Name> {
        match scope {
            Scope::Service => Ok(&self.service),
            Scope::Host => self.host.as_ref().ok_or_else(invalid),
            Scope::Reverse(i) => self.reverse.get(i).ok_or_else(invalid),
        }
    }
    fn host_domain(&self) -> &Name {
        self.host.as_ref().unwrap_or(&self.service)
    }
    pub fn question(&self, q: &Question) -> io::Result<Option<TranslatedQuestion>> {
        if q.class != 1 || q.kind == 0 {
            return Err(invalid());
        }
        let Some(scope) = self.scope(&q.name) else {
            return Ok(None);
        };
        let mut multicast = q.clone();
        if !matches!(scope, Scope::Reverse(_)) {
            multicast.name =
                replace_suffix(&q.name, self.domain(scope)?, &"local.".parse().unwrap())?;
        }
        if matches!(q.kind, 47 | 50) {
            multicast.kind = 255;
        }
        Ok(Some(TranslatedQuestion {
            original: q.clone(),
            multicast,
            scope,
        }))
    }
    pub fn rewrite(
        &self,
        r: &Record,
        q: &TranslatedQuestion,
        additional: bool,
        reach: &Reachability,
    ) -> io::Result<Option<Record>> {
        if self.scope(&q.original.name) != Some(q.scope) {
            return Err(invalid());
        }
        if r.class & 0x7fff != 1
            || r.ttl == 0
            || matches!(r.kind, 2 | 6 | 24 | 41 | 43 | 46)
            || !usable(r, reach)
        {
            return Ok(None);
        }
        if matches!(r.kind, 47 | 50) {
            return Err(invalid());
        }
        let local: Name = "local.".parse().unwrap();
        let host_owner = additional && matches!(r.kind, 1 | 5 | 28);
        let owner_domain = if host_owner {
            self.host_domain()
        } else {
            self.domain(q.scope)?
        };
        let mut out = r.clone();
        out.name = replace_suffix(&r.name, &local, owner_domain)?;
        let host_target = host_owner
            || matches!(q.scope, Scope::Host | Scope::Reverse(_))
            || matches!(r.kind, 15 | 18 | 21 | 33 | 36)
            || (matches!(r.kind, 5 | 39) && matches!(q.original.kind, 1 | 28))
            || matches!(r.data, Rdata::Svcb { priority: 1.., .. });
        let target_domain = if host_target {
            self.host_domain()
        } else {
            self.domain(q.scope)?
        };
        rewrite_data(&mut out.data, &|n| replace_suffix(n, &local, target_domain))?;
        out.class &= 0x7fff;
        out.ttl = out.ttl.min(10);
        Ok(Some(out))
    }
    /// Convert only the queried owner's type information, never an mDNS interval.
    pub fn denial(
        &self,
        q: &TranslatedQuestion,
        records: &[Record],
        reach: &Reachability,
    ) -> io::Result<Record> {
        use sha1::{Digest, Sha1};
        use std::collections::BTreeSet;
        if records.len() > 4096 || self.scope(&q.original.name) != Some(q.scope) {
            return Err(invalid());
        }
        let domain = self.domain(q.scope)?;
        let apex = q.original.name == *domain;
        let mut types = BTreeSet::new();
        let mut work = 0usize;
        let mut seen = [false; 2];
        let mut reachable = [false; 2];
        let accepted = |kind| {
            kind != 0
                && !matches!(kind, 24 | 41 | 43 | 46 | 47 | 50 | 249..=255)
                && (apex || !matches!(kind, 2 | 6))
        };
        for r in records
            .iter()
            .filter(|r| r.name == q.multicast.name && r.class & 0x7fff == 1 && r.ttl > 0)
        {
            work += 1;
            if let Rdata::Nsec { bitmap, .. } = &r.data {
                work = work.checked_add(bitmap.len()).ok_or_else(invalid)?;
                if work > 262144 {
                    return Err(invalid());
                }
                read_bitmap(bitmap, &mut |kind| {
                    if accepted(kind) {
                        insert_type(&mut types, kind)?;
                    }
                    Ok(())
                })?;
            } else if accepted(r.kind) {
                insert_type(&mut types, r.kind)?;
            }
            if matches!(r.kind, 1 | 28) {
                let i = usize::from(r.kind == 28);
                seen[i] = true;
                reachable[i] |= usable(r, reach);
            }
        }
        for (i, kind) in [1, 28].into_iter().enumerate() {
            if seen[i] && !reachable[i] {
                types.remove(&kind);
            }
        }
        let kind = if q.original.kind == 50 { 50 } else { 47 };
        if kind == 47 {
            insert_type(&mut types, 47)?;
        }
        let bitmap = type_bitmap(&types);
        let (name, data) = if kind == 47 {
            (
                q.original.name.clone(),
                Rdata::Nsec {
                    next: successor(&q.original.name, domain)?,
                    bitmap,
                },
            )
        } else {
            let hash: [u8; 20] = Sha1::digest(q.original.name.canonical()).into();
            let mut labels = vec![base32hex(&hash)];
            labels.extend_from_slice(domain.labels());
            let name = Name::from_labels(labels)?;
            let mut next = hash;
            for octet in next.iter_mut().rev() {
                let (n, carry) = octet.overflowing_add(1);
                *octet = n;
                if !carry {
                    break;
                }
            }
            let mut data = vec![1, 0, 0, 0, 0, 20];
            data.extend(next);
            data.extend(bitmap);
            (name, Rdata::Bytes(data))
        };
        Ok(Record {
            name,
            kind,
            class: 1,
            ttl: 10,
            data,
        })
    }
    fn soa(&self, scope: Scope) -> io::Result<Record> {
        Ok(Record {
            name: self.domain(scope)?.clone(),
            kind: 6,
            class: 1,
            ttl: 10,
            data: Rdata::Soa {
                mname: self.nameservers[0].clone(),
                rname: self.mailbox.clone(),
                serial: 0,
                refresh: 7200,
                retry: 3600,
                expire: 86400,
                minimum: 10,
            },
        })
    }
    pub fn metadata(&self, q: &Question) -> io::Result<Option<Message>> {
        let Some(mapped) = self.question(q)? else {
            return Ok(None);
        };
        let domain = self.domain(mapped.scope)?;
        let apex = q.name == *domain;
        let relative = &q.name.labels()[..q.name.labels().len() - domain.labels().len()];
        let reserved = relative.len() == 2
            && [
                ("_dns-llq", "_udp"),
                ("_dns-llq", "_tcp"),
                ("_dns-llq-tls", "_tcp"),
                ("_dns-push-tls", "_tcp"),
                ("_dns-update", "_udp"),
                ("_dns-update", "_tcp"),
                ("_dns-update-tls", "_tcp"),
            ]
            .iter()
            .any(|(a, b)| {
                relative[0].eq_ignore_ascii_case(a.as_bytes())
                    && relative[1].eq_ignore_ascii_case(b.as_bytes())
            });
        let enumeration = matches!(mapped.scope, Scope::Reverse(_))
            && relative.len() == 3
            && ["b", "db", "lb", "r", "dr"]
                .iter()
                .any(|n| relative[0].eq_ignore_ascii_case(n.as_bytes()))
            && relative[1].eq_ignore_ascii_case(b"_dns-sd")
            && relative[2].eq_ignore_ascii_case(b"_udp");
        if !apex && !matches!(q.kind, 2 | 6 | 43) && !reserved && !enumeration {
            return Ok(None);
        }
        let mut m = Message::new(0, 0x8400);
        m.questions.push(q.clone());
        if apex && matches!(q.kind, 47 | 50) {
            let mut types = self
                .metadata(&Question {
                    kind: 255,
                    ..q.clone()
                })?
                .unwrap()
                .answers;
            for record in &mut types {
                record.name = mapped.multicast.name.clone();
            }
            m.answers
                .push(self.denial(&mapped, &types, &Reachability::default())?);
            return Ok(Some(m));
        }
        if apex && matches!(q.kind, 2 | 255) {
            m.answers.extend(self.nameservers.iter().map(|n| Record {
                name: domain.clone(),
                kind: 2,
                class: 1,
                ttl: 10,
                data: Rdata::Name(n.clone()),
            }));
        }
        if apex && matches!(q.kind, 6 | 255) {
            m.answers.push(self.soa(mapped.scope)?);
        }
        if m.answers.is_empty() {
            m.authority.push(self.soa(mapped.scope)?);
        }
        Ok(Some(m))
    }
}
fn ldh(name: &Name) -> bool {
    !name.labels().is_empty()
        && name.labels().iter().all(|l| {
            l.first().is_some_and(u8::is_ascii_alphanumeric)
                && l.last().is_some_and(u8::is_ascii_alphanumeric)
                && l.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        })
}
fn usable(r: &Record, reach: &Reachability) -> bool {
    match r.data {
        Rdata::A(b) => {
            let a = Ipv4Addr::from(b);
            crate::ipv4::unicast(a)
                && (reach.include_unusable
                    || ((!a.is_link_local() || reach.on_link || reach.ipv4_link_local)
                        && (!a.is_private() || !reach.different_private_realm)))
        }
        Rdata::Aaaa(b) => {
            let a = Ipv6Addr::from(b);
            !a.is_unspecified()
                && !a.is_loopback()
                && !a.is_multicast()
                && a.to_ipv4_mapped().is_none()
                && (reach.include_unusable
                    || ((!a.is_unicast_link_local() || reach.on_link)
                        && (!a.is_unique_local() || !reach.different_ula_realm)))
        }
        _ => true,
    }
}

fn insert_type(types: &mut std::collections::BTreeSet<u16>, kind: u16) -> io::Result<()> {
    if types.len() == 1024 && !types.contains(&kind) {
        return Err(invalid());
    }
    types.insert(kind);
    Ok(())
}
fn read_bitmap(bytes: &[u8], add: &mut impl FnMut(u16) -> io::Result<()>) -> io::Result<()> {
    let mut at = 0;
    let mut previous = None;
    while at < bytes.len() {
        let window = bytes[at];
        let n = usize::from(*bytes.get(at + 1).ok_or_else(invalid)?);
        if n == 0 || n > 32 || previous.is_some_and(|p| p >= window) {
            return Err(invalid());
        }
        let bits = bytes.get(at + 2..at + 2 + n).ok_or_else(invalid)?;
        if bits.last() == Some(&0) {
            return Err(invalid());
        }
        for (i, byte) in bits.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    add(u16::from(window) * 256 + (i * 8 + bit) as u16)?;
                }
            }
        }
        previous = Some(window);
        at += 2 + n;
    }
    Ok(())
}
fn type_bitmap(types: &std::collections::BTreeSet<u16>) -> Vec<u8> {
    let mut bits = [0u8; 8192];
    for kind in types {
        bits[usize::from(*kind) / 8] |= 0x80 >> (kind % 8);
    }
    let mut out = vec![];
    for (window, b) in bits.chunks_exact(32).enumerate() {
        if let Some(last) = b.iter().rposition(|v| *v != 0) {
            out.extend([window as u8, (last + 1) as u8]);
            out.extend(&b[..=last]);
        }
    }
    out
}
fn successor(name: &Name, zone: &Name) -> io::Result<Name> {
    let labels: Vec<Vec<u8>> = name
        .labels()
        .iter()
        .map(|l| l.iter().map(u8::to_ascii_lowercase).collect())
        .collect();
    if name.canonical().len() <= 253 {
        let mut next = vec![vec![0]];
        next.extend(labels);
        return Name::from_labels(next);
    }
    // No room for another label. Increment the least significant label,
    // carrying into its parent when necessary, within the DNS wire limits.
    for start in 0..labels.len().saturating_sub(zone.labels().len()) {
        let mut next = labels[start..].to_vec();
        let length = 1 + next.iter().map(|l| l.len() + 1).sum::<usize>();
        if length < 255 && next[0].len() < 63 {
            next[0].push(0);
            return Name::from_labels(next);
        }
        if let Some(at) = next[0].iter().rposition(|b| *b < 255) {
            next[0][at] += 1;
            if next[0][at] == b'A' {
                next[0][at] = b'[';
            }
            next[0].truncate(at + 1);
            return Name::from_labels(next);
        }
    }
    Ok(zone.clone())
}
fn base32hex(bytes: &[u8; 20]) -> Vec<u8> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut out = Vec::with_capacity(32);
    let mut buffer = 0u32;
    let mut bits = 0;
    for octet in bytes {
        buffer = (buffer << 8) | u32::from(*octet);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize]);
        }
        buffer &= (1 << bits) - 1;
    }
    out
}
