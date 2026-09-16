//! RFC 8766 authoritative view of a single AIL multicast namespace.
use crate::{
    dns::wire::{Message, Name, Question, Rdata, Record},
    mdns::advertise::{replace_suffix, rewrite_data, within},
};
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
