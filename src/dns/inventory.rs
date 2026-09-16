//! Router-owned DNS namespaces and authenticated SRP update aliasing.
use super::wire::{Name, Record};
use crate::{
    mdns::advertise::{replace_suffix, rewrite_data, within},
    persist::Identity,
    srp::wire::Update,
};
use std::io;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Zones {
    pub registrar: Name,
    pub discovery: Name,
    pub host: Option<Name>,
    pub reverse: Vec<Name>,
    pub hostname: Name,
    pub mailbox: Name,
}
impl Zones {
    pub fn for_identity(identity: &Identity) -> Self {
        let site: String = identity.site.address.octets()[1..6]
            .iter()
            .flat_map(|b| [b >> 4, b & 15])
            .map(|n| char::from(b"0123456789abcdef"[usize::from(n)]))
            .collect();
        let hostname: Name = format!("snac-{site}.home.arpa.").parse().unwrap();
        let mut labels = vec![b"srp".to_vec()];
        labels.extend_from_slice(hostname.labels());
        let mut mailbox = vec![b"hostmaster".to_vec()];
        mailbox.extend_from_slice(hostname.labels());
        Self {
            registrar: Name::from_labels(labels).unwrap(),
            discovery: "default.service.arpa.".parse().unwrap(),
            host: None,
            reverse: vec![],
            hostname,
            mailbox: Name::from_labels(mailbox).unwrap(),
        }
    }
    pub(crate) fn proxy(&self) -> io::Result<crate::discovery_proxy::Zone> {
        if self.registrar.labels().is_empty() || within(&self.hostname, &self.registrar) {
            return Err(io::Error::other(
                "invalid registrar namespace or nameserver",
            ));
        }
        crate::discovery_proxy::Zone::new(
            self.discovery.clone(),
            self.host.clone(),
            &self.reverse,
            std::slice::from_ref(&self.hostname),
            self.mailbox.clone(),
        )
    }
    pub(crate) fn registration_name(&self, name: &Name, request_zone: &Name) -> io::Result<Name> {
        replace_suffix(name, request_zone, &self.registrar)
    }
    /// Called only with a successfully authenticated update. Its digest remains
    /// the original signed wire digest, so exact-retry receipt lookup is unchanged.
    pub(crate) fn registration(&self, mut update: Update) -> io::Result<Update> {
        let map = |n: &Name| replace_suffix(n, &update.zone, &self.registrar);
        let records = |records: &mut [Record]| -> io::Result<()> {
            for r in records {
                r.name = map(&r.name)?;
                rewrite_data(&mut r.data, &map)?;
            }
            Ok(())
        };
        update.host = map(&update.host)?;
        records(&mut update.addresses)?;
        for service in &mut update.services {
            service.name = map(&service.name)?;
            records(&mut service.records)?;
            records(&mut service.discovery)?;
        }
        update.zone = self.registrar.clone();
        Ok(update)
    }
}

use super::wire::{Message, Question, Rdata};
use std::net::IpAddr;
pub struct Inventory {
    zones: Zones,
    contexts: Vec<Name>,
    addresses: Vec<IpAddr>,
    dns: Option<u16>,
    tls: Option<u16>,
}
fn prefixed(labels: &[&[u8]], zone: &Name) -> io::Result<Name> {
    let mut out: Vec<_> = labels.iter().map(|s| s.to_vec()).collect();
    out.extend_from_slice(zone.labels());
    Name::from_labels(out)
}
fn rr(name: Name, kind: u16, data: Rdata) -> Record {
    Record {
        name,
        kind,
        class: 1,
        ttl: 10,
        data,
    }
}
impl Inventory {
    pub fn new(zones: Zones) -> io::Result<Self> {
        zones.proxy()?;
        prefixed(
            &[b"SNAC Router", b"_dnssd-srp-tls", b"_tcp"],
            &zones.registrar,
        )?;
        for zone in [&zones.discovery, &zones.registrar, &zones.hostname] {
            prefixed(&[b"lb", b"_dns-sd", b"_udp"], zone)?;
        }
        Ok(Self {
            zones,
            contexts: vec![],
            addresses: vec![],
            dns: None,
            tls: None,
        })
    }
    pub fn set_contexts(&mut self, contexts: &[Name]) -> io::Result<()> {
        if contexts.len() > 64 || contexts.iter().any(|n| n.labels().is_empty()) {
            return Err(io::Error::other(
                "invalid or excessive DNS inventory contexts",
            ));
        }
        let mut names = vec![];
        for n in contexts {
            prefixed(&[b"lb", b"_dns-sd", b"_udp"], n)?;
            if !names.contains(n) {
                names.push(n.clone());
            }
        }
        self.contexts = names;
        Ok(())
    }
    pub fn set_ready(
        &mut self,
        addresses: &[IpAddr],
        dns: Option<u16>,
        tls: Option<u16>,
    ) -> io::Result<()> {
        if addresses.len() > 32
            || dns == Some(0)
            || tls == Some(0)
            || addresses.iter().any(|a| {
                a.is_unspecified()
                    || a.is_multicast()
                    || matches!(a, IpAddr::V4(v) if v.is_broadcast())
                    || matches!(a, IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
            })
        {
            return Err(io::Error::other("invalid or excessive service endpoints"));
        }
        let mut unique = vec![];
        for a in addresses {
            if !unique.contains(a) {
                unique.push(*a);
            }
        }
        self.addresses = unique;
        self.dns = dns;
        self.tls = tls;
        Ok(())
    }
    fn soa(&self, zone: &Name) -> Record {
        rr(
            zone.clone(),
            6,
            Rdata::Soa {
                mname: self.zones.hostname.clone(),
                rname: self.zones.mailbox.clone(),
                serial: 0,
                refresh: 7200,
                retry: 3600,
                expire: 86400,
                minimum: 10,
            },
        )
    }
    fn enumeration(&self, q: &Question, extra_context: bool) -> io::Result<Option<Vec<Record>>> {
        let labels = q.name.labels();
        if labels.len() < 4
            || !labels[1].eq_ignore_ascii_case(b"_dns-sd")
            || !labels[2].eq_ignore_ascii_case(b"_udp")
        {
            return Ok(None);
        }
        let kind = labels[0].to_ascii_lowercase();
        if ![b"b".as_slice(), b"db", b"lb", b"r", b"dr"].contains(&kind.as_slice()) {
            return Ok(None);
        }
        let context = Name::from_labels(labels[3..].to_vec())?;
        if !extra_context
            && context != "local.".parse().unwrap()
            && context != self.zones.discovery
            && context != self.zones.registrar
            && context != self.zones.hostname
            && !self.contexts.contains(&context)
            && !self.zones.reverse.contains(&context)
        {
            return Ok(None);
        }
        let mut domains = match kind.as_slice() {
            b"db" => vec![self.zones.discovery.clone()],
            b"r" | b"dr" => vec![self.zones.registrar.clone()],
            _ => vec![self.zones.discovery.clone(), self.zones.registrar.clone()],
        };
        domains.sort();
        domains.dedup();
        Ok(Some(if matches!(q.kind, 12 | 255) {
            domains
                .into_iter()
                .map(|n| rr(q.name.clone(), 12, Rdata::Name(n)))
                .collect()
        } else {
            vec![]
        }))
    }
    fn records(&self) -> io::Result<Vec<Record>> {
        let mut records = vec![];
        for zone in [&self.zones.registrar, &self.zones.hostname] {
            records.push(self.soa(zone));
            records.push(rr(
                zone.clone(),
                2,
                Rdata::Name(self.zones.hostname.clone()),
            ));
        }
        for a in &self.addresses {
            records.push(match a {
                IpAddr::V4(a) => rr(self.zones.hostname.clone(), 1, Rdata::A(a.octets())),
                IpAddr::V6(a) => rr(self.zones.hostname.clone(), 28, Rdata::Aaaa(a.octets())),
            });
        }
        if !self.addresses.is_empty() {
            for (label, port) in [
                (b"_dnssd-srp".as_slice(), self.dns),
                (b"_dnssd-srp-tls", self.tls),
            ] {
                let Some(port) = port else {
                    continue;
                };
                let service = prefixed(&[label, b"_tcp"], &self.zones.registrar)?;
                let instance = prefixed(&[b"SNAC Router"], &service)?;
                let srv = Rdata::Srv {
                    priority: 0,
                    weight: 0,
                    port,
                    target: self.zones.hostname.clone(),
                };
                records.push(rr(service.clone(), 12, Rdata::Name(instance.clone())));
                records.push(rr(service, 33, srv.clone()));
                records.push(rr(instance.clone(), 33, srv));
                records.push(rr(instance, 16, Rdata::Txt(vec![vec![]])));
            }
        }
        Ok(records)
    }
    pub fn answer(&self, q: &Question, now: u64) -> io::Result<Option<Message>> {
        self.answer_in_context(q, now, false)
    }
    pub(crate) fn answer_in_context(
        &self,
        q: &Question,
        _now: u64,
        extra_context: bool,
    ) -> io::Result<Option<Message>> {
        if q.class != 1 || q.kind == 0 {
            return Ok(None);
        }
        let mut answer = Message::new(0, 0x8400);
        answer.questions.push(q.clone());
        if let Some(records) = self.enumeration(q, extra_context)? {
            answer.answers = records;
            if answer.answers.is_empty() {
                answer.authority.push(self.soa(&self.zones.registrar));
            }
            return Ok(Some(answer));
        }
        if within(&q.name, &self.zones.discovery)
            || self.zones.host.as_ref().is_some_and(|z| within(&q.name, z))
            || self.zones.reverse.iter().any(|z| within(&q.name, z))
        {
            return Ok(None);
        }
        let zone = if within(&q.name, &self.zones.registrar) {
            &self.zones.registrar
        } else if within(&q.name, &self.zones.hostname) {
            &self.zones.hostname
        } else {
            return Ok(None);
        };
        let records = self.records()?;
        answer.answers = records
            .iter()
            .filter(|r| r.name == q.name && (r.kind == q.kind || q.kind == 255))
            .cloned()
            .collect();
        for r in &answer.answers {
            let wanted: Vec<_> = match &r.data {
                Rdata::Name(n) if r.kind == 12 => records
                    .iter()
                    .filter(|r| r.name == *n && matches!(r.kind, 16 | 33))
                    .cloned()
                    .collect(),
                _ => vec![],
            };
            for r in wanted {
                if !answer.additional.contains(&r) {
                    answer.additional.push(r);
                }
            }
        }
        if answer
            .answers
            .iter()
            .chain(&answer.additional)
            .any(|r| r.kind == 33)
        {
            answer.additional.extend(
                records
                    .iter()
                    .filter(|r| r.name == self.zones.hostname && matches!(r.kind, 1 | 28))
                    .cloned(),
            );
        }
        if answer.answers.is_empty() {
            if !records.iter().any(|r| within(&r.name, &q.name)) {
                answer.flags |= 3;
            }
            answer.authority.push(self.soa(zone));
        }
        Ok(Some(answer))
    }
}

pub(crate) fn reverse_network(prefix: crate::wire::Prefix) -> Name {
    let mut labels: Vec<Vec<u8>> = format!("{:032x}", u128::from(prefix.address))
        .as_bytes()
        .iter()
        .rev()
        .map(|b| vec![*b])
        .collect();
    labels.extend([b"ip6".to_vec(), b"arpa".to_vec()]);
    Name::from_labels(labels).unwrap()
}
