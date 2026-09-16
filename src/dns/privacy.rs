//! Resolver-scoped DDR validation. Opportunistic designations retain the original IP.
use super::wire::{Context, Message, Name, Rdata};
use crate::time::RandomSource;
use std::{
    io,
    net::{IpAddr, SocketAddr},
};
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Designation {
    pub endpoint: SocketAddr,
    pub server_name: String,
    pub priority: u16,
    pub expires: u64,
}
#[derive(Debug, Default)]
pub struct Discovery {
    pub candidates: Vec<Designation>,
    pub alias: Option<(Name, u64)>,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid or excessive DDR response",
    )
}
fn hostname(name: &Name) -> Option<String> {
    if name.labels().is_empty() || name == &"resolver.arpa.".parse().unwrap() {
        return None;
    }
    let mut out = String::new();
    for label in name.labels() {
        if label.first() == Some(&b'-')
            || label.last() == Some(&b'-')
            || !label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(label).ok()?);
    }
    Some(out)
}
fn local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(a) => a.is_private() || a.is_link_local() || a.is_loopback(),
        IpAddr::V6(a) => a.is_unique_local() || a.is_unicast_link_local() || a.is_loopback(),
    }
}
pub fn ddr_candidates(
    origin: SocketAddr,
    message: &Message,
    now: u64,
    rng: &mut impl RandomSource,
) -> io::Result<Discovery> {
    if origin.port() == 0
        || origin.ip().is_unspecified()
        || origin.ip().is_multicast()
        || message.flags & 0xfa0f != 0x8000
        || message.questions.len() != 1
        || message.questions[0].kind != 64
        || message.questions[0].class != 1
        || message.answers.len() + message.authority.len() + message.additional.len() > 64
    {
        return Err(invalid());
    }
    let question = &message.questions[0];
    let records: Vec<_> = message
        .answers
        .iter()
        .filter(|r| r.name == question.name && r.kind == 64 && r.class == 1 && r.ttl > 0)
        .collect();
    for r in &records {
        let Rdata::Svcb { params, .. } = &r.data else {
            return Err(invalid());
        };
        if params.len() > 16 || params.iter().map(|(_, b)| b.len()).sum::<usize>() > 4096 {
            return Err(invalid());
        }
        let mut check = Message::new(0, 0x8000);
        check.answers.push((*r).clone());
        Message::parse(&check.encode()?, Context::Unicast)?;
        if params
            .iter()
            .any(|(k, b)| (*k == 4 && b.len() > 32) || (*k == 6 && b.len() > 128))
        {
            return Err(invalid());
        }
    }
    let deadline = |ttl: u32| now.saturating_add(u64::from(ttl.min(86400)) * 1000);
    let aliases: Vec<_> = records
        .iter()
        .filter(|r| matches!(r.data, Rdata::Svcb { priority: 0, .. }))
        .collect();
    if !aliases.is_empty() {
        let r = aliases[rng.sample((aliases.len() - 1) as u64)? as usize];
        let Rdata::Svcb { target, .. } = &r.data else {
            unreachable!()
        };
        return Ok(Discovery {
            alias: (!target.labels().is_empty() && *target != question.name)
                .then_some((target.clone(), deadline(r.ttl))),
            candidates: vec![],
        });
    }
    let mut out = Discovery::default();
    // RFC 9462 4.3 recommends this unauthenticated mode only for private/local
    // resolvers. Public DDR designations require a separate verified policy.
    if !local(origin.ip()) {
        return Ok(out);
    }
    for r in records {
        let Rdata::Svcb {
            priority,
            target,
            params,
        } = &r.data
        else {
            unreachable!()
        };
        let Some(server_name) = hostname(target) else {
            continue;
        };
        if params.iter().any(|(key, b)| {
            *key == 0
                && b.chunks_exact(2)
                    .any(|v| ![1, 2, 3, 4, 6].contains(&u16::from_be_bytes([v[0], v[1]])))
        }) {
            continue;
        }
        let Some((_, alpn)) = params.iter().find(|(key, _)| *key == 1) else {
            continue;
        };
        let mut protocols = alpn.as_slice();
        let mut dot = false;
        while !protocols.is_empty() {
            let length = usize::from(protocols[0]);
            dot |= &protocols[1..1 + length] == b"dot";
            protocols = &protocols[1 + length..];
        }
        if !dot {
            continue;
        }
        let port = params
            .iter()
            .find(|(key, _)| *key == 3)
            .map_or(853, |(_, b)| u16::from_be_bytes([b[0], b[1]]));
        if port == 0 {
            continue;
        }
        let mut evidence = false;
        let mut same = false;
        let mut expires = deadline(r.ttl);
        for (key, bytes) in params {
            match key {
                4 => {
                    for a in bytes.chunks_exact(4) {
                        evidence = true;
                        same |= origin.ip() == IpAddr::V4(<[u8; 4]>::try_from(a).unwrap().into());
                    }
                }
                6 => {
                    for a in bytes.chunks_exact(16) {
                        evidence = true;
                        same |= origin.ip() == IpAddr::V6(<[u8; 16]>::try_from(a).unwrap().into());
                    }
                }
                _ => {}
            }
        }
        for a in message
            .additional
            .iter()
            .filter(|a| a.name == *target && a.class == 1 && a.ttl > 0)
        {
            let address = match a.data {
                Rdata::A(b) => IpAddr::V4(b.into()),
                Rdata::Aaaa(b) => IpAddr::V6(b.into()),
                _ => continue,
            };
            evidence = true;
            if address == origin.ip() {
                same = true;
                expires = expires.min(deadline(a.ttl));
            }
        }
        if evidence && !same {
            continue;
        }
        let mut endpoint = origin;
        endpoint.set_port(port);
        if let Some(old) = out
            .candidates
            .iter_mut()
            .find(|c| c.endpoint == endpoint && c.server_name == server_name)
        {
            old.priority = old.priority.min(*priority);
            old.expires = old.expires.min(expires);
            continue;
        }
        if out.candidates.len() == 8 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DDR candidate capacity",
            ));
        }
        out.candidates.push(Designation {
            endpoint,
            server_name,
            priority: *priority,
            expires,
        });
    }
    out.candidates.sort_by_key(|c| c.priority);
    Ok(out)
}
