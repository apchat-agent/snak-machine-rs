use super::*;
use sha1::{Digest, Sha1};
impl Router {
    pub fn set_link(
        &mut self,
        link: Link,
        up: bool,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        // An exhausted identity requires operator restart, not an IFF_UP poll.
        if up
            && self
                .owned
                .iter()
                .any(|((l, _), a)| *l == link && a.state == DadState::Failed)
        {
            return Ok(());
        }
        if self.links[link.index()].up == up {
            return Ok(());
        }
        let prior = self.stub_routes(now);
        self.links[link.index()].up = up;
        if link == Link::Ail
            && matches!(
                self.lifecycle,
                Lifecycle::Running | Lifecycle::AilUnavailable
            )
        {
            self.lifecycle = if up {
                Lifecycle::Running
            } else {
                Lifecycle::AilUnavailable
            };
        }
        if self.lifecycle == Lifecycle::Stopping && !up {
            self.final_ras[link.index()] = 0;
        }
        if up {
            self.headers.retain(|k, _| k.link != link);
            self.neighbors.retain(|k, _| k.link != link);
            self.suppliers.retain(|(k, _), _| k.link != link);
            let s = &mut self.links[link.index()];
            s.state = AilState::Unknown;
            s.rs_count = 0;
            s.rs_next = now + rng.sample(1000)?;
            s.discovery_end = u64::MAX;
        }
        if link == Link::Stub {
            for ((l, p), v) in self.on_link.iter() {
                if *l == Link::Stub && v.valid.live(now) {
                    if up {
                        self.withdrawals.remove(&(Link::Ail, *p));
                    } else {
                        self.withdrawals.insert((Link::Ail, *p), 3);
                    }
                }
            }
            self.links[0].scheduler.changed(now, rng)?;
        }
        if link == Link::Ail {
            if !up {
                for r in prior {
                    if r.lifetime > 0 {
                        self.withdrawals.insert((Link::Stub, r.prefix), 3);
                    }
                }
            }
            self.routes.clear();
            self.links[1].scheduler.changed(now, rng)?;
            if up {
                self.attachment.discovering = true;
                self.attachment.observed.clear();
                self.pd.refresh(6, now, rng)?;
            }
        }
        Ok(())
    }
    pub fn checkpoint(&self, now: Time, wall: u64) -> io::Result<Vec<u8>> {
        fn end(l: Lifetime, now: Time, wall: u64) -> u64 {
            match l {
                Lifetime::Infinite => u64::MAX,
                Lifetime::Until(t) => wall.saturating_add(t / 1000).saturating_sub(now / 1000),
            }
        }
        let mut text = format!(
            "SNAC-SNAPSHOT-2 {wall}\n{}\n",
            hex(&self.identity.encode()?)
        );
        for evidence in &self.attachment.known {
            text.push_str(&format!("A {}\n", hex(evidence)));
        }
        for ((link, prefix), valid) in &self.retired_ulas {
            text.push_str(&format!(
                "R {} {} {}\n",
                link.index(),
                prefix.address,
                end(*valid, now, wall)
            ));
        }
        for ((link, prefix), v) in self.on_link.iter() {
            if v.valid.live(now) {
                text.push_str(&format!(
                    "O {} {} {} {} {}\n",
                    link.index(),
                    prefix.address,
                    prefix.length,
                    end(v.preferred, now, wall),
                    end(v.valid, now, wall)
                ));
            }
        }
        for link in [Link::Ail, Link::Stub] {
            let state = &self.links[link.index()];
            let deprecation = state.deprecate_at.map_or("-".to_owned(), |at| {
                ((wall as i128 * 1000 + at + 1800000 - now as i128).max(0) / 1000).to_string()
            });
            text.push_str(&format!(
                "L {} {} {}\n",
                link.index(),
                end(state.last_valid, now, wall),
                deprecation
            ));
        }
        for ((link, prefix), valid) in &self.advertised_routes {
            if valid.live(now) {
                text.push_str(&format!(
                    "H {} {} {} {} {}\n",
                    link.index(),
                    prefix.address,
                    prefix.length,
                    end(*valid, now, wall),
                    self.withdrawals.get(&(*link, *prefix)).unwrap_or(&0)
                ));
            }
        }
        for ((link, address), owned) in &self.owned {
            if let Some(prefix) = owned.prefix {
                text.push_str(&format!(
                    "I {} {} {} {} {}\n",
                    link.index(),
                    address,
                    prefix.address,
                    prefix.length,
                    owned.attempts
                ));
            }
        }
        if let Some(fallback) = self.pd.fallback_at {
            text.push_str(&format!(
                "F {}\n",
                end(Lifetime::Until(fallback), now, wall)
            ));
        }
        for (prefix, owned) in &self.pd_prefixes {
            let deprecation = owned.deprecate_at.map_or("-".to_owned(), |at| {
                ((wall as i128 * 1000 + at + 1800000 - now as i128).max(0) / 1000).to_string()
            });
            text.push_str(&format!(
                "D {} {} {} {} {} {}\n",
                prefix.address,
                owned.lease.0,
                owned.lease.1.address,
                owned.lease.1.length,
                deprecation,
                end(owned.last_valid, now, wall)
            ));
        }
        for ((iaid, p), l) in &self.pd.leases {
            if l.used && l.valid.live(now) {
                text.push_str(&format!(
                    "P {iaid} {} {} {} {} {} {} {}\n",
                    p.address,
                    p.length,
                    hex(&l.server),
                    end(l.preferred, now, wall),
                    end(l.valid, now, wall),
                    end(l.t1, now, wall),
                    end(l.t2, now, wall)
                ));
            }
        }
        let digest = hex(&Sha1::digest(text.as_bytes()));
        text.push_str(&format!("Z {} {}\n", text.len(), digest));
        if text.len() > crate::persist::MAX_JOURNAL_BYTES {
            return Err(io::Error::other("journal byte capacity"));
        }
        Ok(text.into_bytes())
    }
    pub fn restore(
        bytes: &[u8],
        now: Time,
        wall: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid SNAC snapshot");
        if bytes.len() > crate::persist::MAX_JOURNAL_BYTES {
            return Err(invalid());
        }
        let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
        let version2 = text.starts_with("SNAC-SNAPSHOT-2 ");
        let text = if version2 {
            let (body, footer) = text.rsplit_once("\nZ ").ok_or_else(invalid)?;
            let footer = footer.strip_suffix('\n').ok_or_else(invalid)?;
            let (len, digest) = footer.split_once(' ').ok_or_else(invalid)?;
            let n = len.parse::<usize>().map_err(|_| invalid())?;
            if n != body.len() + 1 || hex(&Sha1::digest(&bytes[..n])) != digest {
                return Err(invalid());
            }
            &text[..n]
        } else {
            text
        };
        let mut lines = text.lines();
        let first = lines.next().ok_or_else(invalid)?;
        let saved_wall: u64 = first
            .strip_prefix(if version2 {
                "SNAC-SNAPSHOT-2 "
            } else {
                "SNAC-SNAPSHOT-1 "
            })
            .ok_or_else(invalid)?
            .parse()
            .map_err(|_| invalid())?;
        let identity = Identity::decode(&unhex(lines.next().ok_or_else(invalid)?)?)?;
        let mut r = Self::new(identity, now, rng)?;
        let effective_wall = wall.max(saved_wall);
        let parse = |s: &str| s.parse::<u64>().map_err(|_| invalid());
        let lifetime = |s: &str| -> io::Result<Lifetime> {
            let end = parse(s)?;
            Ok(if end == u64::MAX {
                Lifetime::Infinite
            } else {
                Lifetime::Until(
                    now.saturating_add(end.saturating_sub(effective_wall).saturating_mul(1000)),
                )
            })
        };
        let mut seen = std::collections::BTreeSet::new();
        let mut owned_prefixes = BTreeMap::new();
        let mut owned_addresses = BTreeMap::new();
        let mut fallback = None;
        let parse_link = |s: &str| match s {
            "0" => Ok(Link::Ail),
            "1" => Ok(Link::Stub),
            _ => Err(invalid()),
        };
        let prefix = |address: &str, length: &str| -> io::Result<Prefix> {
            let address: Ipv6Addr = address.parse().map_err(|_| invalid())?;
            let length = u8::try_from(parse(length)?).map_err(|_| invalid())?;
            Prefix::new(address, length)
                .filter(|p| p.address == address && p.routable())
                .ok_or_else(invalid)
        };
        let origin = |s: &str| -> io::Result<Option<i128>> {
            if s == "-" {
                Ok(None)
            } else {
                Ok(Some(
                    now as i128 + (parse(s)? as i128 - effective_wall as i128) * 1000 - 1800000,
                ))
            }
        };
        for (line_count, line) in lines.enumerate() {
            if line_count >= 1024 || line.len() > 4096 || !seen.insert(line) {
                return Err(invalid());
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields.as_slice() {
                ["O", link, address, length, preferred, valid] if version2 => {
                    let link = parse_link(link)?;
                    let p = prefix(address, length)?;
                    let preferred = lifetime(preferred)?;
                    let valid = lifetime(valid)?;
                    if preferred > valid
                        || r.on_link.keys().filter(|(l, _)| *l == link).count() >= 160
                        || r.on_link.contains_key(&(link, p))
                    {
                        return Err(invalid());
                    }
                    if valid.live(now) {
                        r.on_link.insert((link, p), OnLink { preferred, valid });
                    }
                }
                ["L", link, last, at] if version2 => {
                    let link = parse_link(link)?;
                    let state = &mut r.links[link.index()];
                    state.last_valid = lifetime(last)?;
                    state.deprecate_at = origin(at)?;
                    if state
                        .deprecate_at
                        .is_some_and(|at| deprecation_remaining(at, now) > 0)
                    {
                        state.state = AilState::Deprecating;
                    }
                }
                ["H", link, address, length, valid, count] if version2 => {
                    let link = parse_link(link)?;
                    let length = u8::try_from(parse(length)?).map_err(|_| invalid())?;
                    let p = Prefix::new(address.parse().map_err(|_| invalid())?, length)
                        .filter(|p| p.routable() || p.length == 0)
                        .ok_or_else(invalid)?;
                    let valid = lifetime(valid)?;
                    let count = u8::try_from(parse(count)?).map_err(|_| invalid())?;
                    if count > 3
                        || r.advertised_routes.contains_key(&(link, p))
                        || r.advertised_routes
                            .keys()
                            .filter(|(l, _)| *l == link)
                            .map(|(_, p)| {
                                Rio {
                                    prefix: *p,
                                    preference: Preference::Low,
                                    lifetime: 0,
                                }
                                .encode()
                                .len()
                            })
                            .sum::<usize>()
                            + (Rio {
                                prefix: p,
                                preference: Preference::Low,
                                lifetime: 0,
                            })
                            .encode()
                            .len()
                            > Self::route_budget(link)
                    {
                        return Err(invalid());
                    }
                    if valid.live(now) {
                        r.advertised_routes.insert((link, p), valid);
                        if count > 0 {
                            r.withdrawals.insert((link, p), count);
                        }
                    }
                }
                ["I", link, address, net, length, attempts] if version2 => {
                    let link = parse_link(link)?;
                    let p = prefix(net, length)?;
                    let address = address.parse().map_err(|_| invalid())?;
                    let attempts = u8::try_from(parse(attempts)?).map_err(|_| invalid())?;
                    if !p.contains(address)
                        || attempts > 3
                        || owned_addresses.keys().filter(|(l, _)| *l == link).count() >= 31
                        || owned_addresses
                            .insert(
                                (link, address),
                                OwnedAddress {
                                    probe_sent: false,
                                    prefix: Some(p),
                                    state: DadState::Tentative,
                                    deadline: Some(now),
                                    attempts,
                                },
                            )
                            .is_some()
                    {
                        return Err(invalid());
                    }
                }
                ["F", at] if version2 => {
                    if fallback.is_some() {
                        return Err(invalid());
                    }
                    fallback = Some(lifetime(at)?);
                }
                ["D", address, iaid, net, length, at, last] if version2 => {
                    let p = prefix(address, "64")?;
                    let lease = prefix(net, length)?;
                    let iaid = u32::try_from(parse(iaid)?).map_err(|_| invalid())?;
                    if ![1, 2].contains(&iaid)
                        || !lease.contains(p.address)
                        || owned_prefixes.len() >= 16
                        || owned_prefixes
                            .insert(
                                p,
                                pd::OwnedPrefix {
                                    lease: (iaid, lease),
                                    deprecate_at: origin(at)?,
                                    last_valid: lifetime(last)?,
                                },
                            )
                            .is_some()
                    {
                        return Err(invalid());
                    }
                }
                ["A", evidence] => {
                    let bytes = unhex(evidence)?;
                    if r.attachment.known.len() >= attachment::MAX_ATTACHMENT_IDENTITIES
                        || bytes.is_empty()
                        || bytes.len() > 128
                        || !r.attachment.known.insert(bytes)
                    {
                        return Err(invalid());
                    }
                }
                ["R", link, address, end] => {
                    let link = match *link {
                        "0" => Link::Ail,
                        "1" => Link::Stub,
                        _ => return Err(invalid()),
                    };
                    let prefix = Prefix::new(address.parse().map_err(|_| invalid())?, 64)
                        .filter(|p| p.ula())
                        .ok_or_else(invalid)?;
                    let valid = lifetime(end)?;
                    if r.retired_ulas.len() >= attachment::MAX_RETIRED_PREFIXES
                        || r.retired_ulas.insert((link, prefix), valid).is_some()
                    {
                        return Err(invalid());
                    }
                    if valid.live(now) && !version2 {
                        r.on_link.insert(
                            (link, prefix),
                            OnLink {
                                valid,
                                preferred: Lifetime::Until(now),
                            },
                        );
                    }
                }
                ["U", link, end] => {
                    let link = match *link {
                        "0" => Link::Ail,
                        "1" => Link::Stub,
                        _ => return Err(invalid()),
                    };
                    let valid = lifetime(end)?;
                    if valid.live(now) {
                        r.on_link.insert(
                            (link, r.identity.prefix(link)),
                            OnLink {
                                valid,
                                preferred: Lifetime::Until(now),
                            },
                        );
                        r.links[link.index()].last_valid = valid;
                    }
                }
                ["P", iaid, address, length, server, preferred, valid, t1, t2] => {
                    let iaid = u32::try_from(parse(iaid)?).map_err(|_| invalid())?;
                    let length = u8::try_from(parse(length)?).map_err(|_| invalid())?;
                    let prefix = Prefix::new(address.parse().map_err(|_| invalid())?, length)
                        .filter(|p| p.routable() && p.length <= 64)
                        .ok_or_else(invalid)?;
                    let server = unhex(server)?;
                    let valid = lifetime(valid)?;
                    let preferred = lifetime(preferred)?;
                    if ![1, 2].contains(&iaid)
                        || server.is_empty()
                        || server.len() > 128
                        || r.pd.leases.len() >= 16
                        || preferred > valid
                    {
                        return Err(invalid());
                    }
                    if valid.live(now) {
                        r.pd.leases.insert(
                            (iaid, prefix),
                            pd::Lease {
                                association: std::rc::Rc::new(pd::Association {
                                    iaid,
                                    server,
                                    t1: lifetime(t1)?,
                                    t2: lifetime(t2)?,
                                }),
                                preferred,
                                valid,
                                used: true,
                            },
                        );
                    }
                }
                _ => return Err(invalid()),
            }
        }
        let mut associations = BTreeMap::new();
        for ((iaid, _), lease) in &mut r.pd.leases {
            let key = (*iaid, lease.server.clone());
            let shared = associations
                .entry(key)
                .or_insert_with(|| lease.association.clone());
            if **shared != *lease.association {
                return Err(invalid());
            }
            lease.association = shared.clone();
        }
        if let Some(fallback) = fallback {
            r.pd.fallback_at = Some(match fallback {
                Lifetime::Until(at) => at,
                Lifetime::Infinite => u64::MAX,
            });
        }
        if !r.pd.leases.is_empty() {
            r.pd.refresh(6, now, rng)?;
            if wall < saved_wall {
                r.pd.fallback_at = Some(now);
            }
            r.sync_pd(now, rng)?;
        }
        for (p, owned) in owned_prefixes {
            if let Some(lease) = r.pd.leases.get(&owned.lease) {
                r.on_link.insert(
                    (Link::Stub, p),
                    OnLink {
                        valid: lease.valid,
                        preferred: if owned.deprecate_at.is_some() {
                            Lifetime::Until(now)
                        } else {
                            lease.preferred
                        },
                    },
                );
                r.pd_prefixes.insert(p, owned);
            }
        }
        for (key, owned) in owned_addresses {
            if owned
                .prefix
                .is_some_and(|p| r.on_link.contains_key(&(key.0, p)))
            {
                r.owned.insert(key, owned);
            }
        }
        Ok(r)
    }
}
pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
pub(crate) fn unhex(s: &str) -> io::Result<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return Err(io::Error::other("invalid hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|n| u8::from_str_radix(&s[n..n + 2], 16).map_err(io::Error::other))
        .collect()
}
