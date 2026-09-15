use super::*;
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
            for ((l, p), v) in &self.on_link {
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
            "SNAC-SNAPSHOT-1 {wall}\n{}\n",
            hex(&self.identity.encode()?)
        );
        for link in [Link::Ail, Link::Stub] {
            let p = self.identity.prefix(link);
            if let Some(v) = self.on_link.get(&(link, p)) {
                text.push_str(&format!("U {} {}\n", link.index(), end(v.valid, now, wall)));
            }
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
        Ok(text.into_bytes())
    }
    pub fn restore(
        bytes: &[u8],
        now: Time,
        wall: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Self> {
        let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid SNAC snapshot");
        let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
        let mut lines = text.lines();
        let first = lines.next().ok_or_else(invalid)?;
        let saved_wall: u64 = first
            .strip_prefix("SNAC-SNAPSHOT-1 ")
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
        for line in lines {
            let fields: Vec<_> = line.split_whitespace().collect();
            match fields.as_slice() {
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
                                server,
                                preferred,
                                valid,
                                t1: lifetime(t1)?,
                                t2: lifetime(t2)?,
                                used: true,
                            },
                        );
                    }
                }
                _ => return Err(invalid()),
            }
        }
        if !r.pd.leases.is_empty() {
            r.pd.refresh(6, now, rng)?;
            if wall < saved_wall {
                r.pd.fallback_at = Some(now);
            }
            r.sync_pd(now, rng)?;
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
