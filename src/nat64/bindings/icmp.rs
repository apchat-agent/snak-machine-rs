use super::*;
use std::net::Ipv4Addr;
impl Bindings {
    pub fn set_icmp_timeout(&mut self, seconds: u32) -> io::Result<()> {
        if !(60..=86400).contains(&seconds) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ICMP timeout must be 60..86400 seconds",
            ));
        }
        self.icmp_seconds = seconds;
        Ok(())
    }
    fn icmp_session(&mut self, key: Key, remote: Ipv4Addr, now: u64) {
        let expires = now.saturating_add(u64::from(self.icmp_seconds) * 1000);
        let remote = SocketAddrV4::new(remote, 0);
        if self
            .sessions
            .insert(
                (key, remote),
                Session {
                    expires,
                    tcp: None,
                    probe: false,
                    syn_quote: vec![],
                },
            )
            .is_none()
        {
            self.bindings.get_mut(&key).unwrap().sessions += 1;
            self.hosts.get_mut(&key.1).unwrap().1 += 1;
        }
        self.next = Some(self.next.map_or(expires, |old| old.min(expires)));
    }
    pub fn icmp_out(
        &mut self,
        source: Ipv6Addr,
        id: u16,
        remote: Ipv4Addr,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<u16> {
        self.expire(now);
        let key = (1, source, id, self.domain);
        self.admit(key, SocketAddrV4::new(remote, 0))?;
        let assigned = if let Some(b) = self.bindings.get(&key) {
            b.port
        } else {
            let id = self.allocate(1, id, rng, |_| false)?;
            let lease = self.ports.claim(1, id, Owner::Translation)?;
            self.bindings.insert(
                key,
                Binding {
                    _port: lease,
                    port: id,
                    sessions: 0,
                },
            );
            self.reverse.insert((1, id), key);
            self.hosts.entry(source).or_default().0 += 1;
            id
        };
        self.icmp_session(key, remote, now);
        Ok(assigned)
    }
    pub fn icmp_in(
        &mut self,
        id: u16,
        remote: Ipv4Addr,
        now: u64,
    ) -> io::Result<Option<(Ipv6Addr, u16)>> {
        self.expire(now);
        let Some(key) = self.reverse.get(&(1, id)).copied() else {
            return Ok(None);
        };
        // Address-dependent query filtering. Unsolicited ICMP never opens
        // state, and ICMP errors use a separate non-refreshing lookup.
        if !self
            .sessions
            .contains_key(&(key, SocketAddrV4::new(remote, 0)))
        {
            return Ok(None);
        }
        self.icmp_session(key, remote, now);
        self.domain = key.3;
        Ok(Some((key.1, key.2)))
    }
}
