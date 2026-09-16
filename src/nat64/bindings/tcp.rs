use super::*;
use crate::nat64::tcp::{State, TRANSITORY};
impl Bindings {
    pub fn tcp_state(
        &self,
        source: Ipv6Addr,
        port: u16,
        remote: SocketAddrV4,
    ) -> Option<(State, u64)> {
        let s = self.sessions.get(&((6, source, port), remote))?;
        Some((s.tcp?, s.expires))
    }
    pub fn take_tcp_probes(&mut self, limit: usize) -> Vec<(Ipv6Addr, u16, u16, SocketAddrV4)> {
        let mut out = vec![];
        for ((key, remote), s) in &mut self.sessions {
            if out.len() >= limit.min(32) {
                break;
            }
            if s.probe {
                s.probe = false;
                out.push((key.1, key.2, self.bindings[key].port, *remote));
            }
        }
        out
    }
    fn tcp_session(&mut self, key: Key, remote: SocketAddrV4, v6: bool, flags: u8, now: u64) {
        let expires = if let Some(s) = self.sessions.get_mut(&(key, remote)) {
            let (state, expires) = s.tcp.unwrap().packet(v6, flags, s.expires, now);
            s.tcp = Some(state);
            s.expires = expires;
            s.probe = false;
            expires
        } else {
            let expires = now.saturating_add(TRANSITORY);
            self.sessions.insert(
                (key, remote),
                Session {
                    expires,
                    tcp: Some(if v6 { State::V6Init } else { State::V4Init }),
                    probe: false,
                },
            );
            self.bindings.get_mut(&key).unwrap().sessions += 1;
            self.hosts.get_mut(&key.1).unwrap().1 += 1;
            expires
        };
        self.next = Some(self.next.map_or(expires, |old| old.min(expires)));
    }
    pub fn tcp_out(
        &mut self,
        source: Ipv6Addr,
        port: u16,
        remote: SocketAddrV4,
        flags: u8,
        now: u64,
        rng: &mut impl RandomSource,
    ) -> io::Result<Option<u16>> {
        self.expire(now);
        let key = (6, source, port);
        // Security policy declines midstream creation. An existing session
        // still follows every retransmission/half-close transition in the RFC.
        if !self.sessions.contains_key(&(key, remote)) && flags & 2 == 0 {
            return Ok(None);
        }
        self.admit(key, remote)?;
        let assigned = if let Some(b) = self.bindings.get(&key) {
            b.port
        } else {
            let port = self.allocate(6, port, rng, |_| false)?;
            let lease = self.ports.claim(6, port, Owner::Translation)?;
            self.bindings.insert(
                key,
                Binding {
                    _port: lease,
                    port,
                    sessions: 0,
                },
            );
            self.reverse.insert((6, port), key);
            self.hosts.entry(source).or_default().0 += 1;
            port
        };
        self.tcp_session(key, remote, true, flags, now);
        Ok(Some(assigned))
    }
    pub fn tcp_in(
        &mut self,
        port: u16,
        remote: SocketAddrV4,
        flags: u8,
        now: u64,
    ) -> io::Result<Option<(Ipv6Addr, u16)>> {
        self.expire(now);
        // No externally initiated binding creation. With a live BIB, use
        // endpoint-independent filtering for SYN, then exact remote sessions.
        let Some(key) = self.reverse.get(&(6, port)).copied() else {
            return Ok(None);
        };
        if !self.sessions.contains_key(&(key, remote)) && flags & 2 == 0 {
            return Ok(None);
        }
        self.admit(key, remote)?;
        self.tcp_session(key, remote, false, flags, now);
        Ok(Some((key.1, key.2)))
    }
}
