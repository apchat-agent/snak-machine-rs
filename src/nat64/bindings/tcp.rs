use super::*;
use crate::nat64::tcp::{State, TRANSITORY};
impl Bindings {
    pub fn tcp_timeout_load(&self) -> (usize, usize) {
        (
            self.tcp_timeouts.len(),
            self.tcp_timeouts.iter().map(Vec::len).sum(),
        )
    }
    pub(crate) fn take_tcp_timeouts(&mut self, limit: usize) -> Vec<Vec<u8>> {
        self.tcp_timeouts
            .drain(..limit.min(32).min(self.tcp_timeouts.len()))
            .collect()
    }
    pub(crate) fn remember_tcp_syn(&mut self, port: u16, remote: SocketAddrV4, packet: &[u8]) {
        let Some(key) = self.reverse.get(&(6, port)) else {
            return;
        };
        let Some(session) = self.sessions.get_mut(&(*key, remote)) else {
            return;
        };
        if session.tcp == Some(State::V4Init) && session.syn_quote.is_empty() {
            let header = usize::from(packet[0] & 15) * 4;
            session.syn_quote = packet[..(header + 8).min(packet.len()).min(68)].to_vec();
            self.tcp_quote_bytes += session.syn_quote.len();
        }
    }
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
            if state != State::V4Init {
                self.tcp_quote_bytes -= s.syn_quote.len();
                s.syn_quote = vec![];
            }
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
                    syn_quote: vec![],
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
    pub(crate) fn tcp_in_packet(
        &mut self,
        port: u16,
        remote: SocketAddrV4,
        flags: u8,
        now: u64,
        packet: &[u8],
    ) -> io::Result<Option<(Ipv6Addr, u16)>> {
        self.expire(now);
        let Some(key) = self.reverse.get(&(6, port)).copied() else {
            return Ok(None);
        };
        let session = self.sessions.get(&(key, remote));
        let needs_quote = flags & 2 != 0
            && session.is_none_or(|s| s.tcp == Some(State::V4Init) && s.syn_quote.is_empty());
        if needs_quote {
            let quote = (usize::from(packet[0] & 15) * 4 + 8)
                .min(packet.len())
                .min(68);
            let added = quote + usize::from(session.is_none()) * 256;
            if self.charged_bytes() + added > 4 * 1024 * 1024 {
                return Err(full());
            }
        }
        let result = self.tcp_in(port, remote, flags, now)?;
        if needs_quote && result.is_some() {
            self.remember_tcp_syn(port, remote, packet);
        }
        Ok(result)
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
