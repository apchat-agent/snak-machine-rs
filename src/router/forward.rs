use super::*;
impl Router {
    pub fn receive_frame(
        &mut self,
        link: Link,
        kind: FrameKind,
        frame: &[u8],
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<Vec<Tx>> {
        let Ok(e) = envelope(kind, frame) else {
            return Ok(vec![]);
        };
        if kind == FrameKind::Ethernet {
            let own = self.links[link.index()]
                .mac
                .unwrap_or(self.identity.macs[link.index()]);
            if frame[6..12] == own || (frame[0] & 1 == 0 && frame[..6] != own) {
                return Ok(vec![]);
            }
        }
        match hop_options(&e) {
            Err(_) => return Ok(vec![]),
            Ok(Some(pointer)) => {
                return Ok(
                    if matches!(
                        self.lifecycle,
                        Lifecycle::Running | Lifecycle::AilUnavailable
                    ) {
                        self.icmp_error(link, &e, 4, 2, pointer, now)
                    } else {
                        vec![]
                    },
                );
            }
            Ok(None) => {}
        }
        let Ok(t) = transport(&e) else {
            return Ok(vec![]);
        };
        if (t.protocol == 58 && t.bytes.first().is_some_and(|v| (133..=136).contains(v)))
            || self.owned.contains_key(&(link, e.destination))
            || e.destination.is_multicast()
        {
            return self.receive(link, e.packet, now, rng);
        }
        self.forward(link, &e, now)
    }
    pub fn lookup(
        &self,
        ingress: Link,
        destination: Ipv6Addr,
        now: Time,
    ) -> Option<(Link, Ipv6Addr)> {
        if self
            .on_link
            .iter()
            .any(|((l, p), v)| *l == Link::Stub && p.contains(destination) && v.valid.live(now))
        {
            return if ingress == Link::Ail {
                Some((Link::Stub, destination))
            } else {
                None
            };
        }
        if ingress == Link::Ail {
            return None;
        }
        self.egress_next_hop(Link::Ail, destination, now)
            .map(|a| (Link::Ail, a))
    }
    fn egress_next_hop(&self, egress: Link, destination: Ipv6Addr, now: Time) -> Option<Ipv6Addr> {
        if link_local(destination)
            || destination.is_multicast()
            || self
                .on_link
                .iter()
                .any(|((l, p), v)| *l == egress && p.contains(destination) && v.valid.live(now))
        {
            return Some(destination);
        }
        if egress == Link::Stub {
            return Some(destination);
        }
        self.routes
            .iter()
            .filter(|((a, p), r)| p.contains(destination) && self.usable_route(*a, r, now))
            .max_by_key(|((a, p), r)| {
                (
                    p.length,
                    self.reachable(
                        RouterKey {
                            link: Link::Ail,
                            address: *a,
                        },
                        now,
                    ),
                    r.preference,
                    std::cmp::Reverse(*a),
                )
            })
            .map(|((a, _), _)| *a)
    }
    pub fn encapsulate(&self, tx: &Tx, kind: FrameKind, now: Time) -> io::Result<Vec<u8>> {
        if kind == FrameKind::RawIpv6 {
            return Ok(tx.packet.clone());
        }
        let e = envelope(FrameKind::RawIpv6, &tx.packet)
            .map_err(|_| io::Error::other("invalid transmit packet"))?;
        let dest = if e.destination.is_multicast() {
            let a = e.destination.octets();
            [0x33, 0x33, a[12], a[13], a[14], a[15]]
        } else {
            let next = self
                .egress_next_hop(tx.link, e.destination, now)
                .ok_or_else(|| io::Error::other("no next hop"))?;
            self.neighbors
                .get(&RouterKey {
                    link: tx.link,
                    address: next,
                })
                .and_then(|n| n.mac)
                .ok_or_else(|| io::Error::new(io::ErrorKind::WouldBlock, "neighbor unresolved"))?
        };
        let mut b = dest.to_vec();
        b.extend(
            self.links[tx.link.index()]
                .mac
                .unwrap_or(self.identity.macs[tx.link.index()]),
        );
        b.extend([0x86, 0xdd]);
        b.extend(&tx.packet);
        Ok(b)
    }
    pub(super) fn forward(
        &mut self,
        link: Link,
        e: &Envelope<'_>,
        now: Time,
    ) -> io::Result<Vec<Tx>> {
        if matches!(
            self.lifecycle,
            Lifecycle::Starting | Lifecycle::Stopping | Lifecycle::Stopped | Lifecycle::Degraded
        ) || !self.links[0].up
            || !self.links[1].up
            || e.source.is_unspecified()
            || e.source.is_multicast()
            || e.source.is_loopback()
            || link_local(e.source)
            || e.destination.is_multicast()
            || link_local(e.destination)
            || e.destination.is_loopback()
            || e.destination.is_unspecified()
        {
            return Ok(vec![]);
        }
        if link == Link::Stub
            && self.on_link.iter().any(|((l, p), v)| {
                *l == Link::Stub && p.contains(e.destination) && v.valid.live(now)
            })
        {
            return Ok(vec![]);
        }
        let Some((egress, next)) = self.lookup(link, e.destination, now) else {
            return Ok(self.icmp_error(link, e, 1, 0, 0, now));
        };
        if e.hop_limit <= 1 {
            return Ok(self.icmp_error(link, e, 3, 0, 0, now));
        }
        if e.packet.len() > self.links[egress.index()].mtu as usize {
            return Ok(self.icmp_error(link, e, 2, 0, self.links[egress.index()].mtu, now));
        }
        self.reap_failed_neighbors(now);
        let key = RouterKey {
            link: egress,
            address: next,
        };
        if self.links[egress.index()].kind == FrameKind::Ethernet
            && self
                .neighbors
                .get(&key)
                .is_none_or(|n| n.mac.is_none() || n.state == NeighborState::Failed)
        {
            if self
                .neighbors
                .get(&key)
                .is_some_and(|n| n.state == NeighborState::Failed)
            {
                return Ok(self.icmp_error(link, e, 1, 3, 0, now));
            }
            return self.queue_neighbor(
                key,
                Pending::Transit(Tx {
                    link,
                    packet: e.packet.to_vec(),
                }),
                now,
            );
        }
        if let Some(n) = self.neighbors.get_mut(&key) {
            if n.state == NeighborState::Stale {
                n.state = NeighborState::Delay;
                n.deadline = Some(now + 5000);
                n.probes_sent = 0;
            }
        }
        let mut packet = e.packet.to_vec();
        packet[7] -= 1;
        Ok(vec![Tx {
            link: egress,
            packet,
        }])
    }
    // One datagram per unresolved next hop, 64 total. IPv6's 16-bit
    // payload limit also bounds retained packet bytes to 64 * 65575.
    fn queue_neighbor(
        &mut self,
        key: RouterKey,
        pending: Pending,
        now: Time,
    ) -> io::Result<Vec<Tx>> {
        if (!self.neighbors.contains_key(&key)
            && self.neighbors.keys().filter(|k| k.link == key.link).count() >= 256)
            || (self.neighbors.get(&key).is_none_or(|n| n.pending.is_none())
                && self
                    .neighbors
                    .values()
                    .filter(|n| n.pending.is_some())
                    .count()
                    >= 64)
        {
            return Ok(vec![]);
        }
        let n = self.neighbors.entry(key).or_insert(Neighbor {
            mac: None,
            state: NeighborState::Incomplete,
            deadline: None,
            probes_sent: 0,
            is_router: false,
            pending: None,
        });
        n.pending = Some(pending);
        if n.probes_sent == 0 {
            return Ok(vec![self.probe(key, now)?]);
        }
        Ok(vec![])
    }
    pub fn resolve_output(&mut self, tx: Tx, now: Time) -> io::Result<Vec<Tx>> {
        self.reap_failed_neighbors(now);
        let Ok(e) = envelope(FrameKind::RawIpv6, &tx.packet) else {
            return Ok(vec![]);
        };
        if self.links[tx.link.index()].kind == FrameKind::RawIpv6 || e.destination.is_multicast() {
            return Ok(vec![tx]);
        }
        let Some(next) = self.egress_next_hop(tx.link, e.destination, now) else {
            return Ok(vec![]);
        };
        let key = RouterKey {
            link: tx.link,
            address: next,
        };
        if self
            .neighbors
            .get(&key)
            .is_some_and(|n| n.mac.is_some() && n.state != NeighborState::Failed)
        {
            return Ok(vec![tx]);
        }
        self.queue_neighbor(key, Pending::Output(tx), now)
    }
    pub(super) fn icmp_error(
        &mut self,
        link: Link,
        e: &Envelope<'_>,
        kind: u8,
        code: u8,
        value: u32,
        now: Time,
    ) -> Vec<Tx> {
        if self.error_after.is_some_and(|t| now < t)
            || e.source.is_unspecified()
            || e.source.is_multicast()
            || e.source.is_loopback()
            || link_local(e.source)
            || (e.destination.is_multicast() && kind != 2 && !(kind == 4 && code == 2))
        {
            return vec![];
        }
        if let Ok(t) = transport(e) {
            if t.protocol == 58 && t.bytes.first().is_some_and(|b| *b < 128) {
                return vec![];
            }
        }
        let Some(source) = self
            .owned
            .iter()
            .filter(|((l, a), v)| *l == link && v.state == DadState::Ready && !link_local(*a))
            .map(|((_, a), _)| *a)
            .next()
        else {
            return vec![];
        };
        let mut b = vec![kind, code, 0, 0];
        b.extend(value.to_be_bytes());
        b.extend(&e.packet[..e.packet.len().min(1232)]);
        self.error_after = Some(now + 100);
        vec![Tx {
            link,
            packet: icmp_packet(source, e.source, 64, b).unwrap(),
        }]
    }
}
