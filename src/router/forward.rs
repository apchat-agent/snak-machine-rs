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
            let own = self.identity.macs[link.index()];
            if frame[6..12] == own || (frame[0] & 1 == 0 && frame[..6] != own) {
                return Ok(vec![]);
            }
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
    pub fn encapsulate(&self, tx: &Tx, kind: FrameKind) -> io::Result<Vec<u8>> {
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
                .egress_next_hop(tx.link, e.destination, 0)
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
        b.extend(self.identity.macs[tx.link.index()]);
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
        let Some((egress, _next)) = self.lookup(link, e.destination, now) else {
            return Ok(vec![]);
        };
        let mut packet = e.packet.to_vec();
        packet[7] = packet[7].saturating_sub(1);
        Ok(vec![Tx {
            link: egress,
            packet,
        }])
    }
}
