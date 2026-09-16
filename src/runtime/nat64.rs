use super::*;
use crate::{
    nat64::Translator,
    wire::{envelope, FrameKind},
};
impl<I: PacketIo> Driver<I> {
    pub(super) fn sync_nat64(&mut self, now: Time) -> io::Result<()> {
        let address = self.ipv4.address.map(|a| a.0).filter(|_| {
            self.router.nat64.policy().enabled
                && self.router.lifecycle == Lifecycle::Running
                && self.router.links.iter().all(|l| l.up)
        });
        if let Some(nat) = &mut self.nat64 {
            nat.set_ipv4(address)?;
            nat.bindings.expire(now);
        } else if let (Some(address), Some(stacks)) = (address, &self.stacks) {
            self.nat64 = Some(Translator::new(
                self.router.nat64.local_prefix(),
                address,
                stacks[0].ports(),
            )?);
        }
        if let Some(nat) = &mut self.nat64 {
            nat.set_mtus([self.router.links[0].mtu, self.router.links[1].mtu]);
        }
        Ok(())
    }
    pub(super) fn receive_nat64(
        &mut self,
        rx: &crate::io::Received,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<bool> {
        self.sync_nat64(now)?;
        let Ok(e) = envelope(rx.kind, &rx.bytes) else {
            return Ok(false);
        };
        if !self.router.nat64.local_prefix().contains(e.destination) {
            return Ok(false);
        }
        // Consume local-prefix traffic even when unavailable. It must never
        // escape to an infrastructure default route or enter from the AIL.
        if rx.link != Link::Stub
            || self.router.lifecycle != Lifecycle::Running
            || !self.router.links.iter().all(|l| l.up)
        {
            return Ok(true);
        }
        if rx.kind == FrameKind::Ethernet {
            let own = self.router.links[1]
                .mac
                .unwrap_or(self.router.identity.macs[1]);
            if rx.bytes[..6] != own
                || rx.bytes[6..12] == own
                || rx.bytes[6..12] == [0; 6]
                || rx.bytes[6] & 1 != 0
            {
                return Ok(true);
            }
        }
        let router = &self.router;
        let source_allowed = |source| {
            !router.owned.contains_key(&(Link::Stub, source))
                && router.on_link.iter().any(|((link, p), v)| {
                    *link == Link::Stub && p.routable() && p.contains(source) && v.valid.live(now)
                })
        };
        if !source_allowed(e.source)
            || e.source.is_unspecified()
            || e.source.is_multicast()
            || e.source.is_loopback()
            || crate::wire::link_local(e.source)
            || self.router.nat64.local_prefix().contains(e.source)
        {
            return Ok(true);
        }
        let (Some(nat), Some(stacks)) = (&mut self.nat64, &mut self.stacks) else {
            return Ok(true);
        };
        let Ok(Some(datagram)) = stacks[1].reassemble_nat(e.packet, now) else {
            return Ok(true);
        };
        let output = nat.outbound_datagram(&datagram, now, rng, source_allowed, |dest| {
            self.ipv4.next_hop(dest).is_some()
        });
        if let Ok(output) = output {
            self.dispatch_nat64(output, now, rng)?;
        }
        Ok(true)
    }
    pub(super) fn poll_nat64(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.sync_nat64(now)?;
        // Keep the existing endpoint input queue and its aggregate bound.
        // Distribute validated IPv4 datagrams before the local stack polls.
        while let Some(packet) = self.ipv4.take_packet() {
            let Some(stacks) = &mut self.stacks else {
                continue;
            };
            let Ok(Some(datagram)) = stacks[0].reassemble_nat(&packet, now) else {
                continue;
            };
            let packet = datagram.packet;
            let translated = crate::ipv4::wire::Packet::parse(&packet)
                .ok()
                .is_some_and(|p| {
                    self.nat64.as_ref().is_some_and(|n| {
                        let id = if [6, 17].contains(&p.protocol) && p.payload.len() >= 4 {
                            Some(u16::from_be_bytes([p.payload[2], p.payload[3]]))
                        } else if p.protocol == 1
                            && p.payload.len() >= 8
                            && [0, 8].contains(&p.payload[0])
                        {
                            Some(u16::from_be_bytes([p.payload[4], p.payload[5]]))
                        } else if p.protocol == 1 && p.payload.len() >= 36 {
                            return crate::ipv4::wire::Packet::quoted(&p.payload[8..])
                                .ok()
                                .is_some_and(|q| {
                                    let port =
                                        if [6, 17].contains(&q.protocol) && q.payload.len() >= 8 {
                                            Some(u16::from_be_bytes([q.payload[0], q.payload[1]]))
                                        } else if q.protocol == 1
                                            && q.payload.len() >= 8
                                            && [0, 8].contains(&q.payload[0])
                                        {
                                            Some(u16::from_be_bytes([q.payload[4], q.payload[5]]))
                                        } else {
                                            None
                                        };
                                    port.is_some_and(|port| n.bindings.owns(q.protocol, port))
                                });
                        } else {
                            None
                        };
                        id.is_some_and(|id| n.bindings.owns(p.protocol, id))
                    })
                });
            if translated {
                let p = crate::ipv4::wire::Packet::parse(&packet).unwrap();
                if self.ipv4.address.is_some_and(|a| a.0 == p.source)
                    || self.ipv4.next_hop(p.source).is_none()
                {
                    continue;
                }
                if let Ok(output) = self.nat64.as_mut().unwrap().inbound(&packet, now) {
                    self.dispatch_nat64(output, now, rng)?;
                }
            } else if let Some(stacks) = &mut self.stacks {
                let _ = stacks[0].input(&packet, now);
            }
        }
        if let Some(nat) = &mut self.nat64 {
            let output = nat.poll(now)?;
            self.dispatch_nat64(output, now, rng)?;
        }
        Ok(())
    }
    fn dispatch_nat64(
        &mut self,
        output: Vec<Tx>,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<()> {
        for tx in output {
            if tx.link == Link::Ail {
                if let Err(error) = self.send_ipv4(&tx.packet, now, rng) {
                    if error.kind() != io::ErrorKind::WouldBlock {
                        return Err(error);
                    }
                }
            } else {
                self.dispatch(vec![tx], now, rng)?;
            }
        }
        Ok(())
    }
}
