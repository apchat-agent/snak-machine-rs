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
        let Some(nat) = &mut self.nat64 else {
            return Ok(true);
        };
        let router = &self.router;
        let ipv4 = &self.ipv4;
        let output = nat.outbound(
            e.packet,
            now,
            rng,
            |source| {
                !router.owned.contains_key(&(Link::Stub, source))
                    && router.on_link.iter().any(|((link, p), v)| {
                        *link == Link::Stub
                            && p.routable()
                            && p.contains(source)
                            && v.valid.live(now)
                    })
            },
            |destination| ipv4.next_hop(destination).is_some(),
        );
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
            let translated = crate::ipv4::wire::Packet::parse(&packet)
                .ok()
                .is_some_and(|p| {
                    p.protocol == 17
                        && p.payload.len() >= 4
                        && self.nat64.as_ref().is_some_and(|n| {
                            n.bindings
                                .owns(17, u16::from_be_bytes([p.payload[2], p.payload[3]]))
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
