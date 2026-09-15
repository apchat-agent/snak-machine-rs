use super::*;
use crate::{
    dns::wire::Message,
    mdns::wire::{encode, multicast, Datagram},
    wire::{self, FrameKind},
};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
};
pub(super) struct Output {
    id: u64,
    messages: VecDeque<Message>,
    packets: VecDeque<Vec<u8>>,
    sources: Vec<IpAddr>,
    pub(super) retry: Time,
}
impl<I: PacketIo> Driver<I> {
    fn mdns_sources(&self) -> Vec<IpAddr> {
        if !self.router.links[0].up
            || !matches!(
                self.router.lifecycle,
                Lifecycle::Starting | Lifecycle::Running
            )
        {
            return vec![];
        }
        let mut out = vec![];
        let v6 = self.router.identity.link_local(Link::Ail);
        if self.router.address_ready(Link::Ail, v6) {
            out.push(IpAddr::V6(v6));
        }
        if self.io.info(Link::Ail).kind == FrameKind::Ethernet {
            if let Some((v4, _)) = self.ipv4.address {
                out.push(IpAddr::V4(v4));
            }
        }
        out
    }
    pub(super) fn receive_mdns(
        &mut self,
        rx: &crate::io::Received,
        now: Time,
        rng: &mut impl RandomSource,
    ) -> io::Result<bool> {
        if rx.link != Link::Ail || self.stacks.is_none() || self.mdns_sources().is_empty() {
            return Ok(false);
        }
        let raw = if rx.kind == FrameKind::Ethernet {
            if rx.bytes.len() < 14
                || ![[8, 0], [0x86, 0xdd]].contains(&rx.bytes[12..14].try_into().unwrap())
            {
                return Ok(false);
            }
            &rx.bytes[14..]
        } else {
            &rx.bytes
        };
        let (source, destination, fragmented, body, on_link) = match raw.first().map(|b| b >> 4) {
            Some(6) => {
                let Ok(e) = wire::envelope(FrameKind::RawIpv6, raw) else {
                    return Ok(false);
                };
                if e.hop_limit != 255
                    || e.source.is_unspecified()
                    || e.source.is_multicast()
                    || e.source.is_loopback()
                    || e.source.to_ipv4_mapped().is_some()
                    || !wire::hop_options(&e).is_ok_and(|v| v.is_none())
                {
                    return Ok(false);
                }
                let Ok(t) = wire::transport(&e) else {
                    return Ok(false);
                };
                if t.protocol != 17 {
                    return Ok(false);
                }
                let on_link = e.source.is_unicast_link_local()
                    || self.router.on_link.iter().any(|((link, prefix), v)| {
                        *link == Link::Ail && v.valid.live(now) && prefix.contains(e.source)
                    });
                (
                    IpAddr::V6(e.source),
                    IpAddr::V6(e.destination),
                    t.fragmented,
                    if t.non_initial { None } else { Some(t.bytes) },
                    on_link,
                )
            }
            Some(4) => {
                let Ok(p) = crate::ipv4::wire::Packet::parse(raw) else {
                    return Ok(false);
                };
                let Some((address, length)) = self.ipv4.address else {
                    return Ok(false);
                };
                if p.ttl != 255 || p.protocol != 17 || !crate::ipv4::unicast(p.source) {
                    return Ok(false);
                }
                let mask = u32::MAX.checked_shl(32 - u32::from(length)).unwrap_or(0);
                (
                    IpAddr::V4(p.source),
                    IpAddr::V4(p.destination),
                    p.more_fragments || p.fragment_offset != 0,
                    if p.fragment_offset != 0 {
                        None
                    } else {
                        Some(p.payload)
                    },
                    u32::from(address) & mask == u32::from(p.source) & mask,
                )
            }
            _ => return Ok(false),
        };
        let multicast = destination == multicast(source.is_ipv6());
        let owned = match destination {
            IpAddr::V6(a) => self.router.address_ready(Link::Ail, a),
            IpAddr::V4(a) => self.ipv4.address.is_some_and(|v| v.0 == a),
        };
        if !multicast && !owned {
            return Ok(false);
        }
        if body.is_some_and(|b| b.len() < 4 || b[2..4] != [0x14, 0xe9]) {
            return Ok(false);
        }
        if rx.kind == FrameKind::Ethernet {
            let expected = if multicast {
                multicast_mac(destination)
            } else {
                self.ipv4.mac
            };
            if rx.bytes[..6] != expected
                || rx.bytes[6] & 1 != 0
                || rx.bytes[6..12] == [0; 6]
                || rx.bytes[6..12] == self.ipv4.mac
            {
                return Ok(true);
            }
        }
        if raw.len() > 9000 {
            return Ok(true);
        }
        let packet = if fragmented {
            let Ok(Some(p)) = self.stacks.as_mut().unwrap()[0].reassemble_mdns(raw, now) else {
                return Ok(true);
            };
            p
        } else {
            raw.to_vec()
        };
        let Ok(d) = Datagram::parse(Link::Ail, &packet) else {
            return Ok(true);
        };
        // A fragmented multicast DNS message may contain only one RR (RFC 6762 17).
        if fragmented
            && d.message.answers.len() + d.message.authority.len() + d.message.additional.len() > 1
        {
            return Ok(true);
        }
        let _ = self.mdns.querier.receive(&d, on_link, now, rng)?;
        Ok(true)
    }
    pub(super) fn poll_mdns(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        let sources = self.mdns_sources();
        self.mdns.querier.available(!sources.is_empty(), now, rng)?;
        if sources.is_empty() {
            self.mdns_output = None;
            return Ok(());
        }
        if self
            .mdns_output
            .as_ref()
            .is_some_and(|o| o.sources != sources)
        {
            if let Some(o) = self.mdns_output.take() {
                self.mdns.querier.sent(o.id, false, now);
            }
        }
        for _ in 0..32 {
            if self.mdns_output.is_none() {
                let Some(batch) = self.mdns.querier.poll(now)? else {
                    break;
                };
                self.mdns_output = Some(Output {
                    id: batch.id,
                    messages: batch.messages.into(),
                    packets: VecDeque::new(),
                    sources: sources.clone(),
                    retry: now,
                });
            }
            let output = self.mdns_output.as_mut().unwrap();
            if output.retry > now {
                break;
            }
            if output.packets.is_empty() {
                let Some(message) = output.messages.pop_front() else {
                    self.mdns.querier.sent(output.id, true, now);
                    self.mdns_output = None;
                    continue;
                };
                for source in &output.sources {
                    let destination = multicast(source.is_ipv6());
                    let packet = encode(
                        SocketAddr::new(*source, 5353),
                        SocketAddr::new(destination, 5353),
                        &message,
                    )?;
                    let fragments = crate::ip_reassembly::fragment(
                        &packet,
                        self.io.info(Link::Ail).mtu as usize,
                        self.mdns_fragment_id,
                    )?;
                    self.mdns_fragment_id = self.mdns_fragment_id.wrapping_add(1);
                    for packet in fragments {
                        let frame = if self.io.info(Link::Ail).kind == FrameKind::Ethernet {
                            let mut frame = multicast_mac(destination).to_vec();
                            frame.extend(self.ipv4.mac);
                            frame.extend(if source.is_ipv6() {
                                [0x86, 0xdd]
                            } else {
                                [8, 0]
                            });
                            frame.extend(packet);
                            frame
                        } else {
                            packet
                        };
                        output.packets.push_back(frame);
                    }
                }
            }
            let Some(packet) = output.packets.front() else {
                continue;
            };
            match self.io.send(Link::Ail, packet) {
                Ok(()) => {
                    output.packets.pop_front();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    output.retry = now.saturating_add(100);
                    break;
                }
                Err(_) => {
                    self.mdns.querier.sent(output.id, false, now);
                    self.mdns_output = None;
                    self.router.set_link(Link::Ail, false, now, rng)?;
                    self.mdns.querier.available(false, now, rng)?;
                    break;
                }
            }
        }
        Ok(())
    }
}
fn multicast_mac(destination: IpAddr) -> [u8; 6] {
    match destination {
        IpAddr::V4(a) => {
            let a = a.octets();
            [1, 0, 0x5e, a[1] & 0x7f, a[2], a[3]]
        }
        IpAddr::V6(a) => {
            let a = a.octets();
            [0x33, 0x33, a[12], a[13], a[14], a[15]]
        }
    }
}
