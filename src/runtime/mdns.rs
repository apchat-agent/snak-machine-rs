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
pub(super) type Source = Box<
    dyn Fn(u64, Time, &Router, &crate::dns::resolver::Resolver) -> Vec<crate::dns::wire::Record>,
>;
#[derive(Clone, Copy)]
enum Owner {
    Query(u64),
    Publication(u64),
    Response(u64),
}
pub(super) struct Output {
    owner: Owner,
    destination: Option<SocketAddr>,
    messages: VecDeque<Message>,
    packets: VecDeque<Vec<u8>>,
    sources: Vec<IpAddr>,
    pub(super) retry: Time,
}
impl<I: PacketIo> Driver<I> {
    /// Install the authoritative owner's projection function. Stored publications
    /// must be synchronized with that owner before polling or receiving traffic.
    pub fn set_mdns_source(
        &mut self,
        source: impl Fn(u64, Time, &Router, &crate::dns::resolver::Resolver) -> Vec<crate::dns::wire::Record>
            + 'static,
    ) {
        self.mdns_source = Box::new(source);
        self.mdns_output = None;
    }

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
            && d.message
                .answers
                .iter()
                .chain(&d.message.authority)
                .chain(&d.message.additional)
                .filter(|r| r.kind != 41)
                .count()
                > 1
        {
            return Ok(true);
        }
        self.dns.sync_advertising(&mut self.mdns, now, rng)?;
        let source = |id, at| (self.mdns_source)(id, at, &self.router, &self.dns);
        if self.mdns.receive(&d, on_link, &source, now, rng)? && rx.kind == FrameKind::Ethernet {
            self.mdns.querier.remember_peer(
                d.source.ip(),
                rx.bytes[6..12].try_into().unwrap(),
                now,
            );
        }
        self.mdns.sync_budget()?;
        Ok(true)
    }
    fn mdns_complete(&mut self, owner: Owner, success: bool, now: Time) {
        match owner {
            Owner::Query(id) => self.mdns.querier.sent(id, success, now),
            Owner::Publication(id) => self.mdns.publisher.sent(id, success, now),
            Owner::Response(id) => {
                self.mdns
                    .responder
                    .sent(id, success, &mut self.mdns.publisher, now)
            }
        }
    }
    fn mdns_current(&self, owner: Owner, now: Time) -> bool {
        match owner {
            Owner::Query(id) => self.mdns.querier.active(id, now),
            Owner::Publication(id) => self.mdns.publisher.offered(id),
            Owner::Response(id) => self.mdns.responder.offered(id, now),
        }
    }
    fn mdns_next_output(&mut self, sources: &[IpAddr], now: Time) -> io::Result<Option<Output>> {
        let source = |id, at| (self.mdns_source)(id, at, &self.router, &self.dns);
        for _ in 0..3 {
            let round = self.mdns_round;
            self.mdns_round = (self.mdns_round + 1) % 3;
            let (owner, destination, messages) = match round {
                0 => {
                    if let Some(b) = self.mdns.querier.poll(now)? {
                        (Owner::Query(b.id), None, b.messages)
                    } else {
                        continue;
                    }
                }
                1 => {
                    if let Some(b) = self.mdns.publisher.poll(&source, now)? {
                        (Owner::Publication(b.token), None, b.messages)
                    } else {
                        continue;
                    }
                }
                _ => {
                    if let Some(b) = self
                        .mdns
                        .responder
                        .poll(&self.mdns.publisher, &source, now)?
                    {
                        (Owner::Response(b.token), Some(b.destination), b.messages)
                    } else {
                        continue;
                    }
                }
            };
            return Ok(Some(Output {
                owner,
                destination,
                messages: self.mdns.prepare_outgoing(messages, now)?.into(),
                packets: VecDeque::new(),
                sources: sources.to_vec(),
                retry: now,
            }));
        }
        Ok(None)
    }
    pub(super) fn poll_mdns(&mut self, now: Time, rng: &mut impl RandomSource) -> io::Result<()> {
        self.mdns.sync_budget()?;
        let sources = self.mdns_sources();
        self.mdns.querier.available(!sources.is_empty(), now, rng)?;
        self.mdns
            .publisher
            .available(!sources.is_empty(), now, rng)?;
        if sources.is_empty() {
            self.mdns_output = None;
            self.mdns.responder.clear();
            return Ok(());
        }
        if self
            .mdns_output
            .as_ref()
            .is_some_and(|o| o.sources != sources || !self.mdns_current(o.owner, now))
        {
            if let Some(o) = self.mdns_output.take() {
                self.mdns_complete(o.owner, false, now);
            }
        }
        for _ in 0..32 {
            if self.mdns_output.is_none() {
                self.mdns_output = self.mdns_next_output(&sources, now)?;
                if self.mdns_output.is_none() {
                    break;
                }
            }
            let output = self.mdns_output.as_mut().unwrap();
            if output.retry > now {
                break;
            }
            if output.packets.is_empty() {
                let Some(mut message) = output.messages.pop_front() else {
                    let owner = output.owner;
                    self.mdns_output = None;
                    self.mdns_complete(owner, true, now);
                    continue;
                };
                if !crate::mdns::tsr::legacy(&message) {
                    crate::mdns::tsr::attach(&mut message, self.mdns.tsr_code(), now, &|n| {
                        self.mdns.publisher.output_stamp(n)
                    })?;
                }
                for source in &output.sources {
                    if output
                        .destination
                        .is_some_and(|d| d.is_ipv6() != source.is_ipv6())
                    {
                        continue;
                    }
                    let destination = output
                        .destination
                        .unwrap_or_else(|| SocketAddr::new(multicast(source.is_ipv6()), 5353));
                    let mac = if destination.ip().is_multicast() {
                        Some(multicast_mac(destination.ip()))
                    } else {
                        self.mdns.querier.peer(destination.ip(), now)
                    };
                    if self.io.info(Link::Ail).kind == FrameKind::Ethernet && mac.is_none() {
                        let owner = output.owner;
                        self.mdns_output = None;
                        self.mdns_complete(owner, false, now);
                        return Ok(());
                    }
                    let packet = encode(SocketAddr::new(*source, 5353), destination, &message)?;
                    let fragments = crate::ip_reassembly::fragment(
                        &packet,
                        self.io.info(Link::Ail).mtu as usize,
                        self.mdns_fragment_id,
                    )?;
                    self.mdns_fragment_id = self.mdns_fragment_id.wrapping_add(1);
                    for packet in fragments {
                        let frame = if self.io.info(Link::Ail).kind == FrameKind::Ethernet {
                            let mut frame = mac.unwrap().to_vec();
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
                    let owner = output.owner;
                    self.mdns_output = None;
                    self.mdns_complete(owner, false, now);
                    self.router.set_link(Link::Ail, false, now, rng)?;
                    self.mdns.querier.available(false, now, rng)?;
                    self.mdns.publisher.available(false, now, rng)?;
                    self.mdns.responder.clear();
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
