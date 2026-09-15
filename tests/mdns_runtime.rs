mod common;
use snac_rs::{
    dns::wire::{Message, Name, Question, Rdata, Record},
    io::{Direction, LinkInfo, MemoryIo, Received},
    mdns::wire::Datagram,
    persist::{Identity, MemoryStore},
    router::Router,
    runtime::Driver,
    time::ScriptedRandom,
    wire::FrameKind,
    Link,
};
fn driver() -> Driver<MemoryIo> {
    let mut rng = ScriptedRandom::new([123]);
    let identity =
        Identity::load_or_create(&mut MemoryStore::default(), "mdns-runtime", &mut rng).unwrap();
    let router = Router::new(identity, 0, &mut rng).unwrap();
    let info = [1, 2].map(|index| LinkInfo {
        name: format!("mdns{index}"),
        index,
        kind: FrameKind::Ethernet,
        mtu: 1500,
        mac: Some([2, 0, 0, 0, 0, index as u8]),
    });
    Driver::new(router, MemoryIo::new(info)).unwrap()
}
fn question() -> Question {
    Question {
        name: "light.local.".parse().unwrap(),
        kind: 1,
        class: 1,
    }
}
fn sum(bytes: &[u8]) -> u16 {
    let mut n: u32 = bytes
        .chunks(2)
        .map(|p| (u32::from(p[0]) << 8) | u32::from(*p.get(1).unwrap_or(&0)))
        .sum();
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
fn packet(v6: bool, body: &[u8]) -> Vec<u8> {
    let mut udp = vec![0x14, 0xe9, 0x14, 0xe9];
    udp.extend(((body.len() + 8) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(body);
    if v6 {
        let source = common::ip("fe80::2");
        let destination = common::ip("ff02::fb");
        let checksum = common::sum(source, destination, 17, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend((udp.len() as u16).to_be_bytes());
        ip.extend([17, 255]);
        ip.extend(source.octets());
        ip.extend(destination.octets());
        ip.extend(udp);
        ip
    } else {
        let mut pseudo = vec![192, 0, 2, 2, 224, 0, 0, 251, 0, 17];
        pseudo.extend((udp.len() as u16).to_be_bytes());
        pseudo.extend(&udp);
        let checksum = sum(&pseudo);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        let mut ip = vec![0x45, 0];
        ip.extend(((20 + udp.len()) as u16).to_be_bytes());
        ip.extend([0, 0, 0, 0, 255, 17, 0, 0, 192, 0, 2, 2, 224, 0, 0, 251]);
        let checksum = sum(&ip);
        ip[10..12].copy_from_slice(&checksum.to_be_bytes());
        ip.extend(udp);
        ip
    }
}
fn frame(packet: Vec<u8>) -> Received {
    let v6 = packet[0] >> 4 == 6;
    let mut bytes = if v6 {
        vec![0x33, 0x33, 0, 0, 0, 0xfb]
    } else {
        vec![1, 0, 0x5e, 0, 0, 0xfb]
    };
    bytes.extend([2, 0, 0, 0, 0, 99]);
    bytes.extend(if v6 { [0x86, 0xdd] } else { [8, 0] });
    bytes.extend(packet);
    Received {
        link: Link::Ail,
        kind: FrameKind::Ethernet,
        bytes,
        direction: Direction::Ingress,
    }
}
fn response() -> Message {
    let mut m = Message::new(123, 0x8000);
    m.answers.push(Record {
        name: question().name,
        kind: 1,
        class: 0x8001,
        ttl: 120,
        data: Rdata::A([192, 0, 2, 9]),
    });
    m
}
#[test]
fn s13_driver_issues_both_multicast_families_and_admits_only_checked_ail_answers() {
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    // Let the real acquisition reducer reach IPv4LL, using only memory frames.
    for now in (1000..=75000).step_by(1000) {
        d.step(now, &mut rng).unwrap();
    }
    assert!(d.ipv4.ready());
    assert!(d.io.groups[0].contains(&common::ip("ff02::fb")));
    assert!(d.io.ipv4_groups[0].contains(&"224.0.0.251".parse().unwrap()));
    d.io.output.clear();
    d.mdns
        .querier
        .start(question(), 100000, 75000, &mut rng)
        .unwrap();
    d.step(75019, &mut rng).unwrap();
    assert!(d
        .io
        .output
        .iter()
        .all(|(_, f)| Datagram::parse(Link::Ail, &f[14..]).is_err()));
    d.step(75020, &mut rng).unwrap();
    let sent: Vec<_> =
        d.io.output
            .iter()
            .filter_map(|(link, f)| Datagram::parse(*link, &f[14..]).ok())
            .collect();
    assert_eq!(sent.len(), 2);
    assert!(sent.iter().any(|m| m.source.is_ipv4()));
    assert!(sent.iter().any(|m| m.source.is_ipv6()));
    assert!(sent
        .iter()
        .all(|m| m.message.questions[0].class == 0x8001 && m.destination.ip().is_multicast()));
    for v6 in [false, true] {
        for mutation in 0..5 {
            let mut rx = frame(packet(v6, &response().encode().unwrap()));
            match mutation {
                0 => rx.link = Link::Stub,
                1 => rx.bytes[6] = 1,
                2 => rx.bytes[..6].fill(0),
                3 => rx.direction = Direction::OwnEgress,
                _ => rx.bytes[14 + if v6 { 7 } else { 8 }] = 254,
            }
            d.accept(rx, 76000, &mut rng).unwrap();
            assert!(d.mdns.querier.cache.answers(&question(), 76000).is_empty());
        }
    }
    for v6 in [false, true] {
        d.accept(
            frame(packet(v6, &response().encode().unwrap())),
            76001,
            &mut rng,
        )
        .unwrap();
    }
    assert_eq!(d.mdns.querier.cache.answers(&question(), 76001).len(), 1);
    d.io.up[0] = false;
    d.step(77000, &mut rng).unwrap();
    assert!(d.mdns.querier.cache.answers(&question(), 77000).is_empty());
    assert!(d.io.groups[0].is_empty() && d.io.ipv4_groups[0].is_empty());
}
fn fragment6(packet: &[u8], offset: usize, end: usize, more: bool) -> Vec<u8> {
    let mut b = packet[..40].to_vec();
    b[6] = 44;
    b[4..6].copy_from_slice(&((end - offset + 8) as u16).to_be_bytes());
    b.extend([17, 0]);
    b.extend(((offset as u16) | u16::from(more)).to_be_bytes());
    b.extend(123u32.to_be_bytes());
    b.extend(&packet[40 + offset..40 + end]);
    b
}
#[test]
fn s13_driver_reassembles_large_single_mdns_records_before_cache_delivery() {
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let mut m = Message::new(0, 0x8400);
    let name: Name = "big.local.".parse().unwrap();
    m.answers.push(Record {
        name: name.clone(),
        kind: 16,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Txt(vec![vec![42; 250]; 10]),
    });
    let ip = packet(true, &m.encode().unwrap());
    let q = Question {
        name,
        kind: 16,
        class: 1,
    };
    d.accept(
        frame(fragment6(&ip, 1024, ip.len() - 40, false)),
        1001,
        &mut rng,
    )
    .unwrap();
    assert!(d.mdns.querier.cache.answers(&q, 1001).is_empty());
    d.accept(frame(fragment6(&ip, 0, 1024, true)), 1002, &mut rng)
        .unwrap();
    assert_eq!(
        d.mdns.querier.cache.answers(&q, 1002)[0].data,
        m.answers[0].data
    );
}

#[test]
fn s13_driver_sends_publication_and_unicast_responses_from_current_owner_projection() {
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let records = response().answers;
    let owned = records.clone();
    d.set_mdns_source(move |_, _, _, _| owned.clone());
    d.mdns
        .publisher
        .replace(1, &[], &records, 1000, &mut rng)
        .unwrap();
    d.io.output.clear();
    for now in [1000, 1250, 1500, 1750, 2750] {
        d.step(now, &mut rng).unwrap();
    }
    let sent: Vec<_> =
        d.io.output
            .iter()
            .filter_map(|(l, f)| Datagram::parse(*l, &f[14..]).ok())
            .collect();
    assert_eq!(
        sent.iter()
            .filter(|d| d.message.flags & 0x8000 == 0)
            .count(),
        3
    );
    assert_eq!(
        sent.iter()
            .filter(|d| d.message.flags & 0x8000 != 0)
            .count(),
        2
    );
    assert!(d.mdns.publisher.ready(1));
    d.io.output.clear();
    let mut q = Message::new(321, 0);
    let mut question = question();
    question.class = 0x8001;
    q.questions.push(question);
    d.accept(frame(packet(true, &q.encode().unwrap())), 3000, &mut rng)
        .unwrap();
    d.step(3000, &mut rng).unwrap();
    let (link, f) =
        d.io.output
            .iter()
            .find(|(l, f)| Datagram::parse(*l, &f[14..]).is_ok())
            .unwrap();
    assert_eq!(*link, Link::Ail);
    assert_eq!(f[..6], [2, 0, 0, 0, 0, 99]);
    let answer = Datagram::parse(Link::Ail, &f[14..]).unwrap();
    assert_eq!(answer.destination, "[fe80::2]:5353".parse().unwrap());
    assert_eq!(answer.message.answers[0].data, records[0].data);
    assert_eq!(answer.message.id, 0);
    // A stale owner callback cannot emit the old records after a projection update.
    d.set_mdns_source(|_, _, _, _| vec![]);
    assert!(d.step(4000, &mut rng).is_err());
}
#[test]
fn s13_unicast_probe_defense_is_admitted_only_for_the_probed_name_and_recent_send() {
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let records = response().answers;
    let owned = records.clone();
    d.set_mdns_source(move |_, _, _, _| owned.clone());
    d.mdns
        .publisher
        .replace(1, &[], &records, 1000, &mut rng)
        .unwrap();
    d.step(1000, &mut rng).unwrap();
    let mut m = response();
    m.answers[0].data = Rdata::A([192, 0, 2, 200]);
    let own = d.router.identity.link_local(Link::Ail);
    let mut p = packet(true, &m.encode().unwrap());
    p[24..40].copy_from_slice(&own.octets());
    p[46..48].fill(0);
    let checksum = common::sum(common::ip("fe80::2"), own, 17, &p[40..]);
    p[46..48].copy_from_slice(&checksum.to_be_bytes());
    let mut rx = frame(p);
    rx.bytes[..6].copy_from_slice(&d.ipv4.mac);
    d.accept(rx, 1001, &mut rng).unwrap();
    assert_eq!(d.mdns.publisher.take_conflict(), Some(1));
    assert!(!d.mdns.publisher.ready(1));
}

struct Flaky {
    inner: MemoryIo,
    armed: bool,
    fragments: usize,
    failed: bool,
}
impl snac_rs::io::PacketIo for Flaky {
    fn info(&self, link: Link) -> &LinkInfo {
        &self.inner.info[link.index()]
    }
    fn receive(&mut self, timeout: std::time::Duration) -> std::io::Result<Option<Received>> {
        self.inner.receive(timeout)
    }
    fn send(&mut self, link: Link, b: &[u8]) -> std::io::Result<()> {
        if self.armed && b.len() >= 62 && b[12..14] == [0x86, 0xdd] && b[20] == 44 && b[54] == 17 {
            if self.fragments == 1 && !self.failed {
                self.failed = true;
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            self.fragments += 1;
        }
        self.inner.send(link, b)
    }
    fn join(&mut self, link: Link, group: std::net::Ipv6Addr) -> std::io::Result<()> {
        self.inner.join(link, group)
    }
    fn leave(&mut self, link: Link, group: std::net::Ipv6Addr) -> std::io::Result<()> {
        self.inner.leave(link, group)
    }
    fn join_v4(&mut self, link: Link, group: std::net::Ipv4Addr) -> std::io::Result<()> {
        self.inner.join_v4(link, group)
    }
    fn leave_v4(&mut self, link: Link, group: std::net::Ipv4Addr) -> std::io::Result<()> {
        self.inner.leave_v4(link, group)
    }
    fn link_up(&self, link: Link) -> std::io::Result<bool> {
        Ok(self.inner.up[link.index()])
    }
}
#[test]
fn s13_fragmented_transmit_resumes_at_failed_frame_and_respects_interface_mtu() {
    let base = driver();
    let mut d = Driver::new(
        base.router,
        Flaky {
            inner: base.io,
            armed: false,
            fragments: 0,
            failed: false,
        },
    )
    .unwrap();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let data = vec![Record {
        name: "large.local.".parse().unwrap(),
        kind: 16,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Txt(vec![vec![42; 250]; 30]),
    }];
    let owned = data.clone();
    d.set_mdns_source(move |_, _, _, _| owned.clone());
    d.mdns
        .publisher
        .replace(1, &[], &data, 1000, &mut rng)
        .unwrap();
    d.io.inner.output.clear();
    d.io.armed = true;
    d.step(1000, &mut rng).unwrap();
    assert!(d.io.failed);
    assert_eq!(d.io.fragments, 1);
    d.step(1050, &mut rng).unwrap();
    assert_eq!(d.io.fragments, 1);
    d.step(1100, &mut rng).unwrap();
    let fragments: Vec<_> =
        d.io.inner
            .output
            .iter()
            .filter(|(_, b)| b.len() >= 62 && b[20] == 44 && b[54] == 17)
            .collect();
    assert!(fragments.len() > 1);
    assert!(fragments.iter().all(|(_, b)| b.len() <= 1514));
    assert_eq!(
        fragments
            .iter()
            .filter(|(_, b)| u16::from_be_bytes([b[56], b[57]]) & 0xfff8 == 0)
            .count(),
        1,
        "already sent fragment is never repeated on retry"
    );
    let mut reassembly = snac_rs::ip_reassembly::Reassembler::default();
    let mut complete = None;
    for (_, b) in fragments {
        if let Some(p) = reassembly.input(&b[14..], 1100).unwrap() {
            complete = Some(p);
        }
    }
    let packet = Datagram::parse(Link::Ail, &complete.unwrap()).unwrap();
    assert_eq!(packet.message.authority.len(), 1);
    assert_eq!(packet.message.authority[0].data, data[0].data);
    assert!(!d.mdns.publisher.ready(1));
}

#[test]
fn s14_driver_sends_tsr_and_accepts_a_fragmented_record_with_its_opt() {
    use snac_rs::mdns::tsr::{attach, extract, Stamp, OPTION_CODE};
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let records = response().answers;
    let stamps = records
        .iter()
        .map(|r| {
            (
                r.name.clone(),
                Stamp {
                    key_checksum: 7,
                    received_at: 0,
                },
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let projection = records.clone();
    d.set_mdns_source(move |_, _, _, _| projection.clone());
    d.mdns
        .register_tsr(1, (&[], &records), &stamps, 1000, &mut rng)
        .unwrap();
    d.io.output.clear();
    d.step(1001, &mut rng).unwrap();
    let sent =
        d.io.output
            .iter()
            .filter_map(|(l, f)| Datagram::parse(*l, &f[14..]).ok())
            .next()
            .unwrap();
    assert_eq!(
        extract(&sent.message, OPTION_CODE, 1001).unwrap()[&records[0].name].key_checksum,
        7
    );
    let mut m = Message::new(0, 0x8400);
    m.answers.push(Record {
        name: "remote.local.".parse().unwrap(),
        kind: 16,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Txt(vec![vec![b'x'; 240]; 10]),
    });
    attach(&mut m, OPTION_CODE, 2000, &|_| {
        Some(Stamp {
            key_checksum: 8,
            received_at: 0,
        })
    })
    .unwrap();
    let ip = packet(
        true,
        &m.encode_context(snac_rs::dns::wire::Context::Mdns).unwrap(),
    );
    d.accept(frame(fragment6(&ip, 0, 1024, true)), 2000, &mut rng)
        .unwrap();
    d.accept(
        frame(fragment6(&ip, 1024, ip.len() - 40, false)),
        2001,
        &mut rng,
    )
    .unwrap();
    assert!(d
        .mdns
        .querier
        .cache
        .owner_stamp(&m.answers[0].name, 2001)
        .is_some());
}

#[test]
fn s14_native_signed_srp_udp_drives_ail_probe_browse_update_and_expiry() {
    use snac_rs::{service_io::stack::Stack, srp::registry::LeasePolicy};
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.dns
        .enable_srp(Box::new(MemoryStore::default()), 0, common::srp::NOW)
        .unwrap();
    d.dns
        .set_srp_policy(LeasePolicy {
            max_lease: 10,
            max_key_lease: 60,
            ..LeasePolicy::default()
        })
        .unwrap();
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let own = d.router.identity.link_local(Link::Stub);
    let mut rx = frame(common::nd_packet(
        "fe80::99",
        &snac_rs::wire::solicited_node(own).to_string(),
        {
            let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
            ns.extend(own.octets());
            ns.extend([1, 1, 2, 0, 0, 0, 0, 99]);
            ns
        },
    ));
    rx.link = Link::Stub;
    d.accept(rx, 1001, &mut rng).unwrap();
    let mut peer = Stack::new(0, &mut rng).unwrap();
    let client: std::net::IpAddr = "fe80::99".parse().unwrap();
    peer.set_addresses(&[client]).unwrap();
    peer.listen_udp(40000).unwrap();
    let mut request = common::srp::update();
    if let Some(r) = request.authority.iter_mut().find(|r| r.kind == 16) {
        r.data = Rdata::Txt(vec![vec![0, 255, b'=']]);
    }
    let signed = common::srp::sign(request.clone());
    peer.send_udp(client, 40000, own.into(), 53, &signed)
        .unwrap();
    peer.poll(1002).unwrap();
    let mut rx = frame(peer.output().unwrap());
    rx.link = Link::Stub;
    rx.bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    d.accept(rx, 1002, &mut rng).unwrap();
    d.io.output.clear();
    d.step(1002, &mut rng).unwrap();
    for (link, b) in &d.io.output {
        if *link == Link::Stub && b.len() > 62 && b[20] == 17 {
            peer.input(&b[14..], 1002).unwrap();
        }
    }
    peer.poll(1002).unwrap();
    let ack = peer.receive_udp().unwrap();
    assert_eq!(
        Message::parse(&ack.bytes, snac_rs::dns::wire::Context::Unicast)
            .unwrap()
            .flags
            & 15,
        0
    );
    let first =
        d.io.output
            .iter()
            .filter_map(|(l, b)| Datagram::parse(*l, &b[14..]).ok())
            .find(|m| !m.message.authority.is_empty())
            .expect("accepted SRP automatically starts AIL probing");
    assert!(first
        .message
        .authority
        .iter()
        .all(|r| r.name.labels().last().unwrap() == b"local"));
    for at in [1252, 1502, 1752, 2752] {
        d.step(at, &mut rng).unwrap();
    }
    d.io.output.clear();
    let mut browse = Message::new(0, 0);
    browse.questions.push(Question {
        name: "_http._tcp.local.".parse().unwrap(),
        kind: 12,
        class: 1,
    });
    d.accept(
        frame(packet(true, &browse.encode().unwrap())),
        3800,
        &mut rng,
    )
    .unwrap();
    d.step(3820, &mut rng).unwrap();
    let reply =
        d.io.output
            .iter()
            .filter_map(|(l, b)| Datagram::parse(*l, &b[14..]).ok())
            .find(|m| !m.message.answers.is_empty())
            .unwrap();
    assert!(reply.message.answers.iter().any(|r| r.kind == 12));
    assert!(reply
        .message
        .additional
        .iter()
        .any(|r| r.data == Rdata::Txt(vec![vec![0, 255, b'=']])));
    assert!(reply.message.additional.iter().any(|r| r.kind == 28));
    request.id += 1;
    if let Some(r) = request.authority.iter_mut().find(|r| r.kind == 16) {
        r.data = Rdata::Txt(vec![b"updated".to_vec()]);
    }
    peer.send_udp(client, 40000, own.into(), 53, &common::srp::sign(request))
        .unwrap();
    peer.poll(4000).unwrap();
    let mut rx = frame(peer.output().unwrap());
    rx.link = Link::Stub;
    rx.bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    d.accept(rx, 4000, &mut rng).unwrap();
    d.io.output.clear();
    for at in [4000, 4250, 4500, 4750, 5750] {
        d.step(at, &mut rng).unwrap();
    }
    assert!(d
        .io
        .output
        .iter()
        .filter_map(|(l, b)| Datagram::parse(*l, &b[14..]).ok())
        .flat_map(|d| d.message.answers)
        .any(|r| r.data == Rdata::Txt(vec![b"updated".to_vec()])));
    d.io.output.clear();
    d.step(14000, &mut rng).unwrap();
    assert!(d
        .io
        .output
        .iter()
        .filter_map(|(l, b)| Datagram::parse(*l, &b[14..]).ok())
        .flat_map(|d| d.message.answers)
        .any(|r| r.ttl == 0));
    assert_eq!(d.mdns.publisher.counts().0, 0);
}
