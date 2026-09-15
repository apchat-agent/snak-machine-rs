mod common;
use snac_rs::{
    dns::wire::{Context, Message, Question, Rdata, Record},
    io::{Direction, LinkInfo, MemoryIo, Received},
    persist::{Identity, MemoryStore},
    router::Router,
    runtime::Driver,
    service_io::stack::Stack,
    time::ScriptedRandom,
    wire::{dhcpv6, envelope, FrameKind},
    Link,
};
use std::net::IpAddr;
fn driver() -> Driver<MemoryIo> {
    let mut rng = ScriptedRandom::new([345]);
    let id =
        Identity::load_or_create(&mut MemoryStore::default(), "dns-service", &mut rng).unwrap();
    let r = Router::new(id, 0, &mut rng).unwrap();
    let infos = [1, 2].map(|index| LinkInfo {
        name: format!("mem{index}"),
        index,
        kind: FrameKind::Ethernet,
        mtu: 1500,
        mac: Some([2, 0, 0, 0, 0, index as u8]),
    });
    Driver::new(r, MemoryIo::new(infos)).unwrap()
}
fn rx(link: Link, packet: Vec<u8>) -> Received {
    let mut b = vec![
        2,
        0,
        0,
        0,
        0,
        link.index() as u8 + 1,
        2,
        0,
        0,
        0,
        0,
        99,
        0x86,
        0xdd,
    ];
    b.extend(packet);
    Received {
        link,
        kind: FrameKind::Ethernet,
        bytes: b,
        direction: Direction::Ingress,
    }
}
fn peer(link: Link) -> IpAddr {
    common::ip(if link == Link::Ail {
        "fe80::53"
    } else {
        "fe80::99"
    })
    .into()
}
fn learn(d: &mut Driver<MemoryIo>, link: Link, rng: &mut ScriptedRandom) {
    let own = d.router.identity.link_local(link);
    let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
    ns.extend(own.octets());
    ns.extend([1, 1, 2, 0, 0, 0, 0, 99]);
    d.accept(
        rx(
            link,
            common::nd_packet(
                &peer(link).to_string(),
                &snac_rs::wire::solicited_node(own).to_string(),
                ns,
            ),
        ),
        1001,
        rng,
    )
    .unwrap();
}
fn stack(a: IpAddr) -> Stack {
    let mut s = Stack::new(0, &mut ScriptedRandom::new([])).unwrap();
    s.set_addresses(&[a]).unwrap();
    s
}
fn cycle(d: &mut Driver<MemoryIo>, hosts: &mut [Stack; 2], now: u64, rng: &mut ScriptedRandom) {
    for link in [Link::Ail, Link::Stub] {
        let h = &mut hosts[link.index()];
        h.poll(now).unwrap();
        while let Some(p) = h.output() {
            d.accept(rx(link, p), now, rng).unwrap();
        }
    }
    d.step(now, rng).unwrap();
    for (link, b) in std::mem::take(&mut d.io.output) {
        if b.len() < 14 || b[12..14] != [0x86, 0xdd] {
            continue;
        }
        let e = envelope(FrameKind::Ethernet, &b).unwrap();
        if IpAddr::V6(e.destination) == peer(link) && [6, 17].contains(&e.next_header) {
            hosts[link.index()].input(e.packet, now).unwrap();
        }
    }
}
fn query(name: &str, kind: u16, id: u16) -> Vec<u8> {
    let mut m = Message::new(id, 0x100);
    m.questions.push(Question {
        name: name.parse().unwrap(),
        kind,
        class: 1,
    });
    m.encode().unwrap()
}
#[test]
fn s09_driver_dns_udp_forwards_through_owned_ail_source_and_augment() {
    let mut d = driver();
    let mut rng = ScriptedRandom::new(0..10000);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    for link in [Link::Ail, Link::Stub] {
        learn(&mut d, link, &mut rng);
    }
    d.dns_discovery
        .set_configured(&["[fe80::53]:53".parse().unwrap()])
        .unwrap();
    let mut hosts = [stack(peer(Link::Ail)), stack(peer(Link::Stub))];
    hosts[0].listen_udp(53).unwrap();
    hosts[1].listen_udp(40000).unwrap();
    let own = d.router.identity.link_local(Link::Stub);
    hosts[1]
        .send_udp(
            peer(Link::Stub),
            40000,
            own.into(),
            53,
            &query("v4.test.", 28, 99),
        )
        .unwrap();
    let mut kinds = vec![];
    let mut result = None;
    for now in (1010..5000).step_by(10) {
        cycle(&mut d, &mut hosts, now, &mut rng);
        while let Some(q) = hosts[0].receive_udp() {
            assert_eq!(
                q.source,
                IpAddr::V6(d.router.identity.link_local(Link::Ail))
            );
            let mut m = Message::parse(&q.bytes, Context::Unicast).unwrap();
            let kind = m.questions[0].kind;
            kinds.push(kind);
            m.flags = 0x8180;
            if kind == 1 {
                m.answers.push(Record {
                    name: m.questions[0].name.clone(),
                    kind: 1,
                    class: 1,
                    ttl: 30,
                    data: Rdata::A([192, 0, 2, 9]),
                });
            }
            hosts[0]
                .send_udp(
                    peer(Link::Ail),
                    53,
                    q.source,
                    q.source_port,
                    &m.encode().unwrap(),
                )
                .unwrap();
        }
        if let Some(a) = hosts[1].receive_udp() {
            result = Some(a);
            break;
        }
    }
    let reply = result.expect("real DNS response through Driver, ND and both userspace stacks");
    let m = Message::parse(&reply.bytes, Context::Unicast).unwrap();
    assert_eq!(m.id, 99);
    assert!(m.answers.is_empty());
    assert_eq!(m.additional[0].data, Rdata::A([192, 0, 2, 9]));
    assert_eq!(kinds, [28, 1]);
    assert_eq!(d.dns.pending_count(), 0);
}
#[test]
fn s09_driver_information_reply_and_ra_feed_dns_configuration() {
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let p =
        d.io.output
            .iter()
            .filter_map(|(l, b)| {
                let e = envelope(FrameKind::Ethernet, b).ok()?;
                (*l == Link::Ail && e.next_header == 17 && e.payload.get(8) == Some(&11))
                    .then(|| e.packet.to_vec())
            })
            .next()
            .expect("Information-request once AIL DAD is complete");
    let e = envelope(FrameKind::RawIpv6, &p).unwrap();
    let opts = dhcpv6::options(&e.payload[12..]).unwrap();
    let duid = opts.iter().find(|(k, _)| *k == 1).unwrap().1;
    let mut b = vec![7];
    b.extend(&e.payload[9..12]);
    b.extend(dhcpv6::option(1, duid));
    b.extend(dhcpv6::option(2, &[0, 3, 0, 1, 2, 0, 0, 0, 0, 99]));
    b.extend(dhcpv6::option(23, &common::ip("2001:db8::53").octets()));
    let p = dhcpv6::udp_packet(common::ip("fe80::99"), e.source, 547, 546, &b).unwrap();
    d.accept(rx(Link::Ail, p), 1001, &mut rng).unwrap();
    d.step(1001, &mut rng).unwrap();
    assert_eq!(d.dns.upstreams(), ["[2001:db8::53]:53".parse().unwrap()]);
    let mut opt = vec![25, 3, 0, 0, 0, 0, 0, 60];
    opt.extend(common::ip("2001:db8::54").octets());
    let p = common::nd_packet("fe80::99", "ff02::1", common::ra(0, 1800, &opt));
    d.accept(rx(Link::Ail, p), 1002, &mut rng).unwrap();
    d.step(1002, &mut rng).unwrap();
    assert_eq!(d.dns.upstreams().len(), 2);
    d.io.up[0] = false;
    d.step(1003, &mut rng).unwrap();
    assert!(d.dns.upstreams().is_empty());
}
#[test]
fn s09_cli_explicit_upstream_and_additional_a_override() {
    let base = ["--backend", "tap", "--infra", "a", "--stub", "b"];
    let c = snac_rs::config::Config::parse(base.into_iter().chain([
        "--dns-upstream",
        "[2001:db8::53]:53",
        "--no-additional-a",
    ]))
    .unwrap()
    .unwrap();
    assert!(c.no_additional_a);
    assert_eq!(c.dns_upstreams, vec!["[2001:db8::53]:53".parse().unwrap()]);
    assert!(
        snac_rs::config::Config::parse(base.into_iter().chain(["--dns-upstream", "bad"])).is_err()
    );
}

#[test]
fn s09_driver_tcp_pipeline_and_upstream_tcp_large_split_response() {
    use snac_rs::dns::wire::TcpFrames;
    let mut d = driver();
    let mut rng = ScriptedRandom::new(0..10000);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    for link in [Link::Ail, Link::Stub] {
        learn(&mut d, link, &mut rng);
    }
    d.dns_discovery
        .set_configured(&["[fe80::53]:53".parse().unwrap()])
        .unwrap();
    let mut hosts = [stack(peer(Link::Ail)), stack(peer(Link::Stub))];
    hosts[0].listen_udp(53).unwrap();
    hosts[0].listen_tcp(53).unwrap();
    let cid = hosts[1]
        .connect(
            peer(Link::Stub),
            40001,
            d.router.identity.link_local(Link::Stub).into(),
            53,
            1001,
        )
        .unwrap();
    for now in (1010..1500).step_by(10) {
        cycle(&mut d, &mut hosts, now, &mut rng);
    }
    assert!(hosts[1].established(cid), "production DNS TCP listener");
    let mut frame = TcpFrames::frame(&query("large.test.", 16, 90)).unwrap();
    frame.extend(TcpFrames::frame(&query("small.test.", 1, 91)).unwrap());
    hosts[1].send_tcp(cid, &frame[..3]).unwrap();
    cycle(&mut d, &mut hosts, 1500, &mut rng);
    hosts[1].send_tcp(cid, &frame[3..]).unwrap();
    let mut server_frames = TcpFrames::new(65535).unwrap();
    let mut client_frames = TcpFrames::new(65535).unwrap();
    let mut replies = std::collections::BTreeMap::new();
    let mut pending: Option<(usize, Vec<u8>, usize)> = None;
    let mut saw_tcp = false;
    for now in (1510..15000).step_by(10) {
        cycle(&mut d, &mut hosts, now, &mut rng);
        while let Some(q) = hosts[0].receive_udp() {
            let mut m = Message::parse(&q.bytes, Context::Unicast).unwrap();
            m.flags = 0x8180;
            if m.questions[0].kind == 16 {
                m.flags |= 0x200;
            } else {
                m.answers.push(Record {
                    name: m.questions[0].name.clone(),
                    kind: 1,
                    class: 1,
                    ttl: 30,
                    data: Rdata::A([192, 0, 2, 9]),
                });
            }
            hosts[0]
                .send_udp(
                    peer(Link::Ail),
                    53,
                    q.source,
                    q.source_port,
                    &m.encode().unwrap(),
                )
                .unwrap();
        }
        for id in hosts[0].connections() {
            server_frames.input(&hosts[0].receive_tcp(id)).unwrap();
            if let Some(b) = server_frames.pop() {
                saw_tcp = true;
                let mut m = Message::parse(&b, Context::Unicast).unwrap();
                assert_eq!(m.questions[0].kind, 16);
                m.flags = 0x8180;
                m.answers.push(Record {
                    name: m.questions[0].name.clone(),
                    kind: 16,
                    class: 1,
                    ttl: 30,
                    data: Rdata::Txt(vec![vec![42; 250]; 180]),
                });
                pending = Some((id, TcpFrames::frame(&m.encode().unwrap()).unwrap(), 0));
            }
        }
        if let Some((id, b, offset)) = &mut pending {
            let n = hosts[0].send_tcp(*id, &b[*offset..]).unwrap();
            *offset += n;
            if *offset == b.len() {
                pending = None;
            }
        }
        client_frames.input(&hosts[1].receive_tcp(cid)).unwrap();
        while let Some(b) = client_frames.pop() {
            let m = Message::parse(&b, Context::Unicast).unwrap();
            replies.insert(m.id, m);
        }
        if replies.len() == 2 {
            break;
        }
    }
    assert!(saw_tcp);
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[&91].answers[0].data, Rdata::A([192, 0, 2, 9]));
    assert_eq!(
        replies[&90].answers[0].data,
        Rdata::Txt(vec![vec![42; 250]; 180])
    );
    assert_eq!(replies[&90].flags & 0x200, 0);
    assert_eq!(d.dns.pending_count(), 0);
}

#[test]
fn s09_dns_configuration_ignores_foreign_ethernet_destination() {
    let mut d = driver();
    let mut rng = ScriptedRandom::new([]);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    let mut opt = vec![25, 3, 0, 0, 0, 0, 0, 60];
    opt.extend(common::ip("2001:db8::53").octets());
    let mut p = rx(
        Link::Ail,
        common::nd_packet("fe80::99", "ff02::1", common::ra(0, 1800, &opt)),
    );
    p.bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 222]);
    d.accept(p, 1001, &mut rng).unwrap();
    d.step(1001, &mut rng).unwrap();
    assert!(d.dns.upstreams().is_empty());
}
#[test]
fn s09_udp_backpressure_retains_reply_and_queue_bounds_are_independent() {
    use snac_rs::dns::{
        resolver::{Action, Client, Resolver},
        service::Service,
    };
    let mut r = Resolver::new(true);
    let mut rng = ScriptedRandom::new([]);
    let mut svc = Service::default();
    let mut stacks = [
        stack("fe80::1".parse().unwrap()),
        stack("fe80::2".parse().unwrap()),
    ];
    stacks[1].listen_udp(53).unwrap();
    let mut c = stack("fe80::99".parse().unwrap());
    c.listen_udp(40000).unwrap();
    c.send_udp(
        "fe80::99".parse().unwrap(),
        40000,
        "fe80::2".parse().unwrap(),
        53,
        &query("blocked.test.", 1, 1),
    )
    .unwrap();
    c.poll(0).unwrap();
    stacks[1].input(&c.output().unwrap(), 0).unwrap();
    stacks[1].poll(0).unwrap();
    for _ in 0..4 {
        stacks[1]
            .send_udp(
                "fe80::2".parse().unwrap(),
                53,
                "fe80::99".parse().unwrap(),
                40000,
                &[42; 1024],
            )
            .unwrap();
    }
    svc.poll(&mut r, &mut stacks, 0, &mut rng).unwrap();
    assert_eq!(
        svc.next_deadline(0),
        Some(0),
        "full socket must retain the pending reply"
    );
    stacks[1].poll(1).unwrap();
    while stacks[1].output().is_some() {}
    svc.poll(&mut r, &mut stacks, 1, &mut rng).unwrap();
    assert_eq!(svc.queued_replies(), (0, 0));
    let mut svc = Service::default();
    for _ in 0..257 {
        svc.queue(vec![Action::Reply {
            client: Client::udp("[fe80::99]:40000".parse().unwrap()),
            bytes: vec![0; 12],
        }]);
    }
    assert_eq!(svc.queued_replies().0, 256);
    assert!(svc.queued_replies().1 <= 65536);
    let mut svc = Service::default();
    for _ in 0..20 {
        svc.queue(vec![Action::Reply {
            client: Client::udp("[fe80::99]:40000".parse().unwrap()),
            bytes: vec![0; 4096],
        }]);
    }
    assert!(svc.queued_replies().0 < 20);
    assert!(svc.queued_replies().1 <= 65536);
}
#[test]
fn s09_service_upstream_slot_bounds_release_on_expiry() {
    use snac_rs::dns::{resolver::Resolver, service::Service};
    for tcp in [false, true] {
        let mut r = Resolver::new(true);
        let mut rng = ScriptedRandom::new(0..10000);
        let mut svc = Service::default();
        let mut stacks = [
            stack("fe80::1".parse().unwrap()),
            stack("fe80::2".parse().unwrap()),
        ];
        stacks[1].listen_udp(53).unwrap();
        for n in 0..9 {
            r.set_upstreams(&[format!("[fe80::{:x}]:53", 100 + n).parse().unwrap()])
                .unwrap();
            r.submit(
                snac_rs::dns::resolver::Client::udp(
                    format!("[fe80::{:x}]:40000", 200 + n).parse().unwrap(),
                ),
                &query(&format!("n{n}.test."), 1, n),
                0,
                &mut rng,
            )
            .unwrap();
        }
        if tcp {
            let queries: Vec<_> = r.queries().cloned().collect();
            for q in queries {
                let mut m = Message::parse(&q.bytes, Context::Unicast).unwrap();
                m.flags = 0x8380;
                r.receive(
                    q.exchange,
                    q.server,
                    q.source_port,
                    false,
                    &m.encode().unwrap(),
                    0,
                    &mut rng,
                )
                .unwrap();
            }
        }
        svc.poll(&mut r, &mut stacks, 0, &mut rng).unwrap();
        let (udp, _, up) = svc.counts();
        assert_eq!((udp, up), if tcp { (0, 8) } else { (8, 0) });
        svc.poll(&mut r, &mut stacks, 10000, &mut rng).unwrap();
        assert_eq!(svc.counts(), (0, 0, 0));
    }
}

#[test]
fn s09_service_client_stream_table_has_shared_connection_cap() {
    use snac_rs::dns::{resolver::Resolver, service::Service};
    let mut r = Resolver::new(true);
    let mut rng = ScriptedRandom::new([]);
    let mut svc = Service::default();
    let mut stacks = [
        stack("fe80::1".parse().unwrap()),
        stack("fe80::2".parse().unwrap()),
    ];
    stacks[1].listen_tcp(53).unwrap();
    stacks[1].listen_udp(53).unwrap();
    for n in 0..17 {
        let source: IpAddr = format!("fe80::{:x}", 100 + n).parse().unwrap();
        let mut h = stack(source);
        for port in 40000..if n == 16 { 40001 } else { 40004 } {
            h.connect(source, port, "fe80::2".parse().unwrap(), 53, 0)
                .unwrap();
            h.poll(0).unwrap();
            while let Some(p) = h.output() {
                stacks[1].input(&p, 0).unwrap();
                stacks[1].poll(0).unwrap();
                svc.poll(&mut r, &mut stacks, 0, &mut rng).unwrap();
                while let Some(p) = stacks[1].output() {
                    h.input(&p, 0).unwrap();
                }
            }
        }
        assert_eq!(svc.counts().1, ((n + 1) * 4).min(64));
    }
    stacks[1].poll(120001).unwrap();
    svc.poll(&mut r, &mut stacks, 120001, &mut rng).unwrap();
    assert_eq!(svc.counts().1, 0);
}
#[test]
fn s09_driver_rejects_bad_tcp_framing_and_answers_after_client_half_close() {
    use snac_rs::dns::wire::TcpFrames;
    for bad in [true, false] {
        let mut d = driver();
        let mut rng = ScriptedRandom::new([]);
        d.start(0, &mut rng).unwrap();
        d.step(1000, &mut rng).unwrap();
        learn(&mut d, Link::Stub, &mut rng);
        let mut hosts = [stack(peer(Link::Ail)), stack(peer(Link::Stub))];
        let id = hosts[1]
            .connect(
                peer(Link::Stub),
                40001,
                d.router.identity.link_local(Link::Stub).into(),
                53,
                1001,
            )
            .unwrap();
        for now in (1010..1500).step_by(10) {
            cycle(&mut d, &mut hosts, now, &mut rng);
        }
        let b = if bad {
            vec![0, 1, 42]
        } else {
            TcpFrames::frame(&query("offline.test.", 1, 15)).unwrap()
        };
        hosts[1].send_tcp(id, &b).unwrap();
        if !bad {
            hosts[1].close(id);
        }
        let mut bytes = vec![];
        for now in (1500..3000).step_by(10) {
            cycle(&mut d, &mut hosts, now, &mut rng);
            bytes.extend(hosts[1].receive_tcp(id));
        }
        assert_eq!(d.dns.pending_count(), 0);
        if bad {
            assert!(bytes.is_empty());
            assert!(!hosts[1].established(id));
        } else {
            let mut f = TcpFrames::new(65535).unwrap();
            f.input(&bytes).unwrap();
            let m = Message::parse(
                &f.pop().expect("half-close still permits response"),
                Context::Unicast,
            )
            .unwrap();
            assert_eq!(m.id, 15);
            assert_eq!(m.flags & 15, 2);
        }
    }
}

#[test]
fn s10_driver_dot_pipeline_large_query_and_update_dispatch() {
    use snac_rs::{
        dns::wire::TcpFrames,
        service_io::{identity::TlsIdentity, tls::opportunistic_client},
    };
    use std::io::{Read, Write};
    struct Sender<'a>(&'a mut Stack, usize);
    impl Write for Sender<'_> {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.send_tcp(self.1, b)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut d = driver();
    let mut rng = ScriptedRandom::new(1..10000);
    let identity =
        TlsIdentity::load_or_create(&mut MemoryStore::default(), 1789473600, &mut rng).unwrap();
    d.enable_dot(identity.server_config().unwrap().into())
        .unwrap();
    d.dns.set_srp_clock(1789473600, 0);
    d.start(0, &mut rng).unwrap();
    d.step(1000, &mut rng).unwrap();
    learn(&mut d, Link::Stub, &mut rng);
    let mut hosts = [stack(peer(Link::Ail)), stack(peer(Link::Stub))];
    let id = hosts[1]
        .connect(
            peer(Link::Stub),
            40001,
            d.router.identity.link_local(Link::Stub).into(),
            853,
            1001,
        )
        .unwrap();
    for now in (1010..1500).step_by(10) {
        cycle(&mut d, &mut hosts, now, &mut rng);
    }
    assert!(hosts[1].established(id));
    let mut tls = rustls::ClientConnection::new(
        opportunistic_client().unwrap().into(),
        "self-signed.test".try_into().unwrap(),
    )
    .unwrap();
    for now in (1500..3000).step_by(10) {
        tls.write_tls(&mut Sender(&mut hosts[1], id)).unwrap();
        cycle(&mut d, &mut hosts, now, &mut rng);
        let b = hosts[1].receive_tcp(id);
        let mut p = b.as_slice();
        while !p.is_empty() {
            let n = tls.read_tls(&mut p).unwrap();
            assert!(n > 0);
            tls.process_new_packets().unwrap();
        }
    }
    assert!(!tls.is_handshaking());
    let mut bytes = TcpFrames::frame(&query("offline.test.", 1, 77)).unwrap();
    let mut update = Message::new(78, 0x2800);
    update.questions.push(Question {
        name: "default.service.arpa.".parse().unwrap(),
        kind: 6,
        class: 1,
    });
    bytes.extend(TcpFrames::frame(&update.encode().unwrap()).unwrap());
    let mut large = Message::parse(&query("large.test.", 16, 79), Context::Unicast).unwrap();
    large.additional.push(Record {
        name: ".".parse().unwrap(),
        kind: 41,
        class: 4096,
        ttl: 0,
        data: Rdata::Opt(vec![(65000, vec![9; 60000])]),
    });
    bytes.extend(TcpFrames::frame(&large.encode().unwrap()).unwrap());
    let mut bad_signature = include_bytes!("fixtures/srp/alg13.bin").to_vec();
    *bad_signature.last_mut().unwrap() ^= 1;
    bytes.extend(TcpFrames::frame(&bad_signature).unwrap());
    tls.writer().write_all(&bytes).unwrap();
    let mut frames = TcpFrames::new(65535).unwrap();
    let mut replies = std::collections::BTreeMap::new();
    for now in (3000..15000).step_by(10) {
        tls.write_tls(&mut Sender(&mut hosts[1], id)).unwrap();
        cycle(&mut d, &mut hosts, now, &mut rng);
        let b = hosts[1].receive_tcp(id);
        let mut p = b.as_slice();
        while !p.is_empty() {
            let n = tls.read_tls(&mut p).unwrap();
            assert!(n > 0);
            tls.process_new_packets().unwrap();
        }
        let mut b = [0; 8192];
        while let Ok(n) = tls.reader().read(&mut b) {
            if n == 0 {
                break;
            }
            frames.input(&b[..n]).unwrap();
        }
        while let Some(b) = frames.pop() {
            let m = Message::parse(&b, Context::Unicast).unwrap();
            replies.insert(m.id, m);
        }
        if replies.len() == 4 {
            break;
        }
    }
    assert_eq!(replies.len(), 4);
    assert_eq!(
        replies[&0x1234].flags & 15,
        5,
        "bad SIG(0) is REFUSED over TLS"
    );
    assert_eq!(replies[&77].flags & 15, 2);
    assert_eq!(replies[&79].flags & 15, 2);
    assert_eq!((replies[&78].flags >> 11) & 15, 5);
    assert_ne!(replies[&78].flags & 15, 0, "unsigned update never succeeds");
    assert_eq!(d.dns.pending_count(), 0);
    let own = d.stack_mut(Link::Stub).unwrap().connections();
    assert_eq!(own.len(), 1);
    assert_eq!(
        d.stack_mut(Link::Stub).unwrap().tcp_buffer_bytes(own[0]),
        8192
    );
}

#[test]
fn s10_dot_activation_refuses_another_owners_port_and_bounds_ring_sizes() {
    use snac_rs::service_io::identity::TlsIdentity;
    let mut d = driver();
    let mut rng = ScriptedRandom::new(1..10000);
    d.start(0, &mut rng).unwrap();
    d.stack_mut(Link::Stub).unwrap().listen_tcp(853).unwrap();
    let i = TlsIdentity::load_or_create(&mut MemoryStore::default(), 1789473600, &mut rng).unwrap();
    assert!(d.enable_dot(i.server_config().unwrap().into()).is_err());
    let mut s = stack("fe80::2".parse().unwrap());
    assert!(s.listen_tcp_buffered(853, 4095).is_err());
    assert!(s.listen_tcp_buffered(853, 8193).is_err());
    assert!(s.listen_tcp_buffered(853, 4096).is_ok());
    assert!(s.listen_tcp_buffered(854, 8192).is_ok());
}
#[test]
fn s10_tls_handshake_exhaustion_shares_sixty_four_slots_and_expires() {
    use snac_rs::dns::{resolver::Resolver, service::Service};
    use snac_rs::service_io::identity::TlsIdentity;
    let mut r = Resolver::new(true);
    let mut rng = ScriptedRandom::new(1..10000);
    let identity =
        TlsIdentity::load_or_create(&mut MemoryStore::default(), 1789473600, &mut rng).unwrap();
    let mut svc = Service::default();
    svc.enable_tls(identity.server_config().unwrap().into());
    let mut stacks = [
        stack("fe80::1".parse().unwrap()),
        stack("fe80::2".parse().unwrap()),
    ];
    stacks[1].listen_tcp_buffered(853, 4096).unwrap();
    for n in 0..17 {
        let source: IpAddr = format!("fe80::{:x}", 100 + n).parse().unwrap();
        let mut h = stack(source);
        for port in 40000..if n == 16 { 40001 } else { 40004 } {
            h.connect(source, port, "fe80::2".parse().unwrap(), 853, 0)
                .unwrap();
            h.poll(0).unwrap();
            while let Some(p) = h.output() {
                stacks[1].input(&p, 0).unwrap();
                stacks[1].poll(0).unwrap();
                svc.poll(&mut r, &mut stacks, 0, &mut rng).unwrap();
                while let Some(p) = stacks[1].output() {
                    h.input(&p, 0).unwrap();
                }
            }
        }
        assert_eq!(svc.counts().1, ((n + 1) * 4).min(64));
    }
    assert_eq!(svc.next_deadline(0), Some(10000));
    svc.poll(&mut r, &mut stacks, 10000, &mut rng).unwrap();
    stacks[1].poll(10001).unwrap();
    svc.poll(&mut r, &mut stacks, 10001, &mut rng).unwrap();
    assert_eq!(svc.counts().1, 0);
}
