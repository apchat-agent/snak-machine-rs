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
