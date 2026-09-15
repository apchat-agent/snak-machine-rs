mod common;
use snac_rs::{
    dns::wire::{Context, Message, Name, Question, Rdata, Record},
    mdns::wire::{encode, Datagram},
    Link,
};
use std::net::{IpAddr, SocketAddr};
fn query() -> Message {
    let mut m = Message::new(0, 0);
    m.questions.push(Question {
        name: "light.local.".parse().unwrap(),
        kind: 28,
        class: 0x8001,
    });
    m
}
fn sum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| (u32::from(p[0]) << 8) | u32::from(*p.get(1).unwrap_or(&0)))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn packet(v6: bool, message: &Message, source_port: u16, hop: u8) -> Vec<u8> {
    let body = message.encode().unwrap();
    let mut udp = source_port.to_be_bytes().to_vec();
    udp.extend(5353u16.to_be_bytes());
    udp.extend(((body.len() + 8) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(body);
    if v6 {
        let source = "fe80::2".parse().unwrap();
        let destination = "ff02::fb".parse().unwrap();
        let c = common::sum(source, destination, 17, &udp);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        let mut b = vec![0x60, 0, 0, 0];
        b.extend((udp.len() as u16).to_be_bytes());
        b.extend([17, hop]);
        b.extend(source.octets());
        b.extend(destination.octets());
        b.extend(udp);
        b
    } else {
        let mut pseudo = vec![192, 0, 2, 2, 224, 0, 0, 251, 0, 17];
        pseudo.extend((udp.len() as u16).to_be_bytes());
        pseudo.extend(&udp);
        let c = sum(&pseudo);
        udp[6..8].copy_from_slice(&c.to_be_bytes());
        let mut b = vec![0x45, 0];
        b.extend(((20 + udp.len()) as u16).to_be_bytes());
        b.extend([0, 0, 0, 0, hop, 17, 0, 0, 192, 0, 2, 2, 224, 0, 0, 251]);
        let c = sum(&b);
        b[10..12].copy_from_slice(&c.to_be_bytes());
        b.extend(udp);
        b
    }
}
#[test]
fn s13_mdns_datagrams_validate_both_ip_families_ports_hops_and_all_truncations() {
    for v6 in [false, true] {
        let b = packet(v6, &query(), 5353, 255);
        let d = Datagram::parse(Link::Ail, &b).unwrap();
        assert_eq!(d.source.port(), 5353);
        assert_eq!(d.destination.port(), 5353);
        assert_eq!(d.message.questions, query().questions);
        assert!(Datagram::parse(Link::Stub, &b).is_err());
        assert!(Datagram::parse(Link::Ail, &packet(v6, &query(), 5353, 254)).is_err());
        assert!(Datagram::parse(Link::Ail, &packet(v6, &query(), 0, 255)).is_err());
        for n in 0..b.len() {
            assert!(
                Datagram::parse(Link::Ail, &b[..n]).is_err(),
                "family {v6}, prefix {n}"
            );
        }
        for at in if v6 {
            vec![4, 6, 7, 40, 42, 44, 46, 48, 49]
        } else {
            vec![0, 2, 6, 8, 9, 10, 20, 22, 24, 26, 28, 29]
        } {
            let mut corrupt = b.clone();
            corrupt[at] ^= 1;
            assert!(
                Datagram::parse(Link::Ail, &corrupt).is_err(),
                "family {v6}, byte {at}"
            );
        }
        let mut extra = b.clone();
        extra.push(0);
        assert!(Datagram::parse(Link::Ail, &extra).is_err());
        assert_eq!(encode(d.source, d.destination, &d.message).unwrap(), b);
        let mut answer = query();
        answer.flags = 0x8400; // Questions and nonzero IDs must be ignored by the receive engine.
        answer.id = 99;
        assert!(Datagram::parse(Link::Ail, &packet(v6, &answer, 40000, 255)).is_err());
        assert!(Datagram::parse(Link::Ail, &packet(v6, &answer, 5353, 255)).is_ok());
        assert!(Datagram::parse(Link::Ail, &packet(v6, &query(), 40000, 255)).is_ok());
    }
}
#[test]
fn s13_mdns_ignores_reserved_flags_but_rejects_wrong_opcode_rcode_and_excessive_work() {
    for flags in [
        0, 0x0400, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010, 0x8000, 0x8200, 0x8400,
    ] {
        let mut m = query();
        m.flags = flags;
        assert!(
            Datagram::parse(Link::Ail, &packet(true, &m, 5353, 255)).is_ok(),
            "flags {flags:x}"
        );
    }
    for flags in [0x0800, 0x2800, 0x8001, 0x000f] {
        let mut m = query();
        m.flags = flags;
        assert!(Datagram::parse(Link::Ail, &packet(true, &m, 5353, 255)).is_err());
    }
    let mut m = query();
    m.questions = vec![m.questions[0].clone(); 128];
    let s: SocketAddr = "[fe80::2]:5353".parse().unwrap();
    let d: SocketAddr = "[ff02::fb]:5353".parse().unwrap();
    let b = encode(s, d, &m).unwrap();
    assert!(Datagram::parse(Link::Ail, &b).is_ok());
    m.questions.push(m.questions[0].clone());
    assert!(Datagram::parse(Link::Ail, &packet(true, &m, 5353, 255)).is_err());
    let mut m = Message::new(0, 0x8400);
    m.answers = vec![
        Record {
            name: "a.local.".parse().unwrap(),
            kind: 1,
            class: 0x8001,
            ttl: 120,
            data: Rdata::A([192, 0, 2, 2])
        };
        512
    ];
    assert!(Datagram::parse(Link::Ail, &encode(s, d, &m).unwrap()).is_ok());
    m.answers.push(m.answers[0].clone());
    assert!(encode(s, d, &m).is_err());
    assert!(encode(s, "[ff02::fb]:53".parse().unwrap(), &query()).is_err());
    assert!(encode(s, "224.0.0.251:5353".parse().unwrap(), &query()).is_err());
    assert!(Datagram::parse(Link::Ail, &vec![0; 9001]).is_err());
}
#[test]
fn s13_mdns_large_single_records_respect_nine_thousand_byte_ip_limit() {
    let mut m = Message::new(0, 0x8400);
    m.answers.push(Record {
        name: Name::root(),
        kind: 16,
        class: 1,
        ttl: 120,
        data: Rdata::Txt(vec![vec![1; 250]; 35]),
    });
    for (s, d) in [
        ("192.0.2.2:5353", "224.0.0.251:5353"),
        ("[fe80::2]:5353", "[ff02::fb]:5353"),
    ] {
        let b = encode(s.parse().unwrap(), d.parse().unwrap(), &m).unwrap();
        assert!(b.len() <= 9000);
        Datagram::parse(Link::Ail, &b).unwrap();
    }
    if let Rdata::Txt(v) = &mut m.answers[0].data {
        v.push(vec![1; 250]);
    }
    assert!(encode(
        "192.0.2.2:5353".parse().unwrap(),
        "224.0.0.251:5353".parse().unwrap(),
        &m
    )
    .is_err());
    let _ = Context::Mdns;
    let _: IpAddr = "fe80::1".parse().unwrap();
}

fn a_record(name: &str, last: u8, ttl: u32, unique: bool) -> Record {
    Record {
        name: name.parse().unwrap(),
        kind: 1,
        class: if unique { 0x8001 } else { 1 },
        ttl,
        data: Rdata::A([192, 0, 2, last]),
    }
}
fn response(records: Vec<Record>) -> Message {
    let mut m = Message::new(99, 0x8000); // AA and ID have no receive significance.
    m.answers = records;
    m
}
fn question(name: &str, kind: u16) -> Question {
    Question {
        name: name.parse().unwrap(),
        kind,
        class: 1,
    }
}
#[test]
fn s13_cache_flush_bursts_goodbyes_rescue_and_expiry_use_one_second_grace() {
    use snac_rs::{mdns::cache::Cache, time::ScriptedRandom};
    let mut c = Cache::default();
    let mut rng = ScriptedRandom::new([]);
    let q = question("lamp.local.", 1);
    c.receive(
        &response(vec![a_record("lamp.local.", 1, 120, true)]),
        0,
        &mut rng,
    )
    .unwrap();
    c.receive(
        &response(vec![a_record("LAMP.local.", 2, 120, true)]),
        2000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(c.answers(&q, 2999).len(), 2);
    c.receive(
        &response(vec![a_record("lamp.local.", 3, 120, true)]),
        2500,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        c.answers(&q, 3500).len(),
        2,
        "recent members of a burst survive flush"
    );
    c.receive(
        &response(vec![a_record("lamp.local.", 2, 0, true)]),
        4000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(c.answers(&q, 4999).len(), 2);
    c.receive(
        &response(vec![a_record("lamp.local.", 2, 10, true)]),
        4500,
        &mut rng,
    )
    .unwrap();
    assert_eq!(c.answers(&q, 5000).len(), 2, "fresh data rescues goodbye");
    assert_eq!(
        c.answers(&q, 5500).len(),
        1,
        "old other member expires after flush"
    );
    assert_eq!(c.answers(&q, 14500).len(), 0);
    c.expire(14500);
    assert_eq!(c.counts(), (0, 0, 0));
    c.receive(
        &response(vec![a_record("lamp.local.", 8, 0, true)]),
        15000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        c.counts(),
        (0, 0, 0),
        "unsolicited goodbye cannot create cache state"
    );
}
#[test]
fn s13_cache_never_learns_queries_pseudorecords_or_unknown_pointer_data_and_tracks_nsec() {
    use snac_rs::{mdns::cache::Cache, time::ScriptedRandom};
    let mut c = Cache::default();
    let mut rng = ScriptedRandom::new([]);
    let mut m = response(vec![a_record("lamp.local.", 1, 120, false)]);
    m.flags = 0;
    c.receive(&m, 0, &mut rng).unwrap();
    assert_eq!(c.counts(), (0, 0, 0));
    m.flags = 0x8400;
    m.answers.clear();
    m.additional.push(Record {
        name: Name::root(),
        kind: 41,
        class: 4096,
        ttl: 120,
        data: Rdata::Opt(vec![]),
    });
    m.additional.push(Record {
        name: "lamp.local.".parse().unwrap(),
        kind: 65000,
        class: 1,
        ttl: 120,
        data: Rdata::Opaque(vec![0xc0, 12]),
    });
    c.receive(&m, 0, &mut rng).unwrap();
    assert_eq!(c.counts(), (0, 0, 0));
    let mut n = a_record("lamp.local.", 1, 120, true);
    n.kind = 47;
    n.data = Rdata::Nsec {
        next: n.name.clone(),
        bitmap: vec![0, 6, 0x40, 0, 0, 0, 0, 1],
    };
    c.receive(&response(vec![n]), 0, &mut rng).unwrap();
    assert!(c.negative(&question("LAMP.local.", 28), 0));
    assert!(!c.negative(&question("lamp.local.", 1), 0));
    assert!(!c.negative(&question("other.local.", 28), 0));
    assert!(!c.negative(&question("lamp.local.", 28), 120000));
}
#[test]
fn s13_cache_bounds_rrsets_bytes_and_lru_without_losing_recent_lookup() {
    use snac_rs::{mdns::cache::Cache, time::ScriptedRandom};
    let mut c = Cache::default();
    let mut rng = ScriptedRandom::new([]);
    for i in 0..1024 {
        c.receive(
            &response(vec![a_record(&format!("n{i}.local."), 1, 120, false)]),
            i,
            &mut rng,
        )
        .unwrap();
    }
    assert_eq!(c.counts().0, 1024);
    c.answers(&question("n0.local.", 1), 1025);
    c.receive(
        &response(vec![a_record("new.local.", 1, 120, false)]),
        1026,
        &mut rng,
    )
    .unwrap();
    assert_eq!(c.counts().0, 1024);
    assert_eq!(c.answers(&question("n0.local.", 1), 1027).len(), 1);
    assert!(c.answers(&question("n1.local.", 1), 1027).is_empty());
    let mut c = Cache::default();
    for i in 0..1100 {
        let mut r = a_record(&format!("t{i}.local."), 1, 120, false);
        r.kind = 16;
        r.data = Rdata::Txt(vec![vec![42; 250]; 30]);
        c.receive(&response(vec![r]), i, &mut rng).unwrap();
        assert!(c.counts().2 <= 4 * 1024 * 1024);
    }
    assert!(
        c.counts().0 < 1024,
        "byte budget is exercised independently"
    );
    c.expire(200000);
    assert_eq!(c.counts(), (0, 0, 0));
}
#[test]
fn s13_cache_passive_failure_observation_expires_stale_records() {
    use snac_rs::{mdns::cache::Cache, time::ScriptedRandom};
    let mut c = Cache::default();
    let mut rng = ScriptedRandom::new([]);
    let q = question("lamp.local.", 1);
    c.receive(
        &response(vec![a_record("lamp.local.", 1, 120, false)]),
        0,
        &mut rng,
    )
    .unwrap();
    c.observe_question(&q, &[], 1000);
    c.observe_question(&q, &[], 2000);
    assert_eq!(c.answers(&q, 10999).len(), 1);
    assert!(c.answers(&q, 11000).is_empty());
    c.receive(
        &response(vec![a_record("lamp.local.", 1, 120, false)]),
        12000,
        &mut rng,
    )
    .unwrap();
    c.observe_question(&q, &[], 13000);
    c.observe_question(&q, &[], 14000);
    c.receive(
        &response(vec![a_record("lamp.local.", 1, 120, false)]),
        15000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        c.answers(&q, 23000).len(),
        1,
        "response cancels passive failure"
    );
    c.observe_question(&q, &[a_record("lamp.local.", 1, 120, false)], 24000);
    c.observe_question(&q, &[a_record("lamp.local.", 1, 120, false)], 25000);
    assert_eq!(
        c.answers(&q, 35000).len(),
        1,
        "known-answer suppression explains missing response"
    );
}
