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

#[test]
fn s13_questions_retry_only_after_send_refresh_unique_records_and_cancel() {
    use snac_rs::{mdns::query::Querier, time::ScriptedRandom};
    let mut e = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let q = question("lamp.local.", 1);
    let id = e.start(q.clone(), 200000, 0, &mut rng).unwrap();
    assert!(e.poll(19).unwrap().is_none());
    let batch = e.poll(20).unwrap().unwrap();
    assert_eq!(batch.id, id);
    assert_eq!(batch.messages[0].questions[0].class, 0x8001);
    e.sent(id, false, 20);
    assert!(e.poll(21).unwrap().is_none());
    e.poll(120).unwrap().unwrap();
    e.sent(id, true, 120);
    assert!(e.poll(1119).unwrap().is_none());
    let batch = e.poll(1120).unwrap().unwrap();
    assert_eq!(batch.messages[0].questions[0].class, 1);
    e.sent(id, true, 1120);
    assert!(e.poll(3119).unwrap().is_none());
    e.poll(3120).unwrap().unwrap();
    e.sent(id, true, 3120);
    let d = Datagram::parse(
        Link::Ail,
        &packet(
            true,
            &response(vec![a_record("lamp.local.", 1, 100, true)]),
            5353,
            255,
        ),
    )
    .unwrap();
    assert!(e.receive(&d, true, 4000, &mut rng).unwrap());
    assert!(e.poll(83999).unwrap().is_none());
    for at in [84000, 89000, 94000, 99000] {
        let b = e.poll(at).unwrap().unwrap();
        assert!(
            b.messages[0].answers.is_empty(),
            "expiring records must not suppress refresh"
        );
        e.sent(id, true, at);
        assert!(e.poll(at + 1).unwrap().is_none());
    }
    assert!(e.cache.answers(&q, 104000).is_empty());
    e.stop(id);
    assert!(e.poll(150000).unwrap().is_none());
    assert_eq!(e.counts().0, 0);
    // Uninterested records never cause maintenance queries.
    e.cache.receive(&d.message, 150000, &mut rng).unwrap();
    assert!(e.poll(230000).unwrap().is_none());
}
#[test]
fn s13_unicast_answers_require_recent_successful_qu_and_onlink_source() {
    use snac_rs::{mdns::query::Querier, time::ScriptedRandom};
    let mut e = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let mut d = Datagram {
        source: "[fe80::2]:5353".parse().unwrap(),
        destination: "[fe80::1]:5353".parse().unwrap(),
        message: response(vec![a_record("lamp.local.", 1, 120, true)]),
    };
    assert!(!e.receive(&d, true, 0, &mut rng).unwrap());
    let id = e
        .start(question("lamp.local.", 1), 10000, 0, &mut rng)
        .unwrap();
    e.poll(20).unwrap().unwrap();
    e.sent(id, false, 20);
    assert!(!e.receive(&d, true, 21, &mut rng).unwrap());
    e.poll(120).unwrap().unwrap();
    e.sent(id, true, 120);
    assert!(!e.receive(&d, false, 121, &mut rng).unwrap());
    assert!(e.receive(&d, true, 121, &mut rng).unwrap());
    assert!(!e.receive(&d, true, 2121, &mut rng).unwrap());
    d.destination = "[ff02::fb]:5353".parse().unwrap();
    assert!(
        e.receive(&d, false, 2122, &mut rng).unwrap(),
        "multicast works across overlay subnets"
    );
    e.available(false, 2200, &mut rng).unwrap();
    assert!(e
        .cache
        .answers(&question("lamp.local.", 1), 2200)
        .is_empty());
    assert!(!e.receive(&d, true, 2300, &mut rng).unwrap());
    assert!(e.poll(3000).unwrap().is_none());
    e.available(true, 4000, &mut rng).unwrap();
    assert_eq!(
        e.poll(4020).unwrap().unwrap().messages[0].questions[0].class,
        0x8001
    );
}
#[test]
fn s13_known_answers_span_bounded_packets_and_duplicate_queries_are_safely_suppressed() {
    use snac_rs::{mdns::query::Querier, time::ScriptedRandom};
    let mut e = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let q = question("_light._tcp.local.", 12);
    let mut rrs = vec![];
    for i in 0..100 {
        rrs.push(Record {
            name: q.name.clone(),
            kind: 12,
            class: 1,
            ttl: 120,
            data: Rdata::Name(
                format!("long-printer-name-number-{i}._light._tcp.local.")
                    .parse()
                    .unwrap(),
            ),
        });
    }
    e.cache.receive(&response(rrs), 0, &mut rng).unwrap();
    let id = e.start(q.clone(), 100000, 0, &mut rng).unwrap();
    let batch = e.poll(20).unwrap().unwrap();
    assert!(batch.messages.len() > 1);
    let last = batch.messages.len() - 1;
    assert_eq!(
        batch
            .messages
            .iter()
            .map(|m| m.answers.len())
            .sum::<usize>(),
        100
    );
    for (i, m) in batch.messages.iter().enumerate() {
        assert_eq!(m.questions.len(), usize::from(i == 0));
        assert_eq!(m.flags & 0x200 != 0, i != last);
        assert!(m.answers.iter().all(|r| r.class == 1));
        assert!(m.encode_context(Context::Mdns).unwrap().len() <= 1200);
    }
    e.sent(id, true, 20);
    let mut m = Message::new(0, 0);
    m.questions.push(q.clone());
    let d = Datagram {
        source: "[fe80::2]:5353".parse().unwrap(),
        destination: "[ff02::fb]:5353".parse().unwrap(),
        message: m,
    };
    assert!(e.receive(&d, true, 1000, &mut rng).unwrap());
    assert!(
        e.poll(1020).unwrap().is_none(),
        "peer QM replaces our redundant query"
    );
    let mut d = d;
    d.message.answers.push(Record {
        name: q.name.clone(),
        kind: 12,
        class: 1,
        ttl: 120,
        data: Rdata::Name("unknown._light._tcp.local.".parse().unwrap()),
    });
    e.receive(&d, true, 2999, &mut rng).unwrap();
    assert!(
        e.poll(3000).unwrap().is_some(),
        "peer knowledge we lack cannot suppress our query"
    );
}
#[test]
fn s13_question_rate_caps_and_reconfirmation_make_progress_during_floods() {
    use snac_rs::{mdns::query::Querier, time::ScriptedRandom};
    let mut e = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    for i in 0..128 {
        e.start(question(&format!("q{i}.local."), 1), 10000, 0, &mut rng)
            .unwrap();
    }
    assert!(e
        .start(question("overflow.local.", 1), 10000, 0, &mut rng)
        .is_err());
    assert_eq!(e.counts().0, 128);
    let mut accepted = 0;
    for i in 0..500 {
        let d = Datagram {
            source: SocketAddr::new(format!("fe80::{:x}", i + 2).parse().unwrap(), 5353),
            destination: "[ff02::fb]:5353".parse().unwrap(),
            message: query(),
        };
        accepted += usize::from(e.receive(&d, true, 20, &mut rng).unwrap());
        assert!(e.counts().1 <= 32);
        assert!(e.cache.counts().2 <= 4 * 1024 * 1024);
    }
    assert_eq!(e.counts().1, 32);
    assert!(accepted <= 128);
    for _ in 0..128 {
        let batch = e.poll(20).unwrap().unwrap();
        e.sent(batch.id, true, 20);
    }
    assert!(e.poll(20).unwrap().is_none());
    e.poll(10000).unwrap();
    assert_eq!(e.counts().0, 0);
    let q = question("stale.local.", 1);
    e.cache
        .receive(
            &response(vec![a_record("stale.local.", 1, 120, true)]),
            10000,
            &mut rng,
        )
        .unwrap();
    let id = e.reconfirm(q.clone(), 10000, &mut rng).unwrap();
    e.poll(10020).unwrap().unwrap();
    e.sent(id, true, 10020);
    e.poll(11020).unwrap().unwrap();
    e.sent(id, true, 11020);
    assert_eq!(e.cache.answers(&q, 19999).len(), 1);
    assert!(e.cache.answers(&q, 20000).is_empty());
}

#[test]
fn s13_nsec_next_name_is_ignored_and_duplicate_question_compares_known_record_membership() {
    use snac_rs::{mdns::query::Querier, time::ScriptedRandom};
    let mut e = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let mut n = a_record("lamp.local.", 1, 120, true);
    n.kind = 47;
    n.data = Rdata::Nsec {
        next: "future.local.".parse().unwrap(),
        bitmap: vec![0, 6, 0x40, 0, 0, 0, 0, 1],
    };
    e.cache.receive(&response(vec![n]), 0, &mut rng).unwrap();
    assert!(
        e.cache.negative(&question("lamp.local.", 28), 0),
        "RFC 6762 6.1 ignores future next-name semantics"
    );
    let q = question("shared.local.", 1);
    let rr = a_record("shared.local.", 1, 120, false);
    e.cache
        .receive(&response(vec![rr.clone()]), 0, &mut rng)
        .unwrap();
    let id = e.start(q.clone(), 10000, 0, &mut rng).unwrap();
    e.poll(20).unwrap().unwrap();
    e.sent(id, true, 20);
    let mut m = Message::new(0, 0);
    m.questions.push(q);
    m.answers.push(rr);
    let d = Datagram {
        source: "[fe80::2]:5353".parse().unwrap(),
        destination: "[ff02::fb]:5353".parse().unwrap(),
        message: m,
    };
    e.receive(&d, true, 1000, &mut rng).unwrap();
    assert!(
        e.poll(1020).unwrap().is_none(),
        "a one-second TTL difference does not change known-answer membership"
    );
}

fn published() -> Vec<Record> {
    vec![
        a_record("lamp.local.", 2, 120, true),
        Record {
            name: "_light._tcp.local.".parse().unwrap(),
            kind: 12,
            class: 1,
            ttl: 120,
            data: Rdata::Name("Lamp._light._tcp.local.".parse().unwrap()),
        },
    ]
}
#[test]
fn s13_publication_probes_three_times_then_announces_twice_and_only_success_advances() {
    use snac_rs::{mdns::publish::Publisher, time::ScriptedRandom};
    let mut p = Publisher::default();
    let mut rng = ScriptedRandom::new([]);
    let data = published();
    let source = |_: u64, _: u64| data.clone();
    p.replace(1, &[], &data, 0, &mut rng).unwrap();
    let b = p.poll(&source, 0).unwrap().unwrap();
    assert_eq!(b.messages[0].flags, 0);
    assert_eq!(
        b.messages[0].questions[0],
        Question {
            name: "lamp.local.".parse().unwrap(),
            kind: 255,
            class: 0x8001
        }
    );
    assert!(b
        .messages
        .iter()
        .all(|m| m.authority.iter().all(|r| r.class == 1)));
    p.sent(b.token, false, 0);
    assert!(!p.ready(1));
    assert!(p.poll(&source, 99).unwrap().is_none());
    for at in [100, 350, 600] {
        let b = p.poll(&source, at).unwrap().unwrap();
        assert!(b
            .messages
            .iter()
            .all(|m| m.flags == 0 && !m.authority.is_empty()));
        p.sent(b.token, true, at);
        assert!(!p.ready(1));
    }
    assert!(p.poll(&source, 849).unwrap().is_none());
    for at in [850, 1850] {
        let b = p.poll(&source, at).unwrap().unwrap();
        assert!(b
            .messages
            .iter()
            .all(|m| m.id == 0 && m.flags == 0x8400 && m.questions.is_empty()));
        let records: Vec<_> = b.messages.iter().flat_map(|m| &m.answers).collect();
        assert!(records.iter().any(|r| r.kind == 1 && r.class == 0x8001));
        assert!(records.iter().any(|r| r.kind == 12 && r.class == 1));
        assert!(records.iter().any(|r| r.kind == 47));
        p.sent(b.token, true, at);
        assert!(p.ready(1));
    }
    assert!(
        p.poll(&source, 5000).unwrap().is_none(),
        "no periodic unsolicited announcements"
    );
}
#[test]
fn s13_probe_tiebreak_unsigned_rdata_and_live_conflicts_reprobe_or_request_rename() {
    use snac_rs::{mdns::publish::Publisher, time::ScriptedRandom};
    let mut p = Publisher::default();
    let mut rng = ScriptedRandom::new([]);
    let data = vec![a_record("lamp.local.", 50, 120, true)];
    let source = |_: u64, _: u64| data.clone();
    p.replace(1, &[], &data, 0, &mut rng).unwrap();
    let mut d = Datagram {
        source: "[fe80::2]:5353".parse().unwrap(),
        destination: "[ff02::fb]:5353".parse().unwrap(),
        message: response(vec![a_record("lamp.local.", 200, 120, true)]),
    };
    p.receive(&d, &source, 0, &mut rng).unwrap();
    assert_eq!(p.take_conflict(), None, "pre-probe stale response ignored");
    let b = p.poll(&source, 0).unwrap().unwrap();
    p.sent(b.token, true, 0);
    d.message.flags = 0;
    d.message.questions.push(Question {
        name: data[0].name.clone(),
        kind: 255,
        class: 0x8001,
    });
    d.message.authority = d.message.answers.clone();
    d.message.answers.clear();
    p.receive(&d, &source, 100, &mut rng).unwrap();
    assert!(
        p.poll(&source, 1099).unwrap().is_none(),
        "loser waits one second before retrying"
    );
    let b = p.poll(&source, 1100).unwrap().unwrap();
    p.sent(b.token, true, 1100);
    d.message = response(vec![a_record("lamp.local.", 200, 120, true)]);
    p.receive(&d, &source, 1101, &mut rng).unwrap();
    assert_eq!(p.take_conflict(), Some(1));
    assert_eq!(p.take_conflict(), None);
    let renamed = vec![a_record("lamp-2.local.", 50, 120, true)];
    p.replace(1, &data, &renamed, 1101, &mut rng).unwrap();
    let source2 = |_: u64, _: u64| renamed.clone();
    assert!(
        p.poll(&source2, 6100).unwrap().is_none(),
        "failed-probe backoff cannot be bypassed by rename"
    );
    for at in [6101, 6351, 6601, 6851, 7851] {
        let b = p.poll(&source2, at).unwrap().unwrap();
        p.sent(b.token, true, at);
    }
    d.message = response(vec![a_record("lamp-2.local.", 200, 120, true)]);
    p.receive(&d, &source2, 8000, &mut rng).unwrap();
    assert!(!p.ready(1));
    assert_eq!(
        p.take_conflict(),
        None,
        "established conflict first re-probes per section 9"
    );
    assert_eq!(
        p.poll(&source2, 8000).unwrap().unwrap().messages[0].flags,
        0
    );
}
#[test]
fn s13_publication_update_goodbye_withdrawal_and_reconnect_are_derived_and_bounded() {
    use snac_rs::{mdns::publish::Publisher, time::ScriptedRandom};
    let mut p = Publisher::default();
    let mut rng = ScriptedRandom::new([]);
    let old = published();
    let source = |_: u64, _: u64| old.clone();
    p.replace(1, &[], &old, 0, &mut rng).unwrap();
    for at in [0, 250, 500, 750, 1750] {
        let b = p.poll(&source, at).unwrap().unwrap();
        p.sent(b.token, true, at);
    }
    let mut new = old.clone();
    new[0].data = Rdata::A([192, 0, 2, 3]);
    new[1].data = Rdata::Name("Lamp-renamed._light._tcp.local.".parse().unwrap());
    p.replace(1, &old, &new, 3000, &mut rng).unwrap();
    let source2 = |_: u64, _: u64| new.clone();
    let b = p.poll(&source2, 3000).unwrap().unwrap();
    assert_eq!(b.messages.iter().flat_map(|m| &m.answers).count(), 1);
    assert_eq!(b.messages[0].answers[0].kind, 12);
    assert_eq!(b.messages[0].answers[0].ttl, 0);
    p.sent(b.token, true, 3000);
    let b = p.poll(&source2, 3000).unwrap().unwrap();
    assert_eq!(
        b.messages[0].flags, 0x8400,
        "data-only updates announce without probing again"
    );
    p.sent(b.token, true, 3000);
    p.available(false, 3500, &mut rng).unwrap();
    assert!(p.poll(&source2, 4500).unwrap().is_none());
    p.available(true, 5000, &mut rng).unwrap();
    let b = p.poll(&source2, 5000).unwrap().unwrap();
    assert_eq!(b.messages[0].flags, 0);
    assert!(!p.ready(1));
    p.sent(b.token, true, 5000);
    for at in [5250, 5500, 5750, 6750] {
        let b = p.poll(&source2, at).unwrap().unwrap();
        p.sent(b.token, true, at);
    }
    p.replace(1, &new, &[], 8000, &mut rng).unwrap();
    let b = p.poll(&|_, _| vec![], 8000).unwrap().unwrap();
    assert!(b
        .messages
        .iter()
        .flat_map(|m| &m.answers)
        .all(|r| r.ttl == 0));
    p.sent(b.token, true, 8000);
    assert_eq!(p.counts(), (0, 0, 0));
    for i in 0..128 {
        p.replace(
            i,
            &[],
            &[a_record(&format!("p{i}.local."), 1, 120, true)],
            9000,
            &mut rng,
        )
        .unwrap();
    }
    let before = p.counts();
    assert!(p.replace(129, &[], &published(), 9000, &mut rng).is_err());
    assert_eq!(p.counts(), before);
    let mut p = Publisher::default();
    let records: Vec<_> = (0u16..4096)
        .map(|i| Record {
            name: "shared.local.".parse().unwrap(),
            kind: 16,
            class: 1,
            ttl: 120,
            data: Rdata::Txt(vec![i.to_be_bytes().to_vec()]),
        })
        .collect();
    p.replace(1, &[], &records, 0, &mut rng).unwrap();
    assert_eq!(p.counts().1, 4096);
    assert!(p
        .replace(
            2,
            &[],
            &[a_record("extra.local.", 1, 120, false)],
            0,
            &mut rng
        )
        .is_err());
    assert_eq!(p.counts().1, 4096);
    assert!(p.counts().2 <= 4 * 1024 * 1024);
}

fn established() -> (snac_rs::mdns::publish::Publisher, Vec<Record>) {
    use snac_rs::{mdns::publish::Publisher, time::ScriptedRandom};
    let mut p = Publisher::default();
    let mut rng = ScriptedRandom::new([]);
    let mut data = published();
    data.push(Record {
        name: "Lamp._light._tcp.local.".parse().unwrap(),
        kind: 33,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Srv {
            priority: 0,
            weight: 0,
            port: 1234,
            target: "lamp.local.".parse().unwrap(),
        },
    });
    data.push(Record {
        name: "Lamp._light._tcp.local.".parse().unwrap(),
        kind: 16,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Txt(vec![vec![0, 255, 61]]),
    });
    p.replace(1, &[], &data, 0, &mut rng).unwrap();
    for at in [0, 250, 500, 750, 1750] {
        let b = p.poll(&|_, _| data.clone(), at).unwrap().unwrap();
        p.sent(b.token, true, at);
    }
    (p, data)
}
fn peer_query(q: Question) -> Datagram {
    let mut message = Message::new(42, 0);
    message.questions.push(q);
    Datagram {
        source: "[fe80::2]:5353".parse().unwrap(),
        destination: "[ff02::fb]:5353".parse().unwrap(),
        message,
    }
}
#[test]
fn s13_responder_browse_resolve_qu_qm_legacy_and_negative_answers_are_authoritative() {
    use snac_rs::{mdns::respond::Responder, time::ScriptedRandom};
    let (mut p, data) = established();
    let source = |_, _| data.clone();
    let mut e = Responder::default();
    let mut rng = ScriptedRandom::new([]);
    let d = peer_query(question("_light._tcp.local.", 12));
    e.receive(&d, true, &mut p, &source, 3000, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 3019).unwrap().is_none());
    let b = e.poll(&p, &source, 3020).unwrap().unwrap();
    assert_eq!(b.destination, "[ff02::fb]:5353".parse().unwrap());
    assert_eq!(b.messages[0].answers[0].kind, 12);
    for kind in [33, 16, 1] {
        assert!(
            b.messages
                .iter()
                .flat_map(|m| &m.additional)
                .any(|r| r.kind == kind),
            "DNS-SD additional type {kind}"
        );
    }
    e.sent(b.token, true, &mut p, 3020);
    let mut d = peer_query(question("lamp.local.", 1));
    d.message.questions[0].class = 0x8001;
    e.receive(&d, true, &mut p, &source, 3100, &mut rng)
        .unwrap();
    let b = e.poll(&p, &source, 3100).unwrap().unwrap();
    assert_eq!(b.destination, d.source);
    e.sent(b.token, true, &mut p, 3100);
    e.receive(&d, false, &mut p, &source, 4100, &mut rng)
        .unwrap();
    let b = e.poll(&p, &source, 4100).unwrap().unwrap();
    assert!(
        b.destination.ip().is_multicast(),
        "overlay source cannot receive usable unicast"
    );
    e.sent(b.token, true, &mut p, 4100);
    d.source.set_port(40000);
    e.receive(&d, true, &mut p, &source, 4200, &mut rng)
        .unwrap();
    let b = e.poll(&p, &source, 4200).unwrap().unwrap();
    assert_eq!(b.destination, d.source);
    assert_eq!(b.messages[0].id, 42);
    assert_eq!(b.messages[0].questions, d.message.questions);
    assert!(b.messages[0]
        .answers
        .iter()
        .chain(&b.messages[0].additional)
        .all(|r| r.class & 0x8000 == 0 && r.ttl <= 10));
    e.sent(b.token, true, &mut p, 4200);
    let d = peer_query(question("lamp.local.", 28));
    e.receive(&d, true, &mut p, &source, 6000, &mut rng)
        .unwrap();
    let b = e.poll(&p, &source, 6000).unwrap().unwrap();
    assert_eq!(b.messages[0].answers[0].kind, 47);
    e.sent(b.token, true, &mut p, 6000);
    let d = peer_query(question("unknown.local.", 1));
    e.receive(&d, true, &mut p, &source, 7000, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 7100).unwrap().is_none());
}
#[test]
fn s13_responder_suppresses_known_and_duplicate_answers_and_limits_multicast_frequency() {
    use snac_rs::{mdns::respond::Responder, time::ScriptedRandom};
    let (mut p, data) = established();
    let source = |_, _| data.clone();
    let mut e = Responder::default();
    let mut rng = ScriptedRandom::new([]);
    let mut d = peer_query(question("_light._tcp.local.", 12));
    d.message.answers.push(data[1].clone());
    d.message.answers[0].ttl = 60;
    e.receive(&d, true, &mut p, &source, 3000, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 3120).unwrap().is_none());
    d.message.answers[0].ttl = 59;
    e.receive(&d, true, &mut p, &source, 4000, &mut rng)
        .unwrap();
    let mut answer = peer_query(question("irrelevant.local.", 1));
    answer.message = response(vec![data[1].clone()]);
    e.receive(&answer, true, &mut p, &source, 4010, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 4020).unwrap().is_none());
    let d = peer_query(question("lamp.local.", 1));
    e.receive(&d, true, &mut p, &source, 5000, &mut rng)
        .unwrap();
    let b = e.poll(&p, &source, 5000).unwrap().unwrap();
    e.sent(b.token, true, &mut p, 5000);
    e.receive(&d, true, &mut p, &source, 5100, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 5999).unwrap().is_none());
    let b = e.poll(&p, &source, 6000).unwrap().unwrap();
    e.sent(b.token, true, &mut p, 6000);
    let mut probe = d;
    probe
        .message
        .authority
        .push(a_record("lamp.local.", 99, 120, true));
    e.receive(&probe, true, &mut p, &source, 6100, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 6249).unwrap().is_none());
    assert!(
        e.poll(&p, &source, 6250).unwrap().is_some(),
        "probe defense has 250 ms exception"
    );
}
#[test]
fn s13_truncated_known_answer_continuations_are_source_scoped_and_expire_under_flood() {
    use snac_rs::{mdns::respond::Responder, time::ScriptedRandom};
    let (mut p, data) = established();
    let source = |_, _| data.clone();
    let mut e = Responder::default();
    let mut rng = ScriptedRandom::new([]);
    let mut d = peer_query(question("_light._tcp.local.", 12));
    d.message.flags = 0x200;
    e.receive(&d, true, &mut p, &source, 3000, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 3399).unwrap().is_none());
    let mut continuation = peer_query(question("unused.local.", 1));
    continuation.message.questions.clear();
    continuation.message.answers.push(data[1].clone());
    continuation.source = "[fe80::3]:5353".parse().unwrap();
    e.receive(&continuation, true, &mut p, &source, 3300, &mut rng)
        .unwrap();
    assert!(
        e.poll(&p, &source, 3400).unwrap().is_some(),
        "different sender cannot suppress this query"
    );
    continuation.source = d.source;
    e.receive(&continuation, true, &mut p, &source, 3450, &mut rng)
        .unwrap();
    assert!(e.poll(&p, &source, 3500).unwrap().is_none());
    for i in 0..128 {
        let mut d = d.clone();
        d.source = format!("[fe80::{:x}]:5353", i + 2).parse().unwrap();
        e.receive(&d, true, &mut p, &source, 4000, &mut rng)
            .unwrap();
    }
    assert_eq!(e.counts().0, 128);
    let mut extra = d.clone();
    extra.source = "[fe80::ffff]:5353".parse().unwrap();
    assert!(e
        .receive(&extra, true, &mut p, &source, 4000, &mut rng)
        .is_err());
    assert!(e.counts().1 <= 4096 && e.counts().2 <= 4 * 1024 * 1024);
    let mut continuation = d;
    continuation.message.questions.clear();
    for at in [4300, 4600, 4900, 5200, 5500, 5800] {
        e.receive(&continuation, true, &mut p, &source, at, &mut rng)
            .unwrap();
    }
    e.poll(&p, &source, 6000).unwrap();
    assert_eq!(
        e.counts().0,
        0,
        "no unbounded retention from an unfinished known-answer stream"
    );
}
#[test]
fn s13_legacy_mdns_reply_encoding_uses_unicast_srv_rules() {
    let mut m = response(vec![Record {
        name: "Lamp._light._tcp.local.".parse().unwrap(),
        kind: 33,
        class: 1,
        ttl: 10,
        data: Rdata::Srv {
            priority: 0,
            weight: 0,
            port: 1234,
            target: "lamp.local.".parse().unwrap(),
        },
    }]);
    m.questions.push(question("lamp.local.", 1));
    let b = encode(
        "[fe80::1]:5353".parse().unwrap(),
        "[fe80::2]:40000".parse().unwrap(),
        &m,
    )
    .unwrap();
    Message::parse(&b[48..], Context::Unicast).unwrap();
}
