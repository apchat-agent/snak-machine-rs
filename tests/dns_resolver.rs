use snac_rs::dns::{
    resolver::{Action, Client, Resolver, UpstreamQuery},
    wire::{Context, Message, Question, Rdata, Record, TcpFrames},
};
use snac_rs::time::ScriptedRandom;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    time::Duration,
};
fn query(name: &str, kind: u16, id: u16) -> Vec<u8> {
    let mut m = Message::new(id, 0x100);
    m.questions.push(Question {
        name: name.parse().unwrap(),
        kind,
        class: 1,
    });
    m.encode().unwrap()
}
fn client(n: u16) -> Client {
    Client::udp(format!("[fd00::{n:x}]:50000").parse().unwrap())
}
fn setup() -> (Resolver, ScriptedRandom) {
    let mut r = Resolver::new(true);
    r.set_upstreams(&["127.0.0.1:5300".parse().unwrap()])
        .unwrap();
    (r, ScriptedRandom::new(0..10000))
}
fn upstream(actions: Vec<Action>) -> UpstreamQuery {
    assert_eq!(actions.len(), 1);
    match actions.into_iter().next().unwrap() {
        Action::Upstream(q) => q,
        _ => panic!("expected upstream query"),
    }
}
fn reply(actions: Vec<Action>) -> Vec<u8> {
    assert_eq!(actions.len(), 1);
    match actions.into_iter().next().unwrap() {
        Action::Reply { bytes, .. } => bytes,
        _ => panic!("expected client reply"),
    }
}
fn response(q: &UpstreamQuery, rcode: u16, kind: Option<u16>) -> Vec<u8> {
    let mut m = Message::parse(&q.bytes, Context::Unicast).unwrap();
    m.flags = 0x81a0 | rcode;
    if let Some(kind) = kind {
        m.answers.push(Record {
            name: m.questions[0].name.clone(),
            kind,
            class: 1,
            ttl: 60,
            data: if kind == 1 {
                Rdata::A([192, 0, 2, 9])
            } else {
                Rdata::Aaaa([42; 16])
            },
        });
    }
    m.encode().unwrap()
}
fn receive(
    r: &mut Resolver,
    q: &UpstreamQuery,
    b: &[u8],
    now: u64,
    rng: &mut ScriptedRandom,
) -> Vec<Action> {
    r.receive(q.exchange, q.server, q.source_port, q.tcp, b, now, rng)
        .unwrap()
}
#[test]
fn s09_forwarded_udp_and_tc_retry_use_real_loopback_bytes() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let tcp = TcpListener::bind(server.local_addr().unwrap()).unwrap();
    let (mut r, mut rng) = setup();
    r.set_upstreams(&[server.local_addr().unwrap()]).unwrap();
    let q = upstream(
        r.submit(client(1), &query("example.test.", 1, 0x1234), 0, &mut rng)
            .unwrap(),
    );
    assert_ne!(&q.bytes[..2], &[0x12, 0x34]);
    assert!((49152..=65535).contains(&q.source_port));
    let wire = UdpSocket::bind("127.0.0.1:0").unwrap();
    wire.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    wire.send_to(&q.bytes, q.server).unwrap();
    let mut buf = [0; 4096];
    let (n, peer) = server.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], q.bytes);
    let mut truncated = response(&q, 0, None);
    truncated[2] |= 2;
    server.send_to(&truncated, peer).unwrap();
    let (n, from) = wire.recv_from(&mut buf).unwrap();
    let qt = upstream(
        r.receive(
            q.exchange,
            from,
            q.source_port,
            false,
            &buf[..n],
            10,
            &mut rng,
        )
        .unwrap(),
    );
    assert!(qt.tcp);
    let mut c = TcpStream::connect(qt.server).unwrap();
    let (mut s, _) = tcp.accept().unwrap();
    c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let frame = TcpFrames::frame(&qt.bytes).unwrap();
    c.write_all(&frame).unwrap();
    let mut bytes = vec![0; frame.len()];
    s.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, frame);
    let answer = response(&qt, 0, Some(1));
    let f = TcpFrames::frame(&answer).unwrap();
    s.write_all(&f[..3]).unwrap();
    s.write_all(&f[3..]).unwrap();
    let mut bytes = vec![0; f.len()];
    c.read_exact(&mut bytes).unwrap();
    let mut frames = TcpFrames::new(65535).unwrap();
    frames.input(&bytes).unwrap();
    let b = reply(receive(&mut r, &qt, &frames.pop().unwrap(), 20, &mut rng));
    let m = Message::parse(&b, Context::Unicast).unwrap();
    assert_eq!(m.id, 0x1234);
    assert_eq!(m.flags & 0x20, 0);
    assert_eq!(m.answers[0].data, Rdata::A([192, 0, 2, 9]));
}
#[test]
fn s09_empty_aaaa_adds_a_except_nxdomain_or_configured_override() {
    for rcode in [0, 2, 3, 5] {
        for enabled in [true, false] {
            let (mut r, mut rng) = setup();
            r.set_additional_a(enabled);
            let q = upstream(
                r.submit(client(1), &query("v4.test.", 28, 9), 0, &mut rng)
                    .unwrap(),
            );
            let first = response(&q, rcode, None);
            let a = receive(&mut r, &q, &first, 1, &mut rng);
            let result = if enabled && rcode != 3 {
                let aq = upstream(a);
                assert_eq!(
                    Message::parse(&aq.bytes, Context::Unicast)
                        .unwrap()
                        .questions[0]
                        .kind,
                    1
                );
                receive(&mut r, &aq, &response(&aq, 0, Some(1)), 2, &mut rng)
            } else {
                a
            };
            let m = Message::parse(&reply(result), Context::Unicast).unwrap();
            assert_eq!(m.flags & 15, rcode);
            assert_eq!(m.id, 9);
            assert!(m.answers.iter().all(|r| r.kind != 28));
            assert_eq!(
                m.additional.iter().filter(|r| r.kind == 1).count(),
                usize::from(enabled && rcode != 3)
            );
        }
    }
}
#[test]
fn s09_canonical_a_deduplication_and_cname_loop_budget() {
    let (mut r, mut rng) = setup();
    let q = upstream(
        r.submit(client(1), &query("alias.test.", 28, 7), 0, &mut rng)
            .unwrap(),
    );
    let mut b = Message::parse(&response(&q, 0, None), Context::Unicast).unwrap();
    b.answers.push(Record {
        name: "alias.test.".parse().unwrap(),
        kind: 5,
        class: 1,
        ttl: 30,
        data: Rdata::Name("target.test.".parse().unwrap()),
    });
    b.additional.push(Record {
        name: "target.test.".parse().unwrap(),
        kind: 1,
        class: 1,
        ttl: 20,
        data: Rdata::A([192, 0, 2, 9]),
    });
    let a = upstream(receive(&mut r, &q, &b.encode().unwrap(), 1, &mut rng));
    assert_eq!(
        Message::parse(&a.bytes, Context::Unicast)
            .unwrap()
            .questions[0]
            .name,
        "target.test.".parse().unwrap()
    );
    let m = Message::parse(
        &reply(receive(&mut r, &a, &response(&a, 0, Some(1)), 2, &mut rng)),
        Context::Unicast,
    )
    .unwrap();
    assert_eq!(m.answers, b.answers);
    assert_eq!(m.additional.len(), 1);
    for count in [16, 17] {
        let (mut r, mut rng) = setup();
        let q = upstream(
            r.submit(client(1), &query("n0.test.", 28, 7), 0, &mut rng)
                .unwrap(),
        );
        let mut b = Message::parse(&response(&q, 0, None), Context::Unicast).unwrap();
        for n in 0..count {
            b.answers.push(Record {
                name: format!("n{n}.test.").parse().unwrap(),
                kind: 5,
                class: 1,
                ttl: 30,
                data: Rdata::Name(format!("n{}.test.", n + 1).parse().unwrap()),
            });
        }
        let actions = receive(&mut r, &q, &b.encode().unwrap(), 1, &mut rng);
        assert_eq!(matches!(actions[0], Action::Upstream(_)), count == 16);
    }
    let (mut r, mut rng) = setup();
    let q = upstream(
        r.submit(client(1), &query("loop.test.", 28, 7), 0, &mut rng)
            .unwrap(),
    );
    let mut b = Message::parse(&response(&q, 0, None), Context::Unicast).unwrap();
    b.answers.push(Record {
        name: "loop.test.".parse().unwrap(),
        kind: 5,
        class: 1,
        ttl: 30,
        data: Rdata::Name("loop.test.".parse().unwrap()),
    });
    assert!(matches!(
        receive(&mut r, &q, &b.encode().unwrap(), 1, &mut rng)[0],
        Action::Reply { .. }
    ));
}
#[test]
fn s09_rejects_mismatched_hostile_and_stale_replies() {
    let (mut r, mut rng) = setup();
    let q = upstream(
        r.submit(client(1), &query("safe.test.", 1, 3), 0, &mut rng)
            .unwrap(),
    );
    let good = response(&q, 0, Some(1));
    for end in 0..good.len() {
        assert!(r
            .receive(
                q.exchange,
                q.server,
                q.source_port,
                q.tcp,
                &good[..end],
                1,
                &mut rng
            )
            .unwrap()
            .is_empty());
    }
    for which in 0..6 {
        let mut b = good.clone();
        let mut server = q.server;
        let mut port = q.source_port;
        let mut exchange = q.exchange;
        let mut tcp = q.tcp;
        match which {
            0 => b[0] ^= 1,
            1 => b[13] ^= 1,
            2 => server.set_port(server.port() + 1),
            3 => port -= 1,
            4 => exchange += 1,
            _ => tcp = !tcp,
        };
        assert!(r
            .receive(exchange, server, port, tcp, &b, 2, &mut rng)
            .unwrap()
            .is_empty());
    }
    assert_eq!(r.pending_count(), 1);
    assert_eq!(receive(&mut r, &q, &good, 3, &mut rng).len(), 1);
    assert!(receive(&mut r, &q, &good, 4, &mut rng).is_empty());
}
#[test]
fn s09_positive_negative_cache_ttl_and_timeout_are_bounded() {
    let (mut r, mut rng) = setup();
    let bytes = query("cached.test.", 1, 1);
    let q = upstream(r.submit(client(1), &bytes, 0, &mut rng).unwrap());
    receive(&mut r, &q, &response(&q, 0, Some(1)), 1, &mut rng);
    let m = Message::parse(
        &reply(r.submit(client(1), &bytes, 5001, &mut rng).unwrap()),
        Context::Unicast,
    )
    .unwrap();
    assert_eq!(m.answers[0].ttl, 55);
    let q = upstream(r.submit(client(1), &bytes, 60001, &mut rng).unwrap());
    let mut m = Message::parse(&response(&q, 3, None), Context::Unicast).unwrap();
    m.authority.push(Record {
        name: "test.".parse().unwrap(),
        kind: 6,
        class: 1,
        ttl: 30,
        data: Rdata::Soa {
            mname: "ns.test.".parse().unwrap(),
            rname: "mail.test.".parse().unwrap(),
            serial: 1,
            refresh: 10,
            retry: 10,
            expire: 100,
            minimum: 10,
        },
    });
    receive(&mut r, &q, &m.encode().unwrap(), 60002, &mut rng);
    let m = Message::parse(
        &reply(r.submit(client(1), &bytes, 65002, &mut rng).unwrap()),
        Context::Unicast,
    )
    .unwrap();
    assert_eq!(m.flags & 15, 3);
    assert!(m.authority[0].ttl <= 5);
    let q = upstream(r.submit(client(1), &bytes, 70002, &mut rng).unwrap());
    assert_eq!(q.server, "127.0.0.1:5300".parse::<SocketAddr>().unwrap());
    let out = r.tick(80003, &mut rng).unwrap();
    let m = Message::parse(&reply(out), Context::Unicast).unwrap();
    assert_eq!(m.flags & 15, 2);
    assert_eq!(r.pending_count(), 0);
    let q = upstream(
        r.submit(client(1), &query("v4timeout.test.", 28, 1), 90000, &mut rng)
            .unwrap(),
    );
    let aq = upstream(receive(&mut r, &q, &response(&q, 5, None), 90001, &mut rng));
    assert!(!aq.bytes.is_empty());
    let m = Message::parse(&reply(r.tick(100002, &mut rng).unwrap()), Context::Unicast).unwrap();
    assert_eq!(m.flags & 15, 5);
}

#[test]
fn s09_pending_waiter_upstream_and_byte_caps_are_atomic() {
    let (mut r, mut rng) = setup();
    let eps: Vec<_> = (1..=8)
        .map(|n| format!("192.0.2.{n}:53").parse().unwrap())
        .collect();
    r.set_upstreams(&eps).unwrap();
    let mut ninth = eps.clone();
    ninth.push("192.0.2.9:53".parse().unwrap());
    assert!(r.set_upstreams(&ninth).is_err());
    assert_eq!(r.upstreams(), eps);
    for n in 0..128 {
        r.submit(
            client((n / 4 + 1) as u16),
            &query(&format!("p{n}.test."), 1, 1),
            0,
            &mut rng,
        )
        .unwrap();
    }
    assert_eq!(r.pending_count(), 128);
    assert!(r
        .submit(client(100), &query("overflow.test.", 1, 1), 0, &mut rng)
        .is_err());
    for n in 0..128 {
        assert!(r
            .submit(
                client((n / 4 + 1) as u16),
                &query(&format!("p{n}.test."), 1, 2),
                0,
                &mut rng
            )
            .unwrap()
            .is_empty());
    }
    assert_eq!(r.waiter_count(), 256);
    assert!(r
        .submit(client(101), &query("p0.test.", 1, 3), 0, &mut rng)
        .is_err());
    assert!(r.pending_bytes() <= 4 * 1024 * 1024);
    r.tick(10000, &mut rng).unwrap();
    assert_eq!(r.waiter_count(), 0);
    let (mut r, mut rng) = setup();
    for n in 0..8 {
        r.submit(
            client(1),
            &query(&format!("client{n}.test."), 1, 1),
            0,
            &mut rng,
        )
        .unwrap();
    }
    assert!(r
        .submit(client(1), &query("clientoverflow.test.", 1, 1), 0, &mut rng)
        .is_err());
    let mut filled = 0;
    for n in 1..128 {
        let mut m =
            Message::parse(&query(&format!("large{n}.test."), 1, 1), Context::Unicast).unwrap();
        m.additional.push(Record {
            name: ".".parse().unwrap(),
            kind: 41,
            class: 4096,
            ttl: 0,
            data: Rdata::Opt(vec![(65000, vec![9; 60000])]),
        });
        if r.submit(client((n + 2) as u16), &m.encode().unwrap(), 0, &mut rng)
            .is_err()
        {
            break;
        }
        filled += 1;
    }
    assert!(filled > 0 && filled < 100);
    assert!(r.pending_bytes() <= 4 * 1024 * 1024);
}
#[test]
fn s09_cache_entry_and_byte_caps_evict_without_touching_live_queries() {
    let (mut r, mut rng) = setup();
    for n in 0..1025 {
        let q = upstream(
            r.submit(
                client((n % 16 + 1) as u16),
                &query(&format!("cache{n}.test."), 1, 1),
                n * 50,
                &mut rng,
            )
            .unwrap(),
        );
        receive(&mut r, &q, &response(&q, 0, Some(1)), n * 50, &mut rng);
    }
    assert_eq!(r.cache_sets(), 1024);
    assert!(r.cache_bytes() <= 4 * 1024 * 1024);
    assert!(matches!(
        r.submit(client(1), &query("cache0.test.", 1, 1), 51251, &mut rng)
            .unwrap()[0],
        Action::Upstream(_)
    ));
    let (mut r, mut rng) = setup();
    for n in 0..110 {
        let q = upstream(
            r.submit(
                Client::tcp(client((n % 16 + 1) as u16).address, n as usize),
                &query(&format!("blob{n}.test."), 16, 1),
                n,
                &mut rng,
            )
            .unwrap(),
        );
        let mut m = Message::parse(&response(&q, 0, None), Context::Unicast).unwrap();
        m.answers.push(Record {
            name: m.questions[0].name.clone(),
            kind: 16,
            class: 1,
            ttl: 60,
            data: Rdata::Txt(vec![vec![9; 250]; 170]),
        });
        receive(&mut r, &q, &m.encode().unwrap(), n, &mut rng);
    }
    assert!(r.cache_sets() < 110);
    assert!(r.cache_bytes() <= 4 * 1024 * 1024);
    r.tick(60110, &mut rng).unwrap();
    assert_eq!(r.cache_sets(), 0);
}
#[test]
fn s09_edns_extended_rcode_and_bad_version() {
    let (mut r, mut rng) = setup();
    let mut m = Message::parse(&query("version.test.", 1, 10), Context::Unicast).unwrap();
    m.additional.push(Record {
        name: ".".parse().unwrap(),
        kind: 41,
        class: 1232,
        ttl: 0x10000,
        data: Rdata::Opt(vec![]),
    });
    let b = reply(
        r.submit(client(1), &m.encode().unwrap(), 0, &mut rng)
            .unwrap(),
    );
    let m = Message::parse(&b, Context::Unicast).unwrap();
    assert_eq!(m.flags & 15, 0);
    assert_eq!(m.additional[0].ttl >> 24, 1);
    assert_eq!((m.additional[0].ttl >> 16) & 255, 0);
    let q = upstream(
        r.submit(client(1), &query("extended.test.", 28, 1), 1, &mut rng)
            .unwrap(),
    );
    let mut m = Message::parse(&response(&q, 3, None), Context::Unicast).unwrap();
    m.additional.push(Record {
        name: ".".parse().unwrap(),
        kind: 41,
        class: 1232,
        ttl: 1 << 24,
        data: Rdata::Opt(vec![]),
    });
    let a = upstream(receive(&mut r, &q, &m.encode().unwrap(), 2, &mut rng));
    let m = Message::parse(
        &reply(receive(&mut r, &a, &response(&a, 0, Some(1)), 3, &mut rng)),
        Context::Unicast,
    )
    .unwrap();
    assert_eq!(
        m.additional.iter().find(|r| r.kind == 41).unwrap().ttl >> 24,
        1
    );
    assert_eq!(m.flags & 15, 3);
    assert!(m.additional.iter().any(|r| r.kind == 1));
}
#[test]
fn s09_rate_table_is_bounded_and_expires() {
    let (mut r, mut rng) = setup();
    for n in 1..=32 {
        let q = upstream(
            r.submit(client(n), &query("rate.test.", 1, n), 0, &mut rng)
                .unwrap(),
        );
        receive(&mut r, &q, &response(&q, 5, None), 0, &mut rng);
    }
    assert_eq!(r.rate_entries(), 32);
    assert!(r
        .submit(client(33), &query("rate.test.", 1, 1), 0, &mut rng)
        .is_err());
    for _ in 1..32 {
        let q = upstream(
            r.submit(client(1), &query("rate.test.", 1, 1), 0, &mut rng)
                .unwrap(),
        );
        receive(&mut r, &q, &response(&q, 5, None), 0, &mut rng);
    }
    assert!(r
        .submit(client(1), &query("rate.test.", 1, 1), 0, &mut rng)
        .is_err());
    r.tick(1000, &mut rng).unwrap();
    assert_eq!(r.rate_entries(), 0);
    assert!(r
        .submit(client(33), &query("rate.test.", 1, 1), 1000, &mut rng)
        .is_ok());
}

#[test]
fn s09_augmented_negative_cache_expires_at_shortest_record_ttl() {
    let (mut r, mut rng) = setup();
    let bytes = query("short.test.", 28, 1);
    let q = upstream(r.submit(client(1), &bytes, 0, &mut rng).unwrap());
    let mut m = Message::parse(&response(&q, 0, None), Context::Unicast).unwrap();
    m.authority.push(Record {
        name: "test.".parse().unwrap(),
        kind: 6,
        class: 1,
        ttl: 60,
        data: Rdata::Soa {
            mname: "ns.test.".parse().unwrap(),
            rname: "mail.test.".parse().unwrap(),
            serial: 1,
            refresh: 10,
            retry: 10,
            expire: 100,
            minimum: 60,
        },
    });
    let aq = upstream(receive(&mut r, &q, &m.encode().unwrap(), 1, &mut rng));
    let mut a = Message::parse(&response(&aq, 0, Some(1)), Context::Unicast).unwrap();
    a.answers[0].ttl = 2;
    receive(&mut r, &aq, &a.encode().unwrap(), 2, &mut rng);
    assert!(
        matches!(
            r.submit(client(1), &bytes, 3002, &mut rng).unwrap()[0],
            Action::Upstream(_)
        ),
        "expired Additional data cannot outlive its own TTL"
    );
}
#[test]
fn s09_udp_size_fallback_and_opaque_dnssec_preservation() {
    let (mut r, mut rng) = setup();
    let q = upstream(
        r.submit(client(1), &query("large.test.", 16, 44), 0, &mut rng)
            .unwrap(),
    );
    let mut m = Message::parse(&response(&q, 0, None), Context::Unicast).unwrap();
    m.answers.push(Record {
        name: m.questions[0].name.clone(),
        kind: 16,
        class: 1,
        ttl: 60,
        data: Rdata::Txt(vec![vec![42; 250]; 4]),
    });
    let b = reply(receive(&mut r, &q, &m.encode().unwrap(), 1, &mut rng));
    assert!(b.len() <= 512);
    assert_ne!(
        Message::parse(&b, Context::Unicast).unwrap().flags & 0x200,
        0
    );
    let q = upstream(
        r.submit(client(1), &query("opaque.test.", 1, 45), 2, &mut rng)
            .unwrap(),
    );
    let mut wire = response(&q, 0, Some(1));
    wire[11] = 1;
    wire.extend([0xc0, 12, 0xfd, 0xe8, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
    let b = reply(receive(&mut r, &q, &wire, 3, &mut rng));
    assert_eq!(&b[4..], &wire[4..]);
    let cached = reply(
        r.submit(client(1), &query("opaque.test.", 1, 46), 1003, &mut rng)
            .unwrap(),
    );
    assert_eq!(&cached[cached.len() - 2..], &[0xc0, 12]);
    assert_eq!(cached.len(), wire.len());
}
#[test]
fn s09_tcp_disconnect_cancels_only_its_waiters() {
    let (mut r, mut rng) = setup();
    let q = query("shared.test.", 1, 1);
    r.submit(Client::tcp(client(1).address, 11), &q, 0, &mut rng)
        .unwrap();
    r.submit(Client::tcp(client(2).address, 12), &q, 0, &mut rng)
        .unwrap();
    assert_eq!(r.waiter_count(), 2);
    r.cancel_connection(11);
    assert_eq!(r.waiter_count(), 1);
    assert_eq!(r.pending_count(), 1);
    r.cancel_connection(12);
    assert_eq!(r.pending_count(), 0);
}

#[test]
fn s09_local_service_arpa_policy_preserves_dnssec_ds_exception() {
    for name in [
        "service.arpa.",
        "unknown.service.arpa.",
        "default.service.arpa.",
    ] {
        for kind in [1, 28, 2, 43] {
            for do_bit in [false, true] {
                let (mut r, mut rng) = setup();
                let mut m = Message::parse(&query(name, kind, 1), Context::Unicast).unwrap();
                if do_bit {
                    m.additional.push(Record {
                        name: ".".parse().unwrap(),
                        kind: 41,
                        class: 1232,
                        ttl: 0x8000,
                        data: Rdata::Opt(vec![]),
                    });
                }
                let out = r
                    .submit(client(1), &m.encode().unwrap(), 0, &mut rng)
                    .unwrap();
                assert_eq!(
                    matches!(out[0], Action::Upstream(_)),
                    kind == 43 && do_bit,
                    "{name} {kind} {do_bit}"
                );
            }
        }
    }
    let (mut r, mut rng) = setup();
    let zones: Vec<_> = (0..8)
        .map(|n| format!("owned{n}.test.").parse().unwrap())
        .collect();
    r.set_local_zones(&zones).unwrap();
    let mut extra = zones.clone();
    extra.push("overflow.test.".parse().unwrap());
    assert!(r.set_local_zones(&extra).is_err());
    let m = Message::parse(
        &reply(
            r.submit(client(1), &query("host.owned0.test.", 1, 1), 0, &mut rng)
                .unwrap(),
        ),
        Context::Unicast,
    )
    .unwrap();
    assert_eq!(m.flags & 15, 3);
    assert!(r
        .submit(client(1), &query("unowned.test.", 1, 1), 0, &mut rng)
        .unwrap()
        .iter()
        .any(|a| matches!(a, Action::Upstream(_))));
}
#[test]
fn s09_authoritative_answers_share_canonical_a_and_size_rules() {
    let (r, _) = setup();
    let query = query("alias.owned.test.", 28, 80);
    let mut m = Message::parse(&query, Context::Unicast).unwrap();
    m.flags = 0x8580;
    m.answers.push(Record {
        name: m.questions[0].name.clone(),
        kind: 5,
        class: 1,
        ttl: 10,
        data: Rdata::Name("target.owned.test.".parse().unwrap()),
    });
    let mut calls = 0;
    let a = r
        .answer_local(client(1), &query, &m.encode().unwrap(), |q| {
            calls += 1;
            assert_eq!(q.name, "target.owned.test.".parse().unwrap());
            assert_eq!(q.kind, 1);
            let mut a = Message::new(0, 0x8580);
            a.questions.push(q.clone());
            a.answers.push(Record {
                name: q.name.clone(),
                kind: 1,
                class: 1,
                ttl: 10,
                data: Rdata::A([192, 0, 2, 9]),
            });
            a.encode()
        })
        .unwrap();
    let result = Message::parse(&reply(vec![a]), Context::Unicast).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(result.answers, m.answers);
    assert_eq!(result.additional[0].data, Rdata::A([192, 0, 2, 9]));
    assert_ne!(result.flags & 0x400, 0);
    assert_eq!(result.id, 80);
}

#[test]
fn s09_cname_to_local_zone_never_leaks_an_a_lookup_and_large_queries_use_tcp() {
    let (mut r, mut rng) = setup();
    let q = upstream(
        r.submit(client(1), &query("alias.public.test.", 28, 1), 0, &mut rng)
            .unwrap(),
    );
    let mut m = Message::parse(&response(&q, 0, None), Context::Unicast).unwrap();
    m.answers.push(Record {
        name: m.questions[0].name.clone(),
        kind: 5,
        class: 1,
        ttl: 60,
        data: Rdata::Name("host.default.service.arpa.".parse().unwrap()),
    });
    assert!(matches!(
        receive(&mut r, &q, &m.encode().unwrap(), 1, &mut rng)[0],
        Action::Reply { .. }
    ));
    let mut m = Message::parse(&query("largequery.test.", 1, 1), Context::Unicast).unwrap();
    m.additional.push(Record {
        name: ".".parse().unwrap(),
        kind: 41,
        class: 4096,
        ttl: 0,
        data: Rdata::Opt(vec![(65000, vec![42; 5000])]),
    });
    let q = upstream(
        r.submit(
            Client::tcp(client(1).address, 1),
            &m.encode().unwrap(),
            2,
            &mut rng,
        )
        .unwrap(),
    );
    assert!(q.tcp);
}
