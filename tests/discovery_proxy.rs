use snac_rs::dns::wire::{Context, Message, Name, Question, Rdata, Record};
fn name(s: &str) -> Name {
    s.parse().unwrap()
}
fn q(s: &str, kind: u16) -> Question {
    Question {
        name: name(s),
        kind,
        class: 1,
    }
}
fn record(s: &str, kind: u16, data: Rdata) -> Record {
    Record {
        name: name(s),
        kind,
        class: 0x8001,
        ttl: 4500,
        data,
    }
}
fn zone() -> snac_rs::discovery_proxy::Zone {
    snac_rs::discovery_proxy::Zone::new(
        name("Floor 1.example."),
        Some(name("floor-1.example.")),
        &[name("2.0.192.in-addr.arpa.")],
        &[name("proxy.example.net.")],
        name("admin.example.net."),
    )
    .unwrap()
}
#[test]
fn s15_rich_host_and_reverse_queries_map_without_text_transcoding() {
    use snac_rs::discovery_proxy::Reachability;
    let zone = zone();
    let reach = Reachability::default();
    let query = zone
        .question(&q("My Printer._ipp._tcp.Floor 1.example.", 33))
        .unwrap()
        .unwrap();
    assert_eq!(query.multicast, q("My Printer._ipp._tcp.local.", 33));
    let source = record(
        "My Printer._ipp._tcp.local.",
        33,
        Rdata::Srv {
            priority: 0,
            weight: 0,
            port: 631,
            target: name("prnt.local."),
        },
    );
    let mapped = zone
        .rewrite(&source, &query, false, &reach)
        .unwrap()
        .unwrap();
    assert_eq!(mapped.name, query.original.name);
    assert_eq!(mapped.class, 1);
    assert_eq!(mapped.ttl, 10);
    assert!(matches!(mapped.data,Rdata::Srv{target,..} if target==name("prnt.floor-1.example.")));
    let host = record("prnt.local.", 1, Rdata::A([192, 0, 2, 8]));
    assert_eq!(
        zone.rewrite(&host, &query, true, &reach)
            .unwrap()
            .unwrap()
            .name,
        name("prnt.floor-1.example.")
    );
    let alias = zone
        .question(&q("alias.floor-1.example.", 1))
        .unwrap()
        .unwrap();
    let mapped = zone
        .rewrite(
            &record("alias.local.", 5, Rdata::Name(name("prnt.local."))),
            &alias,
            false,
            &reach,
        )
        .unwrap()
        .unwrap();
    assert_eq!(mapped.data, Rdata::Name(name("prnt.floor-1.example.")));
    let reverse = zone
        .question(&q("8.2.0.192.in-addr.arpa.", 12))
        .unwrap()
        .unwrap();
    assert_eq!(reverse.multicast, reverse.original);
    let mapped = zone
        .rewrite(
            &record(
                "8.2.0.192.in-addr.arpa.",
                12,
                Rdata::Name(name("prnt.local.")),
            ),
            &reverse,
            false,
            &reach,
        )
        .unwrap()
        .unwrap();
    assert_eq!(mapped.name, reverse.original.name);
    assert_eq!(mapped.data, Rdata::Name(name("prnt.floor-1.example.")));
    assert!(zone.question(&q("host.elsewhere.", 1)).unwrap().is_none());
    let mut binary = q("instance._ipp._tcp.Floor 1.example.", 16);
    let mut labels = binary.name.labels().to_vec();
    labels[0] = vec![0, 255, b'.'];
    binary.name = Name::from_labels(labels).unwrap();
    let translated = zone.question(&binary).unwrap().unwrap();
    assert_eq!(translated.multicast.name.labels()[0], vec![0, 255, b'.']);
    let mut txt = record(
        "instance._ipp._tcp.local.",
        16,
        Rdata::Txt(vec![vec![0, 255], b"adminurl=http://prnt.local/".to_vec()]),
    );
    txt.name = translated.multicast.name.clone();
    assert_eq!(
        zone.rewrite(&txt, &translated, false, &reach)
            .unwrap()
            .unwrap()
            .data,
        txt.data
    );
    let external = record(
        "My Printer._ipp._tcp.local.",
        33,
        Rdata::Srv {
            priority: 0,
            weight: 0,
            port: 631,
            target: name("host.example.net."),
        },
    );
    assert_eq!(
        zone.rewrite(&external, &query, false, &reach)
            .unwrap()
            .unwrap()
            .data,
        external.data
    );
}
#[test]
fn s15_discovery_address_filter_uses_actual_reachability_and_explicit_override() {
    use snac_rs::discovery_proxy::Reachability;
    let z = zone();
    let mapped = z
        .question(&q("host.floor-1.example.", 255))
        .unwrap()
        .unwrap();
    let v4 = record("host.local.", 1, Rdata::A([169, 254, 3, 4]));
    let v6 = record(
        "host.local.",
        28,
        Rdata::Aaaa("fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets()),
    );
    let r = Reachability::default();
    for value in [&v4, &v6] {
        assert!(z.rewrite(value, &mapped, false, &r).unwrap().is_none());
    }
    let r = Reachability {
        ipv4_link_local: true,
        ..r
    };
    assert!(z.rewrite(&v4, &mapped, false, &r).unwrap().is_some());
    assert!(z.rewrite(&v6, &mapped, false, &r).unwrap().is_none());
    let r = Reachability {
        include_unusable: true,
        ..r
    };
    assert!(z.rewrite(&v6, &mapped, false, &r).unwrap().is_some());
    let private = record("host.local.", 1, Rdata::A([192, 168, 3, 4]));
    let ula = record(
        "host.local.",
        28,
        Rdata::Aaaa("fd11::1".parse::<std::net::Ipv6Addr>().unwrap().octets()),
    );
    let r = Reachability {
        different_private_realm: true,
        different_ula_realm: true,
        ..Reachability::default()
    };
    for value in [&private, &ula] {
        assert!(z.rewrite(value, &mapped, false, &r).unwrap().is_none());
    }
    assert!(z
        .rewrite(&private, &mapped, false, &Reachability::default())
        .unwrap()
        .is_some());
    for bytes in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
        assert!(z
            .rewrite(
                &record("host.local.", 1, Rdata::A(bytes)),
                &mapped,
                false,
                &Reachability::default()
            )
            .unwrap()
            .is_none());
    }
}
#[test]
fn s15_administrative_records_are_immediate_authoritative_and_scoped_outside_proxy_zones() {
    let z = zone();
    let a = z.metadata(&q("Floor 1.example.", 6)).unwrap().unwrap();
    assert_eq!(a.flags & 0x840f, 0x8400);
    assert_eq!(a.answers.len(), 1);
    assert!(
        matches!(&a.answers[0].data,Rdata::Soa{mname,rname,serial:0,refresh:7200,retry:3600,expire:86400,minimum:10} if *mname==name("proxy.example.net.") && *rname==name("admin.example.net."))
    );
    let ns = z.metadata(&q("floor-1.example.", 2)).unwrap().unwrap();
    assert_eq!(ns.answers[0].data, Rdata::Name(name("proxy.example.net.")));
    for query in [
        q("child.Floor 1.example.", 6),
        q("child.Floor 1.example.", 2),
        q("child.Floor 1.example.", 43),
        q("_dns-update._udp.Floor 1.example.", 33),
        q("_dns-llq._tcp.Floor 1.example.", 33),
        q("_dns-push-tls._tcp.Floor 1.example.", 33),
        q("b._dns-sd._udp.2.0.192.in-addr.arpa.", 12),
    ] {
        let a = z.metadata(&query).unwrap().unwrap();
        assert_eq!(a.flags & 15, 0);
        assert!(a.answers.is_empty());
        assert!(a.authority.iter().any(|r| r.kind == 6 && r.ttl == 10));
        assert_eq!(
            Message::parse(&a.encode().unwrap(), Context::Unicast)
                .unwrap()
                .questions,
            vec![query]
        );
    }
    assert!(z
        .metadata(&q("_ipp._tcp.Floor 1.example.", 12))
        .unwrap()
        .is_none());
}
#[test]
fn s15_zone_configuration_bounds_and_name_overflow_fail_atomically() {
    use snac_rs::discovery_proxy::{Reachability, Zone};
    let ns: Vec<_> = (0..8).map(|i| name(&format!("ns{i}.elsewhere."))).collect();
    let reverse: Vec<_> = (0..64)
        .map(|i| name(&format!("{i}.2.0.192.in-addr.arpa.")))
        .collect();
    assert!(Zone::new(
        name("browse.example."),
        None,
        &reverse,
        &ns,
        name("admin.example.")
    )
    .is_ok());
    let mut too_many = ns.clone();
    too_many.push(name("extra.elsewhere."));
    assert!(Zone::new(
        name("browse.example."),
        None,
        &reverse,
        &too_many,
        name("admin.example.")
    )
    .is_err());
    let mut too_many = reverse.clone();
    too_many.push(name("64.2.0.192.in-addr.arpa."));
    assert!(Zone::new(
        name("browse.example."),
        None,
        &too_many,
        &ns,
        name("admin.example.")
    )
    .is_err());
    for bad_ns in [
        "ns.browse.example.",
        "ns.hosts.example.",
        "ns.2.0.192.in-addr.arpa.",
    ] {
        assert!(Zone::new(
            name("browse.example."),
            Some(name("hosts.example.")),
            &[name("2.0.192.in-addr.arpa.")],
            &[name(bad_ns)],
            name("admin.example.")
        )
        .is_err());
    }
    assert!(Zone::new(Name::root(), None, &[], &ns, name("admin.example.")).is_err());
    assert!(Zone::new(
        name("browse.example."),
        Some(name("not LDH.example.")),
        &[],
        &ns,
        name("admin.example.")
    )
    .is_err());
    assert!(Zone::new(
        name("browse.example."),
        None,
        &[name("not-reverse.example.")],
        &ns,
        name("admin.example.")
    )
    .is_err());
    let z = zone();
    let query = z
        .question(&q("name.Floor 1.example.", 16))
        .unwrap()
        .unwrap();
    let huge = Name::from_labels(vec![
        vec![b'x'; 63],
        vec![b'y'; 63],
        vec![b'z'; 63],
        vec![b'w'; 54],
        b"local".to_vec(),
    ])
    .unwrap();
    let mut r = record("unused.local.", 16, Rdata::Txt(vec![b"v".to_vec()]));
    r.name = huge;
    assert!(z
        .rewrite(&r, &query, false, &Reachability::default())
        .is_err());
    let mut bad = q("name.Floor 1.example.", 1);
    bad.class = 0;
    assert!(z.question(&bad).is_err());
}

fn bitmap(types: impl IntoIterator<Item = u16>) -> Vec<u8> {
    let mut windows = std::collections::BTreeMap::<u8, Vec<u8>>::new();
    for kind in types {
        let bytes = windows.entry((kind / 256) as u8).or_default();
        let at = usize::from(kind % 256 / 8);
        bytes.resize(bytes.len().max(at + 1), 0);
        bytes[at] |= 0x80 >> (kind % 8);
    }
    windows
        .into_iter()
        .flat_map(|(w, b)| [vec![w, b.len() as u8], b].concat())
        .collect()
}
#[test]
fn s15_nsec_and_nsec3_convert_multicast_type_information_to_single_name_proofs() {
    use snac_rs::discovery_proxy::Reachability;
    let z = zone();
    let input = vec![
        record("host.local.", 1, Rdata::A([192, 0, 2, 1])),
        record(
            "host.local.",
            47,
            Rdata::Nsec {
                next: name("unrelated.local."),
                bitmap: vec![0, 4, 0x40, 0, 0, 8, 1, 6, 0, 0, 0, 0, 0, 8],
            },
        ),
    ];
    for kind in [47, 50] {
        let query = z
            .question(&q("host.floor-1.example.", kind))
            .unwrap()
            .unwrap();
        assert_eq!(query.multicast.kind, 255);
        let proof = z.denial(&query, &input, &Reachability::default()).unwrap();
        assert_eq!(proof.kind, kind);
        assert_eq!(proof.class, 1);
        assert_eq!(proof.ttl, 10);
        if kind == 47 {
            assert_eq!(proof.name, name("host.floor-1.example."));
            let Rdata::Nsec { next, bitmap } = &proof.data else {
                panic!()
            };
            assert_eq!(next.labels()[0], vec![0]);
            assert_eq!(&next.labels()[1..], proof.name.labels());
            assert_eq!(
                *bitmap,
                vec![0, 6, 0x40, 0, 0, 8, 0, 1, 1, 6, 0, 0, 0, 0, 0, 8]
            );
        } else {
            assert_eq!(
                proof.name,
                name("6V8EDKI4PAD3T7DBJGI1FFS6VERDD7BS.floor-1.example.")
            );
            let Rdata::Bytes(bytes) = &proof.data else {
                panic!()
            };
            assert_eq!(&bytes[..6], &[1, 0, 0, 0, 0, 20]);
            assert_eq!(
                &bytes[6..26],
                &[
                    0x37, 0xd0, 0xe6, 0xd2, 0x44, 0xca, 0x9a, 0x3e, 0x9d, 0xab, 0x9c, 0x24, 0x17,
                    0xbf, 0x86, 0xfb, 0xb6, 0xd6, 0x9d, 0x7d
                ]
            );
            assert_eq!(&bytes[26..], &[0, 4, 0x40, 0, 0, 8, 1, 6, 0, 0, 0, 0, 0, 8]);
        }
        let mut m = Message::new(0, 0x8400);
        m.answers.push(proof);
        let bytes = m.encode().unwrap();
        assert!(Message::parse(&bytes, Context::Unicast).is_ok());
        for end in 0..bytes.len() {
            assert!(Message::parse(&bytes[..end], Context::Unicast).is_err());
        }
    }
}
#[test]
fn s15_multicast_synthesized_nsec_does_not_claim_a_persisted_nsec_type() {
    use snac_rs::{mdns::publish::Publisher, time::ScriptedRandom};
    let mut p = Publisher::default();
    let mut rng = ScriptedRandom::new([]);
    let records = vec![record("host.local.", 1, Rdata::A([192, 0, 2, 1]))];
    p.replace(1, &[], &records, 0, &mut rng).unwrap();
    let b = p.poll(&|_, _| records.clone(), 0).unwrap().unwrap();
    let data = &b
        .messages
        .iter()
        .flat_map(|m| &m.authority)
        .find(|r| r.kind == 47)
        .unwrap()
        .data;
    assert!(
        matches!(data,Rdata::Nsec{bitmap,..} if *bitmap==vec![0,1,0x40]),
        "RFC 6762 6.1 forbids the NSEC bit in synthesized multicast NSEC"
    );
}
#[test]
fn s15_nsec_next_name_handles_maximum_names_without_covering_another_valid_name() {
    use snac_rs::discovery_proxy::Reachability;
    let z = snac_rs::discovery_proxy::Zone::new(
        name("example."),
        None,
        &[],
        &[name("ns.elsewhere.")],
        name("admin.elsewhere."),
    )
    .unwrap();
    for length in [253, 254, 255] {
        let remaining = length - (64 * 3 + 9);
        let n = Name::from_labels(vec![
            vec![b'@'; remaining - 1],
            vec![b'x'; 63],
            vec![b'y'; 63],
            vec![b'z'; 63],
            b"example".to_vec(),
        ])
        .unwrap();
        assert_eq!(n.canonical().len(), length);
        let query = z
            .question(&Question {
                name: n.clone(),
                kind: 47,
                class: 1,
            })
            .unwrap()
            .unwrap();
        let r = z.denial(&query, &[], &Reachability::default()).unwrap();
        let Rdata::Nsec { next, .. } = r.data else {
            panic!()
        };
        assert!(next.canonical().len() <= 255);
        if length == 253 {
            assert_eq!(next.labels()[0], vec![0]);
        }
        if length == 254 {
            assert_eq!(next.labels()[0].last(), Some(&0));
        }
        if length == 255 {
            assert_eq!(next.labels()[0].last(), Some(&b'['));
        }
        let canonical = |n: &Name| {
            n.labels()
                .iter()
                .rev()
                .map(|l| l.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>())
                .collect::<Vec<_>>()
        };
        assert!(canonical(&next) > canonical(&n));
    }
}
#[test]
fn s15_denial_input_rejects_hostile_bitmaps_and_bounds_type_and_record_work() {
    use snac_rs::discovery_proxy::Reachability;
    let z = zone();
    let query = z
        .question(&q("host.floor-1.example.", 47))
        .unwrap()
        .unwrap();
    for bad in [
        vec![0],
        vec![0, 0],
        vec![0, 33],
        vec![0, 2, 0x80],
        vec![0, 1, 0],
        vec![1, 1, 1, 0, 1, 1],
        vec![0, 1, 1, 0, 1, 1],
    ] {
        let input = vec![record(
            "host.local.",
            47,
            Rdata::Nsec {
                next: name("host.local."),
                bitmap: bad,
            },
        )];
        assert!(z.denial(&query, &input, &Reachability::default()).is_err());
    }
    let make = |end| {
        vec![record(
            "host.local.",
            47,
            Rdata::Nsec {
                next: name("host.local."),
                bitmap: bitmap(512..end),
            },
        )]
    };
    assert!(z
        .denial(&query, &make(1535), &Reachability::default())
        .is_ok());
    assert!(z
        .denial(&query, &make(1536), &Reachability::default())
        .is_err());
    let a = record("host.local.", 1, Rdata::A([192, 0, 2, 1]));
    assert!(z
        .denial(&query, &vec![a.clone(); 4096], &Reachability::default())
        .is_ok());
    assert!(z
        .denial(&query, &vec![a; 4097], &Reachability::default())
        .is_err());
}

fn cached(querier: &mut snac_rs::mdns::query::Querier, records: Vec<Record>, now: u64) {
    let mut m = Message::new(0, 0x8400);
    m.answers = records;
    querier
        .cache
        .receive(&m, now, &mut snac_rs::time::ScriptedRandom::new([]))
        .unwrap();
}
#[test]
fn s15_proxy_queries_on_demand_and_completes_first_positive_with_dns_sd_additions() {
    use snac_rs::{discovery_proxy::Proxy, mdns::query::Querier, time::ScriptedRandom};
    let mut p = Proxy::new(zone());
    let mut m = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let id = p.start(q("_ipp._tcp.Floor 1.example.", 12), 0).unwrap();
    assert!(p.poll(&mut m, 0, &mut rng).unwrap().is_empty());
    assert_eq!(m.counts().0, 1);
    assert!(m.poll(19).unwrap().is_none());
    let batch = m.poll(20).unwrap().unwrap();
    assert_eq!(
        batch.messages[0].questions[0].name,
        name("_ipp._tcp.local.")
    );
    m.sent(batch.id, true, 20);
    cached(
        &mut m,
        vec![
            Record {
                class: 1,
                ..record(
                    "_ipp._tcp.local.",
                    12,
                    Rdata::Name(name("My Printer._ipp._tcp.local.")),
                )
            },
            record(
                "My Printer._ipp._tcp.local.",
                33,
                Rdata::Srv {
                    priority: 0,
                    weight: 0,
                    port: 631,
                    target: name("prnt.local."),
                },
            ),
            record(
                "My Printer._ipp._tcp.local.",
                16,
                Rdata::Txt(vec![vec![0, 255, b'=']]),
            ),
            record("prnt.local.", 1, Rdata::A([192, 0, 2, 1])),
        ],
        21,
    );
    let mut done = p.poll(&mut m, 21, &mut rng).unwrap();
    assert_eq!(done.len(), 1);
    let done = done.pop().unwrap();
    assert_eq!(done.id, id);
    assert_eq!(
        done.answer.answers[0].name,
        name("_ipp._tcp.Floor 1.example.")
    );
    assert_eq!(done.answer.flags & 0x840f, 0x8400);
    assert!(done
        .answer
        .additional
        .iter()
        .any(|r| r.data == Rdata::Txt(vec![vec![0, 255, b'=']])));
    assert!(done
        .answer
        .additional
        .iter()
        .any(|r| r.name == name("prnt.floor-1.example.") && r.kind == 1));
    assert!(done
        .answer
        .answers
        .iter()
        .chain(&done.answer.additional)
        .all(|r| r.ttl <= 10 && r.class == 1));
    assert_eq!(p.counts().0, 0);
    assert_eq!(m.counts().0, 0);
    p.start(q("_ipp._tcp.Floor 1.example.", 12), 22).unwrap();
    assert_eq!(p.poll(&mut m, 22, &mut rng).unwrap().len(), 1);
    assert_eq!(m.counts().0, 0, "cache hit emits no multicast question");
}
#[test]
fn s15_proxy_negative_timeout_is_six_seconds_and_nsec_completes_earlier() {
    use snac_rs::{discovery_proxy::Proxy, mdns::query::Querier, time::ScriptedRandom};
    let mut p = Proxy::new(zone());
    let mut m = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let id = p.start(q("missing.floor-1.example.", 33), 0).unwrap();
    p.poll(&mut m, 0, &mut rng).unwrap();
    assert!(p.poll(&mut m, 5999, &mut rng).unwrap().is_empty());
    let done = p.poll(&mut m, 6000, &mut rng).unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].id, id);
    assert!(done[0].answer.answers.is_empty());
    assert_eq!(done[0].answer.flags & 15, 0);
    assert!(done[0]
        .answer
        .authority
        .iter()
        .any(|r| matches!(r.data, Rdata::Soa { minimum: 10, .. }) && r.ttl == 10));
    assert_eq!(m.counts().0, 0);
    p.start(q("host.floor-1.example.", 28), 7000).unwrap();
    p.poll(&mut m, 7000, &mut rng).unwrap();
    cached(
        &mut m,
        vec![record(
            "host.local.",
            47,
            Rdata::Nsec {
                next: name("host.local."),
                bitmap: vec![0, 1, 0x40],
            },
        )],
        7020,
    );
    let done = p.poll(&mut m, 7020, &mut rng).unwrap();
    assert_eq!(done.len(), 1);
    assert!(done[0].answer.answers.is_empty());
    assert_eq!(m.counts().0, 0);
    p.start(q("host.floor-1.example.", 47), 7021).unwrap();
    let done = p.poll(&mut m, 7021, &mut rng).unwrap();
    assert_eq!(done[0].answer.answers[0].kind, 47);
}
#[test]
fn s15_proxy_jobs_coalesce_bound_and_cancel_without_leaving_multicast_queries() {
    use snac_rs::{discovery_proxy::Proxy, mdns::query::Querier, time::ScriptedRandom};
    let mut p = Proxy::new(zone());
    let mut m = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let mut ids = vec![];
    for i in 0..128 {
        let question = q(&format!("host{i}.floor-1.example."), 1);
        let id = p.start(question.clone(), 0).unwrap();
        assert_eq!(p.start(question, 1).unwrap(), id);
        ids.push(id);
    }
    assert_eq!(p.counts().0, 128);
    assert!(p.counts().1 <= 4 * 1024 * 1024);
    assert!(p.start(q("overflow.floor-1.example.", 1), 0).is_err());
    p.poll(&mut m, 0, &mut rng).unwrap();
    assert_eq!(m.counts().0, 128);
    for id in ids {
        p.cancel(id);
    }
    assert!(p.poll(&mut m, 1, &mut rng).unwrap().is_empty());
    assert_eq!(p.counts(), (0, 0));
    assert_eq!(m.counts().0, 0);
    assert!(p.start(q("external.example.net.", 1), 2).is_err());
    assert_eq!(p.counts().0, 0);
}
#[test]
fn s15_proxy_suppresses_services_with_only_unusable_addresses_until_translation_is_ready() {
    use snac_rs::{
        discovery_proxy::{Proxy, Reachability},
        mdns::query::Querier,
        time::ScriptedRandom,
    };
    let mut p = Proxy::new(zone());
    let mut m = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    cached(
        &mut m,
        vec![
            Record {
                class: 1,
                ..record(
                    "_ipp._tcp.local.",
                    12,
                    Rdata::Name(name("Printer._ipp._tcp.local.")),
                )
            },
            record(
                "Printer._ipp._tcp.local.",
                33,
                Rdata::Srv {
                    priority: 0,
                    weight: 0,
                    port: 631,
                    target: name("prnt.local."),
                },
            ),
            record("prnt.local.", 1, Rdata::A([169, 254, 3, 4])),
        ],
        0,
    );
    p.start(q("_ipp._tcp.Floor 1.example.", 12), 0).unwrap();
    let done = p.poll(&mut m, 0, &mut rng).unwrap();
    assert!(done[0].answer.answers.is_empty());
    p.set_reachability(Reachability {
        ipv4_link_local: true,
        ..Reachability::default()
    });
    p.start(q("_ipp._tcp.Floor 1.example.", 12), 1).unwrap();
    let done = p.poll(&mut m, 1, &mut rng).unwrap();
    assert_eq!(done[0].answer.answers.len(), 1);
    assert!(done[0]
        .answer
        .additional
        .iter()
        .any(|r| r.data == Rdata::A([169, 254, 3, 4])));
    assert_eq!(m.counts().0, 0);
}

fn dns_query(id: u16, query: Question) -> Vec<u8> {
    let mut m = Message::new(id, 0x100);
    m.questions.push(query);
    m.encode().unwrap()
}
fn response(action: snac_rs::dns::resolver::Action) -> (snac_rs::dns::resolver::Client, Message) {
    let snac_rs::dns::resolver::Action::Reply { client, bytes } = action else {
        panic!("expected resolver reply")
    };
    (client, Message::parse(&bytes, Context::Unicast).unwrap())
}
#[test]
fn s15_resolver_discovery_coalesces_clients_and_preserves_reply_endpoints() {
    use snac_rs::{
        dns::resolver::{Client, Resolver},
        mdns::Engine,
        time::ScriptedRandom,
    };
    let mut r = Resolver::new(true);
    r.enable_discovery(zone()).unwrap();
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let mut udp = Client::udp("[fd11::1]:12000".parse().unwrap());
    udp.local = Some("fd11::53".parse().unwrap());
    let tcp = Client::tcp("[fd11::2]:12001".parse().unwrap(), 7);
    for (id, client) in [(1, udp.clone()), (2, tcp.clone())] {
        assert!(r
            .submit(
                client,
                &dns_query(id, q("host.floor-1.example.", 1)),
                0,
                &mut rng
            )
            .unwrap()
            .is_empty());
    }
    assert_eq!((r.pending_count(), r.waiter_count()), (1, 2));
    assert!(r.connection_pending(7));
    assert!(r
        .poll_discovery(&mut engine, 0, &mut rng)
        .unwrap()
        .is_empty());
    assert_eq!(engine.querier.counts().0, 1);
    cached(
        &mut engine.querier,
        vec![record("host.local.", 1, Rdata::A([192, 0, 2, 8]))],
        1,
    );
    let answers = r.poll_discovery(&mut engine, 1, &mut rng).unwrap();
    assert_eq!(answers.len(), 2);
    for (action, (client, id)) in answers.into_iter().zip([(udp, 1), (tcp, 2)]) {
        let (actual, answer) = response(action);
        assert_eq!(actual, client);
        assert_eq!(answer.id, id);
        assert_eq!(answer.flags & 0x848f, 0x8480);
        assert_eq!(answer.answers[0].ttl, 10);
    }
    assert_eq!(
        (
            r.pending_count(),
            r.waiter_count(),
            engine.querier.counts().0
        ),
        (0, 0, 0)
    );
    assert_eq!(r.cache_sets(), 0, "learned mDNS stays in its own cache");
}
#[test]
fn s15_resolver_discovery_adds_a_after_negative_aaaa_and_can_disable_it() {
    use snac_rs::{
        dns::resolver::{Client, Resolver},
        mdns::Engine,
        time::ScriptedRandom,
    };
    let mut r = Resolver::new(true);
    r.enable_discovery(zone()).unwrap();
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    cached(
        &mut engine.querier,
        vec![
            record("host.local.", 1, Rdata::A([192, 0, 2, 8])),
            record(
                "host.local.",
                47,
                Rdata::Nsec {
                    next: name("host.local."),
                    bitmap: vec![0, 1, 0x40],
                },
            ),
        ],
        0,
    );
    let client = Client::udp("[fd11::1]:12000".parse().unwrap());
    let query = dns_query(81, q("host.floor-1.example.", 28));
    r.submit(client.clone(), &query, 0, &mut rng).unwrap();
    let mut out = r.poll_discovery(&mut engine, 0, &mut rng).unwrap();
    out.extend(r.poll_discovery(&mut engine, 0, &mut rng).unwrap());
    assert_eq!(out.len(), 1);
    let (_, answer) = response(out.pop().unwrap());
    assert_eq!(answer.questions, [q("host.floor-1.example.", 28)]);
    assert!(answer.answers.is_empty());
    assert_eq!(answer.flags & 15, 0);
    assert_eq!(answer.additional.len(), 1);
    assert_eq!(answer.additional[0].data, Rdata::A([192, 0, 2, 8]));
    assert_eq!(answer.additional[0].name, name("host.floor-1.example."));
    r.set_additional_a(false);
    r.submit(client, &query, 1, &mut rng).unwrap();
    let (_, answer) = response(
        r.poll_discovery(&mut engine, 1, &mut rng)
            .unwrap()
            .pop()
            .unwrap(),
    );
    assert!(answer.additional.is_empty());
}
#[test]
fn s15_resolver_shares_transaction_and_source_limits_between_forwarding_and_discovery() {
    use snac_rs::{
        dns::resolver::{Client, Resolver},
        time::ScriptedRandom,
    };
    let mut r = Resolver::new(true);
    r.enable_discovery(zone()).unwrap();
    r.set_upstreams(&["192.0.2.53:53".parse().unwrap()])
        .unwrap();
    let mut rng = ScriptedRandom::new([]);
    for i in 0..128 {
        let client = Client::tcp(format!("[fd11::{}]:12000", i / 8 + 1).parse().unwrap(), i);
        let suffix = if i % 2 == 0 {
            "floor-1.example."
        } else {
            "outside.example."
        };
        r.submit(
            client,
            &dns_query(i as u16, q(&format!("host{i}.{suffix}"), 1)),
            0,
            &mut rng,
        )
        .unwrap();
    }
    assert_eq!((r.pending_count(), r.waiter_count()), (128, 128));
    assert!(r.pending_bytes() <= 4 * 1024 * 1024);
    for suffix in ["floor-1.example.", "outside.example."] {
        let err = r
            .submit(
                Client::udp("[fd11::99]:12000".parse().unwrap()),
                &dns_query(129, q(&format!("extra.{suffix}"), 1)),
                0,
                &mut rng,
            )
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }
    r.cancel_connection(0);
    assert_eq!(r.pending_count(), 127);
    let err = r
        .submit(
            Client::udp("[fd11::2]:12000".parse().unwrap()),
            &dns_query(130, q("extra.floor-1.example.", 1)),
            0,
            &mut rng,
        )
        .unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::WouldBlock,
        "mixed per-source eight-waiter bound"
    );
}
#[test]
fn s15_resolver_disconnect_cancels_multicast_only_after_last_waiter() {
    use snac_rs::{
        dns::resolver::{Client, Resolver},
        mdns::Engine,
        time::ScriptedRandom,
    };
    let mut r = Resolver::new(true);
    r.enable_discovery(zone()).unwrap();
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    for id in [1, 2] {
        r.submit(
            Client::tcp("[fd11::1]:12000".parse().unwrap(), id),
            &dns_query(id as u16, q("host.floor-1.example.", 1)),
            0,
            &mut rng,
        )
        .unwrap();
    }
    r.poll_discovery(&mut engine, 0, &mut rng).unwrap();
    r.cancel_connection(1);
    assert_eq!((r.pending_count(), r.waiter_count()), (1, 1));
    r.poll_discovery(&mut engine, 1, &mut rng).unwrap();
    assert_eq!(engine.querier.counts().0, 1);
    r.cancel_connection(2);
    assert_eq!(r.pending_count(), 0);
    r.poll_discovery(&mut engine, 2, &mut rng).unwrap();
    assert_eq!(engine.querier.counts().0, 0);
    assert!(!r.connection_pending(2));
}

#[test]
fn s15_proxy_caps_output_and_completion_work_and_survives_unrepresentable_peer_names() {
    use snac_rs::{discovery_proxy::Proxy, mdns::query::Querier, time::ScriptedRandom};
    let mut p = Proxy::new(zone());
    let mut m = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    let records: Vec<_> = (0..513)
        .map(|i| Record {
            class: 1,
            ..record(
                "_many._tcp.local.",
                12,
                Rdata::Name(name(&format!("instance{i}._many._tcp.local."))),
            )
        })
        .collect();
    p.start(q("_many._tcp.Floor 1.example.", 12), 0).unwrap();
    let result = p
        .poll_with_local(
            &mut m,
            &|query| {
                if query.kind == 12 {
                    records.clone()
                } else {
                    vec![]
                }
            },
            0,
            &mut rng,
        )
        .unwrap();
    assert_eq!(result[0].answer.answers.len(), 512);
    assert_ne!(result[0].answer.flags & 0x200, 0);
    for i in 0..17 {
        p.start(q(&format!("host{i}.floor-1.example."), 1), 1)
            .unwrap();
    }
    let local = |query: &Question| {
        vec![Record {
            name: query.name.clone(),
            ..record("unused.local.", 1, Rdata::A([192, 0, 2, 8]))
        }]
    };
    assert_eq!(
        p.poll_with_local(&mut m, &local, 1, &mut rng)
            .unwrap()
            .len(),
        16
    );
    assert_eq!(p.next_deadline(1), Some(1));
    assert_eq!(
        p.poll_with_local(&mut m, &local, 1, &mut rng)
            .unwrap()
            .len(),
        1
    );
    let mut long = vec![
        vec![b'x'; 63],
        vec![b'y'; 63],
        vec![b'z'; 63],
        vec![b'a'; 55],
        b"local".to_vec(),
    ];
    let target = Name::from_labels(long.clone()).unwrap();
    assert_eq!(target.canonical().len(), 255);
    long[3].pop();
    p.start(q("_bad._tcp.Floor 1.example.", 12), 2).unwrap();
    p.poll(&mut m, 2, &mut rng).unwrap();
    assert_eq!(m.counts().0, 1);
    cached(
        &mut m,
        vec![Record {
            class: 1,
            ..record("_bad._tcp.local.", 12, Rdata::Name(target))
        }],
        3,
    );
    let result = p
        .poll(&mut m, 3, &mut rng)
        .expect("peer name expansion must not tear down the service");
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].answer.flags & 15, 2);
    assert_eq!((p.counts().0, m.counts().0), (0, 0));
}
#[test]
fn s15_apex_nsec_and_nsec3_answer_from_owned_zone_metadata_without_multicast() {
    use snac_rs::{discovery_proxy::Proxy, mdns::query::Querier, time::ScriptedRandom};
    let mut p = Proxy::new(zone());
    let mut m = Querier::default();
    let mut rng = ScriptedRandom::new([]);
    for kind in [47, 50] {
        p.start(q("Floor 1.example.", kind), 0).unwrap();
        let a = p.poll(&mut m, 0, &mut rng).unwrap().pop().unwrap().answer;
        assert_eq!(a.answers.len(), 1);
        assert_eq!(a.answers[0].kind, kind);
        let bitmap = match &a.answers[0].data {
            Rdata::Nsec { bitmap, .. } => bitmap.as_slice(),
            Rdata::Bytes(b) => &b[26..],
            _ => panic!("proof type"),
        };
        assert_eq!(bitmap[0], 0);
        assert_eq!(bitmap[2] & 0x22, 0x22, "NS and SOA are present at the apex");
        assert_eq!(m.counts().0, 0);
    }
}

#[test]
fn s15_additional_a_crosses_discovery_and_forwarding_views_without_leaking_local_queries() {
    use snac_rs::{
        dns::resolver::{Action, Client, Resolver},
        mdns::Engine,
        time::ScriptedRandom,
    };
    for outward in [false, true] {
        let mut r = Resolver::new(true);
        r.enable_discovery(zone()).unwrap();
        r.set_upstreams(&["192.0.2.53:53".parse().unwrap()])
            .unwrap();
        let mut e = Engine::default();
        let mut rng = ScriptedRandom::new([]);
        let client = Client::udp("[fd11::1]:40000".parse().unwrap());
        if outward {
            cached(
                &mut e.querier,
                vec![record(
                    "alias.local.",
                    5,
                    Rdata::Name(name("external.example.net.")),
                )],
                0,
            );
            r.submit(
                client,
                &dns_query(103, q("alias.floor-1.example.", 28)),
                0,
                &mut rng,
            )
            .unwrap();
            let actions = r.poll_discovery(&mut e, 0, &mut rng).unwrap();
            let Action::Upstream(up) = &actions[0] else {
                panic!("external canonical A must be attempted");
            };
            let mut reply = Message::parse(&up.bytes, Context::Unicast).unwrap();
            assert_eq!(reply.questions, [q("external.example.net.", 1)]);
            reply.flags = 0x8180;
            reply.answers.push(Record {
                class: 1,
                ..record("external.example.net.", 1, Rdata::A([192, 0, 2, 9]))
            });
            let result = r
                .receive(
                    up.exchange,
                    up.server,
                    up.source_port,
                    up.tcp,
                    &reply.encode().unwrap(),
                    1,
                    &mut rng,
                )
                .unwrap();
            let (_, a) = response(result.into_iter().next().unwrap());
            assert_eq!(a.additional[0].data, Rdata::A([192, 0, 2, 9]));
            assert_eq!(a.additional[0].name, name("external.example.net."));
        } else {
            let actions = r
                .submit(
                    client,
                    &dns_query(104, q("external.example.net.", 28)),
                    0,
                    &mut rng,
                )
                .unwrap();
            let Action::Upstream(up) = &actions[0] else {
                panic!("forward initial query");
            };
            let mut reply = Message::parse(&up.bytes, Context::Unicast).unwrap();
            reply.flags = 0x8180;
            reply.answers.push(Record {
                class: 1,
                ..record(
                    "external.example.net.",
                    5,
                    Rdata::Name(name("host.floor-1.example.")),
                )
            });
            let result = r
                .receive(
                    up.exchange,
                    up.server,
                    up.source_port,
                    up.tcp,
                    &reply.encode().unwrap(),
                    1,
                    &mut rng,
                )
                .unwrap();
            assert!(
                result.is_empty(),
                "canonical local A must enter discovery, never upstream"
            );
            assert_eq!(r.queries().count(), 0);
            cached(
                &mut e.querier,
                vec![record("host.local.", 1, Rdata::A([192, 0, 2, 10]))],
                2,
            );
            let (_, a) = response(
                r.poll_discovery(&mut e, 2, &mut rng)
                    .unwrap()
                    .pop()
                    .unwrap(),
            );
            assert_eq!(a.additional[0].name, name("host.floor-1.example."));
            assert_eq!(a.additional[0].data, Rdata::A([192, 0, 2, 10]));
        }
        assert_eq!(r.pending_count(), 0);
        assert_eq!(
            r.cache_sets(),
            0,
            "derived proxy results remain outside the forwarding cache"
        );
    }
}
#[test]
fn s15_discovery_ds_with_do_forwards_only_the_dnssec_exception_and_cycles_terminate() {
    use snac_rs::{
        dns::resolver::{Action, Client, Resolver},
        mdns::Engine,
        time::ScriptedRandom,
    };
    let mut r = Resolver::new(true);
    r.enable_discovery(
        snac_rs::discovery_proxy::Zone::new(
            name("default.service.arpa."),
            None,
            &[],
            &[name("proxy.home.arpa.")],
            name("admin.home.arpa."),
        )
        .unwrap(),
    )
    .unwrap();
    r.set_upstreams(&["192.0.2.53:53".parse().unwrap()])
        .unwrap();
    let mut e = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let client = Client::udp("[fd11::1]:40000".parse().unwrap());
    for do_bit in [false, true] {
        let mut query = Message::parse(
            &dns_query(105, q("default.service.arpa.", 43)),
            Context::Unicast,
        )
        .unwrap();
        if do_bit {
            query.additional.push(Record {
                name: Name::root(),
                kind: 41,
                class: 4096,
                ttl: 0x8000,
                data: Rdata::Opt(vec![]),
            });
        }
        let result = r
            .submit(client.clone(), &query.encode().unwrap(), 0, &mut rng)
            .unwrap();
        if do_bit {
            assert!(matches!(result[0], Action::Upstream(_)));
        } else {
            assert!(result.is_empty());
            let (_, a) = response(
                r.poll_discovery(&mut e, 0, &mut rng)
                    .unwrap()
                    .pop()
                    .unwrap(),
            );
            assert_eq!(a.flags & 15, 0);
            assert_eq!(a.authority[0].kind, 6);
        }
    }
    cached(
        &mut e.querier,
        vec![record("loop.local.", 5, Rdata::Name(name("loop.local.")))],
        0,
    );
    r.submit(
        client,
        &dns_query(106, q("loop.default.service.arpa.", 28)),
        1,
        &mut rng,
    )
    .unwrap();
    let (_, a) = response(
        r.poll_discovery(&mut e, 1, &mut rng)
            .unwrap()
            .pop()
            .unwrap(),
    );
    assert!(a.additional.is_empty());
    assert_eq!(e.querier.counts().0, 0);
}
