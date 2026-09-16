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
