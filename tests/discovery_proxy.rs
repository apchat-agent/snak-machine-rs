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
