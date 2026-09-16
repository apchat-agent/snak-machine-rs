mod common;
use snac_rs::{
    dns::{
        resolver::{Action, Client, Resolver},
        wire::{Context, Message, Name, Question, Rdata},
    },
    persist::{Identity, MemoryStore},
    time::ScriptedRandom,
};
fn name(s: &str) -> Name {
    s.parse().unwrap()
}
fn identity() -> Identity {
    Identity::load_or_create(
        &mut MemoryStore::default(),
        "inventory",
        &mut ScriptedRandom::new([77]),
    )
    .unwrap()
}
fn query(n: &Name, kind: u16) -> Vec<u8> {
    let mut m = Message::new(101, 0x100);
    m.questions.push(Question {
        name: n.clone(),
        kind,
        class: 1,
    });
    m.encode().unwrap()
}
fn client() -> Client {
    Client::udp("[::1]:40000".parse().unwrap())
}
fn reply(actions: Vec<Action>) -> Message {
    let Action::Reply { bytes, .. } = &actions[0] else {
        panic!("expected reply")
    };
    Message::parse(bytes, Context::Unicast).unwrap()
}
fn in_zone(label: &str, zone: &Name) -> Name {
    let mut labels = vec![label.as_bytes().to_vec()];
    labels.extend_from_slice(zone.labels());
    Name::from_labels(labels).unwrap()
}
#[test]
fn s16_default_zones_use_persisted_site_identity_and_validate_proxy_scope() {
    use snac_rs::dns::inventory::Zones;
    let id = identity();
    let zones = Zones::for_identity(&id);
    assert_eq!(zones.discovery, name("default.service.arpa."));
    assert_eq!(zones.registrar.labels()[0], b"srp");
    assert_eq!(&zones.registrar.labels()[1..], zones.hostname.labels());
    assert!(zones.hostname.labels()[0].starts_with(b"snac-"));
    assert_eq!(&zones.hostname.labels()[1..], name("home.arpa.").labels());
    assert_eq!(
        Zones::for_identity(&Identity::decode(&id.encode().unwrap()).unwrap()),
        zones
    );
    let mut r = Resolver::new(true);
    let mut bad = zones.clone();
    bad.hostname = name("ns.default.service.arpa.");
    assert!(r.configure_zones(bad).is_err());
    let mut bad = zones.clone();
    bad.registrar = Name::root();
    assert!(r.configure_zones(bad).is_err());
    r.configure_zones(zones).unwrap();
}
#[test]
fn s16_verified_update_alias_maps_to_canonical_zone_and_query_keeps_discovery_role() {
    use snac_rs::dns::inventory::Zones;
    let mut zones = Zones::for_identity(&identity());
    zones.registrar = name("registrations.example.");
    zones.discovery = name("services.example.");
    let mut r = Resolver::new(true);
    r.configure_zones(zones.clone()).unwrap();
    r.enable_srp(Box::new(MemoryStore::default()), 0, common::srp::NOW)
        .unwrap();
    let mut rng = ScriptedRandom::new([]);
    let signed = common::srp::sign(common::srp::update());
    let ack = reply(r.submit(client(), &signed, 0, &mut rng).unwrap());
    assert_eq!(ack.flags & 15, 0);
    assert_eq!(
        ack.questions[0].name,
        name("default.service.arpa."),
        "response keeps signed request zone"
    );
    let host = in_zone("host", &zones.registrar);
    assert!(r.registry().unwrap().key(&host, 0).is_some());
    assert!(r
        .registry()
        .unwrap()
        .key(&name("host.default.service.arpa."), 0)
        .is_none());
    let answer = reply(r.submit(client(), &query(&host, 28), 1, &mut rng).unwrap());
    assert_eq!(answer.answers[0].name, host);
    assert_eq!(answer.flags & 0x840f, 0x8400);
    let mut bad = signed.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        reply(r.submit(client(), &bad, 1, &mut rng).unwrap()).flags & 15,
        5
    );
    assert_eq!(r.registry().unwrap().hosts().count(), 1);
    assert_eq!(
        reply(r.submit(client(), &signed, 2, &mut rng).unwrap()).flags & 15,
        0,
        "original-wire replay remains valid"
    );
    assert!(
        r.configure_zones(zones.clone()).is_err(),
        "cannot change a live registrar's namespace"
    );
    let result = r
        .submit(
            client(),
            &query(&in_zone("host", &zones.discovery), 28),
            3,
            &mut rng,
        )
        .unwrap();
    assert!(
        result.is_empty(),
        "DP query does not alias into registrations"
    );
    assert_eq!(r.pending_count(), 1);
}
#[test]
fn s16_canonical_updates_verify_original_wire_and_map_service_rdata_without_touching_txt() {
    use snac_rs::dns::inventory::Zones;
    let zones = Zones::for_identity(&identity());
    let mut r = Resolver::new(true);
    r.configure_zones(zones.clone()).unwrap();
    r.enable_srp(Box::new(MemoryStore::default()), 0, common::srp::NOW)
        .unwrap();
    let mut rng = ScriptedRandom::new([]);
    let mut m = common::srp::update();
    for record in &mut m.authority {
        if record.kind == 16 {
            record.data = Rdata::Txt(vec![
                vec![0, 255],
                b"url=host.default.service.arpa".to_vec(),
            ]);
        }
    }
    assert_eq!(
        reply(
            r.submit(client(), &common::srp::sign(m), 0, &mut rng)
                .unwrap()
        )
        .flags
            & 15,
        0
    );
    let registry = r.registry().unwrap();
    let (service, _) = registry.services().next().unwrap();
    assert!(service.labels().ends_with(zones.registrar.labels()));
    let srv = registry.records(service, 33, 0);
    assert!(
        matches!(&srv[0].data, Rdata::Srv { target, .. } if *target == in_zone("host", &zones.registrar))
    );
    assert_eq!(
        registry.records(service, 16, 0)[0].data,
        Rdata::Txt(vec![
            vec![0, 255],
            b"url=host.default.service.arpa".to_vec()
        ])
    );
    // Independent signing in the actual canonical zone; verify before rewriting.
    let mut canonical = common::srp::update();
    let alias = name("default.service.arpa.");
    let map = |n: &mut Name| {
        if n.labels().ends_with(alias.labels()) {
            let mut labels = n.labels()[..n.labels().len() - alias.labels().len()].to_vec();
            labels.extend_from_slice(zones.registrar.labels());
            *n = Name::from_labels(labels).unwrap();
        }
    };
    map(&mut canonical.questions[0].name);
    for record in canonical
        .authority
        .iter_mut()
        .chain(&mut canonical.additional)
    {
        map(&mut record.name);
        match &mut record.data {
            Rdata::Name(n) => map(n),
            Rdata::Srv { target, .. } => map(target),
            Rdata::Sig { signer, .. } => map(signer),
            _ => {}
        }
    }
    assert_eq!(
        reply(
            r.submit(client(), &common::srp::sign(canonical), 1, &mut rng)
                .unwrap()
        )
        .flags
            & 15,
        0
    );
    assert_eq!(r.registry().unwrap().hosts().count(), 1);
    let mut e = snac_rs::mdns::Engine::default();
    r.sync_advertising(&mut e, 1, &mut rng).unwrap();
    assert_eq!(
        e.publisher.counts().0,
        1,
        "canonical namespace projects through Advertising Proxy"
    );
}

fn question(owner: &str, kind: u16) -> Question {
    Question {
        name: name(owner),
        kind,
        class: 1,
    }
}
fn prefix(labels: &[&str], zone: &Name) -> Name {
    let mut out: Vec<Vec<u8>> = labels.iter().map(|s| s.as_bytes().to_vec()).collect();
    out.extend_from_slice(zone.labels());
    Name::from_labels(out).unwrap()
}
#[test]
fn s16_inventory_enumerates_both_browsing_zones_and_one_default_registration_domain() {
    use snac_rs::dns::inventory::{Inventory, Zones};
    let zones = Zones::for_identity(&identity());
    let mut i = Inventory::new(zones.clone()).unwrap();
    let reverse = name("0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.");
    i.set_contexts(&[name("search.example."), reverse.clone()])
        .unwrap();
    for context in [
        name("local."),
        zones.discovery.clone(),
        zones.registrar.clone(),
        name("search.example."),
        reverse,
    ] {
        for label in ["b", "lb", "db", "r", "dr"] {
            let owner = prefix(&[label, "_dns-sd", "_udp"], &context);
            let answer = i
                .answer(
                    &Question {
                        name: owner,
                        kind: 12,
                        class: 1,
                    },
                    0,
                )
                .unwrap()
                .unwrap();
            let names: std::collections::BTreeSet<_> = answer
                .answers
                .iter()
                .map(|r| {
                    if let Rdata::Name(n) = &r.data {
                        n.clone()
                    } else {
                        panic!("PTR")
                    }
                })
                .collect();
            let expected = match label {
                "b" | "lb" => vec![zones.discovery.clone(), zones.registrar.clone()],
                "db" => vec![zones.discovery.clone()],
                _ => vec![zones.registrar.clone()],
            };
            assert_eq!(names, expected.into_iter().collect());
            assert_eq!(answer.flags & 0x840f, 0x8400);
        }
    }
    assert!(i
        .answer(&question("lb._dns-sd._udp.outside.example.", 12), 0)
        .unwrap()
        .is_none());
    for zone in [&zones.registrar, &zones.hostname] {
        let soa: Message = i
            .answer(
                &Question {
                    name: zone.clone(),
                    kind: 6,
                    class: 1,
                },
                0,
            )
            .unwrap()
            .unwrap();
        assert!(
            matches!(&soa.answers[0].data, Rdata::Soa { mname, rname, .. } if *mname == zones.hostname && *rname == zones.mailbox)
        );
        assert_eq!(
            i.answer(
                &Question {
                    name: zone.clone(),
                    kind: 2,
                    class: 1
                },
                0
            )
            .unwrap()
            .unwrap()
            .answers[0]
                .data,
            Rdata::Name(zones.hostname.clone())
        );
    }
}
#[test]
fn s16_registrar_discovery_uses_tcp_service_names_actual_ports_and_only_ready_addresses() {
    use snac_rs::dns::inventory::{Inventory, Zones};
    let zones = Zones::for_identity(&identity());
    let mut i = Inventory::new(zones.clone()).unwrap();
    let address: std::net::IpAddr = "fd11::53".parse().unwrap();
    for (addresses, dns, tls, expected) in [
        (vec![], Some(53), Some(853), 0),
        (vec![address], Some(1053), None, 1),
        (vec![address], Some(1053), Some(8853), 2),
    ] {
        i.set_ready(&addresses, dns, tls).unwrap();
        let mut count = 0;
        for (label, port) in [("_dnssd-srp", 1053), ("_dnssd-srp-tls", 8853)] {
            let owner = prefix(&[label, "_tcp"], &zones.registrar);
            let mut q = Question {
                name: owner,
                kind: 12,
                class: 1,
            };
            let ptr: Message = i.answer(&q, 0).unwrap().unwrap();
            if ptr.answers.is_empty() {
                continue;
            }
            count += 1;
            let Rdata::Name(instance) = &ptr.answers[0].data else {
                panic!("instance PTR")
            };
            assert!(ptr.additional.iter().any(|r| matches!(&r.data, Rdata::Srv { target, port: actual, .. } if *target==zones.hostname && *actual==port)));
            assert!(ptr.additional.iter().any(|r| r.kind == 16));
            assert!(ptr.additional.iter().any(|r| matches!(r.data, Rdata::Aaaa(a) if a == "fd11::53".parse::<std::net::Ipv6Addr>().unwrap().octets())));
            q.kind = 33;
            assert_eq!(
                i.answer(&q, 0).unwrap().unwrap().answers.len(),
                1,
                "RFC 9665 direct SRV bootstrap"
            );
            q.name = instance.clone();
            assert_eq!(i.answer(&q, 0).unwrap().unwrap().answers.len(), 1);
        }
        assert_eq!(count, expected);
    }
    let q = Question {
        name: prefix(&["_dnssd-srp", "_udp"], &zones.registrar),
        kind: 12,
        class: 1,
    };
    assert!(i.answer(&q, 0).unwrap().unwrap().answers.is_empty());
    i.set_ready(&["fd22::53".parse().unwrap()], Some(53), None)
        .unwrap();
    let host = i
        .answer(
            &Question {
                name: zones.hostname,
                kind: 28,
                class: 1,
            },
            1,
        )
        .unwrap()
        .unwrap();
    assert_eq!(host.answers.len(), 1);
    assert_eq!(
        host.answers[0].data,
        Rdata::Aaaa("fd22::53".parse::<std::net::Ipv6Addr>().unwrap().octets())
    );
}
#[test]
fn s16_inventory_context_and_address_tables_are_bounded_and_reject_expanded_name_overflow() {
    use snac_rs::dns::inventory::{Inventory, Zones};
    let zones = Zones::for_identity(&identity());
    let mut i = Inventory::new(zones.clone()).unwrap();
    let mut contexts: Vec<_> = (0..64)
        .map(|n| name(&format!("search{n}.example.")))
        .collect();
    i.set_contexts(&contexts).unwrap();
    contexts.push(name("overflow.example."));
    assert!(i.set_contexts(&contexts).is_err());
    assert!(i
        .answer(&question("lb._dns-sd._udp.search63.example.", 12), 0)
        .unwrap()
        .is_some());
    assert!(i
        .answer(&question("lb._dns-sd._udp.overflow.example.", 12), 0)
        .unwrap()
        .is_none());
    let mut addresses: Vec<std::net::IpAddr> = (1..=32)
        .map(|n| format!("fd11::{n}").parse().unwrap())
        .collect();
    i.set_ready(&addresses, Some(53), Some(853)).unwrap();
    addresses.push("fd11::99".parse().unwrap());
    assert!(i.set_ready(&addresses, Some(53), Some(853)).is_err());
    let host = i
        .answer(
            &Question {
                name: zones.hostname.clone(),
                kind: 28,
                class: 1,
            },
            0,
        )
        .unwrap()
        .unwrap();
    assert_eq!(host.answers.len(), 32);
    for address in ["::", "ff02::1", "0.0.0.0", "224.0.0.1"] {
        assert!(i
            .set_ready(&[address.parse().unwrap()], Some(53), None)
            .is_err());
    }
    assert!(i.set_ready(&addresses[..1], Some(0), None).is_err());
    let long = Name::from_labels(vec![
        vec![b'x'; 63],
        vec![b'y'; 63],
        vec![b'z'; 63],
        vec![b'a'; 61],
    ])
    .unwrap();
    assert!(i.set_contexts(std::slice::from_ref(&long)).is_err());
    let mut bad = zones;
    bad.registrar = long;
    assert!(Inventory::new(bad).is_err());
}

#[test]
fn s16_cli_configures_zones_host_mapping_reverse_zones_mailbox_and_filter_override() {
    use snac_rs::config::Config;
    let base = ["--backend", "tap", "--infra", "ail", "--stub", "stub"];
    let defaults = Config::parse(base).unwrap().unwrap();
    assert_eq!(
        defaults.dns_zones(&identity()).unwrap(),
        snac_rs::dns::inventory::Zones::for_identity(&identity())
    );
    let configured = Config::parse(base.into_iter().chain([
        "--srp-zone",
        "registered.example.",
        "--discovery-zone",
        "Floor 1.example.",
        "--discovery-host-zone",
        "floor-1.example.",
        "--discovery-reverse-zone",
        "2.0.192.in-addr.arpa.",
        "--dns-soa-rname",
        "admin.example.",
        "--discovery-include-unusable",
    ]))
    .unwrap()
    .unwrap();
    let zones = configured.dns_zones(&identity()).unwrap();
    assert_eq!(zones.registrar, name("registered.example."));
    assert_eq!(zones.discovery, name("Floor 1.example."));
    assert_eq!(zones.host, Some(name("floor-1.example.")));
    assert_eq!(zones.reverse, [name("2.0.192.in-addr.arpa.")]);
    assert_eq!(zones.mailbox, name("admin.example."));
    assert!(configured.discovery_include_unusable);
    for (key, value) in [
        ("--srp-zone", "."),
        ("--discovery-zone", "."),
        ("--discovery-host-zone", "non LDH.example."),
        ("--discovery-reverse-zone", "not-reverse.example."),
    ] {
        let config = Config::parse(base.into_iter().chain([key, value]));
        assert!(config.is_err() || config.unwrap().unwrap().dns_zones(&identity()).is_err());
    }
    let mut args: Vec<String> = base.iter().map(|s| (*s).to_owned()).collect();
    for n in 0..64 {
        args.extend([
            "--discovery-reverse-zone".to_owned(),
            format!("{n}.0.192.in-addr.arpa."),
        ]);
    }
    Config::parse(args.clone())
        .unwrap()
        .unwrap()
        .dns_zones(&identity())
        .unwrap();
    args.extend([
        "--discovery-reverse-zone".to_owned(),
        "64.0.192.in-addr.arpa.".to_owned(),
    ]);
    assert!(Config::parse(args).is_err());
}
#[test]
fn s16_inventory_answers_only_current_stub_network_reverse_enumeration() {
    use snac_rs::{dns::inventory::Zones, wire::Prefix};
    let mut r = Resolver::new(true);
    r.configure_zones(Zones::for_identity(&identity())).unwrap();
    let mut rng = ScriptedRandom::new([]);
    let prefix = Prefix::new("fd11:22:33:44::".parse().unwrap(), 64).unwrap();
    r.set_srp_sources(&[prefix]).unwrap();
    let mut labels: Vec<Vec<u8>> = format!("{:032x}", u128::from(prefix.address))
        .as_bytes()
        .iter()
        .rev()
        .map(|b| vec![*b])
        .collect();
    labels.extend([b"ip6".to_vec(), b"arpa".to_vec()]);
    let context = Name::from_labels(labels).unwrap();
    let owner = prefix_name(&[b"lb", b"_dns-sd", b"_udp"], &context);
    let answer = reply(r.submit(client(), &query(&owner, 12), 0, &mut rng).unwrap());
    assert_eq!(answer.answers.len(), 2);
    r.set_srp_sources(&[]).unwrap();
    let answer = reply(r.submit(client(), &query(&owner, 12), 1, &mut rng).unwrap());
    assert!(
        answer.answers.is_empty(),
        "old reverse network is no longer locally enumerated"
    );
}
fn prefix_name(labels: &[&[u8]], zone: &Name) -> Name {
    let mut out: Vec<_> = labels.iter().map(|l| l.to_vec()).collect();
    out.extend_from_slice(zone.labels());
    Name::from_labels(out).unwrap()
}
#[test]
fn s16_nested_proxy_delegation_and_inventory_a_lookup_preserve_view_ownership() {
    use snac_rs::{dns::inventory::Zones, mdns::Engine};
    let mut zones = Zones::for_identity(&identity());
    zones.discovery = in_zone("services", &zones.hostname);
    let mut r = Resolver::new(true);
    r.configure_zones(zones.clone()).unwrap();
    r.set_service_ready(&["192.0.2.53".parse().unwrap()], Some(53), None)
        .unwrap();
    let mut rng = ScriptedRandom::new([]);
    let query_name = in_zone("alias", &zones.discovery);
    assert!(
        r.submit(client(), &query(&query_name, 28), 0, &mut rng)
            .unwrap()
            .is_empty(),
        "delegated proxy child is not an empty router-owned name"
    );
    let mut engine = Engine::default();
    let mut answer = Message::new(0, 0x8400);
    answer.answers.push(snac_rs::dns::wire::Record {
        name: name("alias.local."),
        kind: 5,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Name(zones.hostname.clone()),
    });
    engine.querier.cache.receive(&answer, 0, &mut rng).unwrap();
    let answer = reply(r.poll_discovery(&mut engine, 1, &mut rng).unwrap());
    assert_eq!(answer.additional[0].data, Rdata::A([192, 0, 2, 53]));
    assert_eq!(answer.additional[0].name, zones.hostname);
}

fn sign_in_zone(mut message: Message, zone: &Name) -> Vec<u8> {
    let alias = name("default.service.arpa.");
    let map = |n: &mut Name| {
        if n.labels().ends_with(alias.labels()) {
            let mut labels = n.labels()[..n.labels().len() - alias.labels().len()].to_vec();
            labels.extend_from_slice(zone.labels());
            *n = Name::from_labels(labels).unwrap();
        }
    };
    map(&mut message.questions[0].name);
    for r in message.authority.iter_mut().chain(&mut message.additional) {
        map(&mut r.name);
        match &mut r.data {
            Rdata::Name(n) => map(n),
            Rdata::Srv { target, .. } => map(target),
            Rdata::Sig { signer, .. } => map(signer),
            _ => {}
        }
    }
    common::srp::sign(message)
}
#[test]
fn s16_alias_and_canonical_keyless_deletions_use_the_correct_stored_key_even_in_nested_zones() {
    use snac_rs::dns::inventory::Zones;
    for canonical_request in [false, true] {
        let mut zones = Zones::for_identity(&identity());
        zones.registrar = name("registered.default.service.arpa.");
        let mut r = Resolver::new(true);
        r.configure_zones(zones.clone()).unwrap();
        r.enable_srp(Box::new(MemoryStore::default()), 0, common::srp::NOW)
            .unwrap();
        let mut rng = ScriptedRandom::new([]);
        assert_eq!(
            reply(
                r.submit(
                    client(),
                    &common::srp::sign(common::srp::update()),
                    0,
                    &mut rng
                )
                .unwrap()
            )
            .flags
                & 15,
            0
        );
        let mut removal = Message::parse(
            include_bytes!("fixtures/srp/alg13-remove.bin"),
            Context::Unicast,
        )
        .unwrap();
        removal.additional[0].data = Rdata::Opt(vec![(2, vec![0; 8])]);
        assert!(
            removal.authority.iter().all(|r| r.kind != 25),
            "key comes from authenticated ownership table"
        );
        let request = if canonical_request {
            sign_in_zone(removal, &zones.registrar)
        } else {
            common::srp::sign(removal)
        };
        assert_eq!(
            reply(r.submit(client(), &request, 1, &mut rng).unwrap()).flags & 15,
            0,
            "canonical request={canonical_request}"
        );
        assert!(r
            .registry()
            .unwrap()
            .key(&in_zone("host", &zones.registrar), 1)
            .is_none());
    }
}
#[test]
fn s16_alias_expansion_overflow_is_atomic_and_canonical_journal_survives_restart() {
    use snac_rs::dns::inventory::Zones;
    let mut zones = Zones::for_identity(&identity());
    zones.registrar = Name::from_labels(vec![
        vec![b'x'; 63],
        vec![b'y'; 63],
        vec![b'z'; 63],
        b"example".to_vec(),
    ])
    .unwrap();
    let disk = common::srp::Store::default();
    let mut r = Resolver::new(true);
    r.configure_zones(zones.clone()).unwrap();
    r.enable_srp(Box::new(disk.clone()), 0, common::srp::NOW)
        .unwrap();
    let mut rng = ScriptedRandom::new([]);
    let original = common::srp::sign(common::srp::update());
    assert_eq!(
        reply(r.submit(client(), &original, 0, &mut rng).unwrap()).flags & 15,
        0
    );
    let saved = disk.bytes.borrow().clone();
    let mut large = common::srp::update();
    large.authority.truncate(3);
    let host = in_zone(&"h".repeat(63), &name("default.service.arpa."));
    for r in &mut large.authority {
        r.name = host.clone();
    }
    if let Rdata::Sig { signer, .. } = &mut large.additional.last_mut().unwrap().data {
        *signer = host;
    }
    assert_eq!(
        reply(
            r.submit(client(), &common::srp::sign(large), 1, &mut rng)
                .unwrap()
        )
        .flags
            & 15,
        2
    );
    assert_eq!(*disk.bytes.borrow(), saved);
    drop(r);
    let mut restored = Resolver::new(true);
    restored.configure_zones(zones.clone()).unwrap();
    restored
        .enable_srp(Box::new(disk.clone()), 0, common::srp::NOW + 1)
        .unwrap();
    assert!(restored
        .registry()
        .unwrap()
        .key(&in_zone("host", &zones.registrar), 0)
        .is_some());
    assert_eq!(
        reply(restored.submit(client(), &original, 0, &mut rng).unwrap()).flags & 15,
        0
    );
    zones.registrar = name("different.example.");
    let mut wrong = Resolver::new(true);
    wrong.configure_zones(zones).unwrap();
    assert!(wrong
        .enable_srp(Box::new(disk.clone()), 0, common::srp::NOW + 1)
        .is_err());
    assert_eq!(*disk.bytes.borrow(), saved);
}

#[test]
fn s16_browsing_ptrs_deduplicate_equal_zones_and_expire_with_registration_leases() {
    use snac_rs::{
        dns::inventory::{Inventory, Zones},
        srp::registry::LeasePolicy,
    };
    let mut same = Zones::for_identity(&identity());
    same.registrar = same.discovery.clone();
    let inventory = Inventory::new(same).unwrap();
    assert_eq!(
        inventory
            .answer(&question("lb._dns-sd._udp.local.", 12), 0)
            .unwrap()
            .unwrap()
            .answers
            .len(),
        1
    );
    let zones = Zones::for_identity(&identity());
    let mut r = Resolver::new(true);
    r.configure_zones(zones.clone()).unwrap();
    r.enable_srp(Box::new(MemoryStore::default()), 0, common::srp::NOW)
        .unwrap();
    r.set_srp_policy(LeasePolicy {
        max_lease: 1,
        ..LeasePolicy::default()
    })
    .unwrap();
    let mut rng = ScriptedRandom::new([]);
    assert_eq!(
        reply(
            r.submit(
                client(),
                &common::srp::sign(common::srp::update()),
                0,
                &mut rng
            )
            .unwrap()
        )
        .flags
            & 15,
        0
    );
    let browse = prefix(&["_http", "_tcp"], &zones.registrar);
    assert_eq!(
        reply(
            r.submit(client(), &query(&browse, 12), 1, &mut rng)
                .unwrap()
        )
        .answers
        .len(),
        1
    );
    r.tick(1000, &mut rng).unwrap();
    let expired = reply(
        r.submit(client(), &query(&browse, 12), 1000, &mut rng)
            .unwrap(),
    );
    assert!(expired.answers.is_empty());
    assert_eq!(expired.authority[0].kind, 6);
}
