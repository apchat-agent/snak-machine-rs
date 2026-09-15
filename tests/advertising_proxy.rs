mod common;
use snac_rs::dns::wire::{Context, Message, Name, Question, Rdata, Record};
fn record(name: &str, kind: u16) -> Record {
    Record {
        name: name.parse().unwrap(),
        kind,
        class: 0x8001,
        ttl: 120,
        data: Rdata::A([192, 0, 2, 1]),
    }
}
#[test]
fn s14_tsr_exact_ten_byte_layout_public_key_checksum_and_seven_day_time_clamp() {
    use snac_rs::mdns::tsr::{key_checksum, Stamp, OPTION_CODE};
    assert_eq!(
        OPTION_CODE, 65002,
        "experimental convention, not an IANA assignment"
    );
    assert_eq!(
        key_checksum(&[1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff, 5]),
        0x06020303
    );
    let s = Stamp {
        key_checksum: 0x12345678,
        received_at: 1000,
    };
    assert_eq!(
        s.encode(0x0102, 6000),
        [1, 2, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 5]
    );
    assert_eq!(
        s.encode(0, 0)[6..],
        [0, 0, 0, 0],
        "clock rollback never wraps to an old age"
    );
    assert_eq!(s.encode(0, u64::MAX)[6..], 604800u32.to_be_bytes());
    let b = s.encode(0x0102, 6000);
    let (index, parsed) = Stamp::decode(&b, 6000).unwrap();
    assert_eq!(index, 0x0102);
    assert_eq!(parsed, s);
    for n in 0..10 {
        assert!(Stamp::decode(&b[..n], 6000).is_none());
    }
    assert!(Stamp::decode(&[0; 11], 6000).is_none());
    let mut excessive = b;
    excessive[6..].fill(255);
    assert_eq!(
        Stamp::decode(&excessive, 0).unwrap().1.received_at,
        -604800000
    );
}
#[test]
fn s14_tsr_indices_exclude_questions_and_invalid_options_cannot_target_arbitrary_names() {
    use snac_rs::mdns::tsr::{extract, Stamp, OPTION_CODE};
    let mut m = Message::new(0, 0x8400);
    m.questions.push(Question {
        name: "question.local.".parse().unwrap(),
        kind: 1,
        class: 1,
    });
    m.answers.push(record("one.local.", 1));
    m.authority.push(record("two.local.", 1));
    m.additional.push(record("three.local.", 1));
    let s = Stamp {
        key_checksum: 17,
        received_at: -2000,
    };
    m.additional.push(Record {
        name: Name::root(),
        kind: 41,
        class: 9000,
        ttl: 0,
        data: Rdata::Opt(vec![
            (OPTION_CODE, s.encode(0, 3000).to_vec()),
            (OPTION_CODE, s.encode(1, 3000).to_vec()),
            (OPTION_CODE, s.encode(2, 3000).to_vec()),
            (OPTION_CODE, s.encode(3, 3000).to_vec()),
            (OPTION_CODE, s.encode(65535, 3000).to_vec()),
            (OPTION_CODE, vec![0; 9]),
            (OPTION_CODE + 1, s.encode(0, 3000).to_vec()),
        ]),
    });
    let b = m.encode().unwrap();
    let parsed = Message::parse(&b, Context::Mdns).unwrap();
    let found = extract(&parsed, OPTION_CODE, 3000).unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(found[&"two.local.".parse().unwrap()], s);
    m.flags = 0;
    assert_eq!(
        extract(&m, OPTION_CODE, 3000).unwrap().len(),
        2,
        "known answers never carry TSR"
    );
    if let Rdata::Opt(options) = &mut m.additional[1].data {
        options.push((OPTION_CODE, s.encode(1, 3000).to_vec()));
    }
    assert!(
        !extract(&m, OPTION_CODE, 3000)
            .unwrap()
            .contains_key(&"two.local.".parse().unwrap()),
        "ambiguous duplicate owner options cannot win by order"
    );
    for n in 0..b.len() {
        assert!(Message::parse(&b[..n], Context::Mdns).is_err());
    }
}
#[test]
fn s14_tsr_output_is_one_option_per_owner_without_known_answers_and_bounds_option_work() {
    use snac_rs::mdns::tsr::{attach, extract, Stamp, OPTION_CODE};
    let mut m = Message::new(0, 0x8400);
    m.answers = vec![record("one.local.", 1), record("one.local.", 1)];
    m.additional.push(record("two.local.", 1));
    let s = Stamp {
        key_checksum: 7,
        received_at: 0,
    };
    attach(&mut m, OPTION_CODE, 6000, &|_| Some(s)).unwrap();
    let Rdata::Opt(options) = &m.additional.last().unwrap().data else {
        panic!()
    };
    assert_eq!(
        options,
        &vec![
            (OPTION_CODE, s.encode(0, 6000).to_vec()),
            (OPTION_CODE, s.encode(2, 6000).to_vec())
        ]
    );
    assert_eq!(
        extract(
            &Message::parse(&m.encode().unwrap(), Context::Mdns).unwrap(),
            OPTION_CODE,
            6000
        )
        .unwrap()
        .len(),
        2
    );
    let mut query = Message::new(0, 0);
    query.answers.push(record("known.local.", 1));
    attach(&mut query, OPTION_CODE, 6000, &|_| Some(s)).unwrap();
    assert!(query.additional.is_empty());
    let mut shared = Message::new(0, 0x8400);
    let mut r = record("shared.local.", 1);
    r.class = 1;
    shared.answers.push(r);
    assert!(attach(&mut shared, OPTION_CODE, 6000, &|_| Some(s)).is_err());
    let mut many = Message::new(0, 0x8400);
    for i in 0..128 {
        many.answers.push(record(&format!("n{i}.local."), 1));
    }
    attach(&mut many, OPTION_CODE, 6000, &|_| Some(s)).unwrap();
    assert_eq!(extract(&many, OPTION_CODE, 6000).unwrap().len(), 128);
    many.answers.push(record("overflow.local.", 1));
    assert!(attach(&mut many, OPTION_CODE, 6000, &|_| Some(s)).is_err());
    if let Rdata::Opt(options) = &mut many.additional[0].data {
        options.push((OPTION_CODE, s.encode(128, 6000).to_vec()));
    }
    assert!(extract(&many, OPTION_CODE, 6000).is_err());
}

fn registered() -> (
    snac_rs::srp::registry::Registry,
    snac_rs::srp::wire::Update,
    snac_rs::persist::MemoryStore,
) {
    use snac_rs::srp::{
        registry::Registry,
        wire::{CryptoBudget, Validator},
    };
    let mut m = common::srp::update();
    for r in &mut m.authority {
        if let Rdata::Txt(v) = &mut r.data {
            *v = vec![
                vec![0, 255, 61],
                b"target=unchanged.default.service.arpa.".to_vec(),
            ];
        }
    }
    let bytes = common::srp::sign(m);
    let u = Validator::new(&[])
        .unwrap()
        .verify(
            &bytes,
            common::srp::NOW,
            &mut CryptoBudget::default(),
            |_| None,
        )
        .unwrap();
    let mut r = Registry::default();
    let mut store = snac_rs::persist::MemoryStore::default();
    r.apply(&u, &mut store, 1000, common::srp::NOW).unwrap();
    (r, u, store)
}
#[test]
fn s14_srp_projection_maps_dataset_owners_ptr_subtypes_and_embedded_targets_without_keys() {
    use snac_rs::mdns::advertise::Mapping;
    let (registry, update, _) = registered();
    let mapping = Mapping::new(update.zone.clone(), &[0x5c, 0x4d, 0x2e, 0x9a, 0xb4]).unwrap();
    let records = mapping.project(&registry, &update.host, 1000).unwrap();
    assert_eq!(records.len(), 5);
    assert!(records.iter().all(|r| r.kind != 25 && r.kind != 24));
    let host: Name = "Host.5c4d2e9ab4.local.".parse().unwrap();
    assert!(records
        .iter()
        .any(|r| r.name == host && r.kind == 28 && r.class == 0x8001));
    let instance = Name::from_labels(vec![
        b"My Printer".to_vec(),
        b"_http".to_vec(),
        b"_tcp".to_vec(),
        b"5c4d2e9ab4".to_vec(),
        b"local".to_vec(),
    ])
    .unwrap();
    for owner in ["_http._tcp.local.", "_color._sub._http._tcp.local."] {
        assert!(records.iter().any(|r| r.name == owner.parse().unwrap()
            && r.class == 1
            && r.data == Rdata::Name(instance.clone())));
    }
    assert!(records.iter().any(|r| r.name == instance
        && matches!(&r.data, Rdata::Srv { target, port: 8080, .. } if *target == host)));
    let txt = records.iter().find(|r| r.kind == 16).unwrap();
    assert_eq!(
        txt.data,
        update.services[0]
            .records
            .iter()
            .find(|r| r.kind == 16)
            .unwrap()
            .data
    );
    let renamed = mapping.renamed(2).unwrap();
    let renamed_records = renamed.project(&registry, &update.host, 1000).unwrap();
    assert!(renamed_records
        .iter()
        .any(|r| r.name == "Host.5c4d2e9ab4-2.local.".parse().unwrap()));
    assert_eq!(
        registry.records(&update.host, 28, 1000).len(),
        1,
        "publication rename does not rename registration"
    );
    let stamp = mapping.stamp(&registry, &host, 1000).unwrap();
    assert_eq!(stamp.received_at, 1000);
    assert!(
        mapping
            .stamp(&registry, &"_http._tcp.local.".parse().unwrap(), 1000)
            .is_none(),
        "shared browse owners cannot carry TSR"
    );
}
#[test]
fn s14_projection_filters_unusable_addresses_and_never_outlives_backing_leases() {
    use snac_rs::{
        mdns::advertise::Mapping,
        srp::wire::{CryptoBudget, Validator},
    };
    let (mut registry, update, mut store) = registered();
    let mut m = common::srp::update();
    m.id += 1;
    m.additional[0].data = Rdata::Opt(vec![(
        2,
        [10u32.to_be_bytes(), 100u32.to_be_bytes()].concat(),
    )]);
    for ip in ["fe80::1", "::", "::1", "ff02::1", "2001:db8::1"] {
        m.authority.push(Record {
            name: update.host.clone(),
            kind: 28,
            class: 1,
            ttl: 120,
            data: Rdata::Aaaa(ip.parse::<std::net::Ipv6Addr>().unwrap().octets()),
        });
    }
    for ip in [
        [169, 254, 1, 1],
        [127, 0, 0, 1],
        [224, 0, 0, 1],
        [0, 0, 0, 0],
        [192, 0, 2, 1],
    ] {
        m.authority.push(Record {
            name: update.host.clone(),
            kind: 1,
            class: 1,
            ttl: 120,
            data: Rdata::A(ip),
        });
    }
    let u = Validator::new(&[])
        .unwrap()
        .verify(
            &common::srp::sign(m),
            common::srp::NOW,
            &mut CryptoBudget::default(),
            |n| registry.key(n, 2000).cloned(),
        )
        .unwrap();
    registry
        .apply(&u, &mut store, 2000, common::srp::NOW)
        .unwrap();
    let mapping = Mapping::new(update.zone, &[1]).unwrap();
    let records = mapping.project(&registry, &u.host, 11000).unwrap();
    assert!(records.iter().all(|r| r.ttl <= 1));
    assert_eq!(records.iter().filter(|r| r.kind == 28).count(), 2);
    assert_eq!(records.iter().filter(|r| r.kind == 1).count(), 1);
    assert!(
        mapping
            .project(&registry, &u.host, 11501)
            .unwrap()
            .is_empty(),
        "subsecond remainder cannot promise one more second"
    );
    assert!(mapping
        .project(&registry, &u.host, 12000)
        .unwrap()
        .is_empty());
    assert!(registry.key(&u.host, 12000).is_some());
}
#[test]
fn s14_mapping_preserves_binary_labels_and_external_names_and_rejects_length_overflow() {
    use snac_rs::mdns::advertise::Mapping;
    let mapping = Mapping::new("example.".parse().unwrap(), &[1, 2, 3]).unwrap();
    let original = Name::from_labels(vec![vec![b'A', 0, 255], b"example".to_vec()]).unwrap();
    let mut r = Record {
        name: original,
        kind: 15,
        class: 1,
        ttl: 120,
        data: Rdata::Preference {
            preference: 10,
            name: "elsewhere.invalid.".parse().unwrap(),
        },
    };
    let transformed = mapping.rewrite(&r).unwrap().unwrap();
    assert_eq!(transformed.name.labels()[0], vec![b'A', 0, 255]);
    assert_eq!(transformed.data, r.data);
    r.kind = 33;
    r.data = Rdata::Srv {
        priority: 0,
        weight: 0,
        port: 1,
        target: "target.example.".parse().unwrap(),
    };
    assert!(
        matches!(mapping.rewrite(&r).unwrap().unwrap().data, Rdata::Srv { target, .. } if target == "target.010203.local.".parse().unwrap())
    );
    let mapping = Mapping::new("x.".parse().unwrap(), &[0; 31]).unwrap();
    let long = Name::from_labels(vec![
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        b"x".to_vec(),
    ])
    .unwrap();
    r.name = long;
    assert!(mapping.rewrite(&r).is_err());
    assert!(Mapping::new(Name::root(), &[1]).is_err());
    assert!(Mapping::new("x.".parse().unwrap(), &[]).is_err());
    assert!(Mapping::new("x.".parse().unwrap(), &[0; 32]).is_err());
}

#[test]
fn s14_tsr_newer_data_replaces_all_cached_types_and_older_goodbyes_cannot_remove_it() {
    use snac_rs::{
        mdns::{
            cache::Cache,
            tsr::{attach, Stamp, OPTION_CODE},
        },
        time::ScriptedRandom,
    };
    let mut cache = Cache::default();
    let mut rng = ScriptedRandom::new([]);
    let q = Question {
        name: "host.local.".parse().unwrap(),
        kind: 1,
        class: 1,
    };
    let make = |last: u8, ttl: u32, stamp: i128, at| {
        let mut m = Message::new(0, 0x8400);
        let mut r = record("host.local.", 1);
        r.ttl = ttl;
        r.data = Rdata::A([192, 0, 2, last]);
        m.answers.push(r);
        attach(&mut m, OPTION_CODE, at, &|_| {
            Some(Stamp {
                key_checksum: 7,
                received_at: stamp,
            })
        })
        .unwrap();
        m
    };
    cache.receive(&make(1, 120, 0, 0), 0, &mut rng).unwrap();
    cache
        .receive(&make(2, 120, 10000, 10000), 10000, &mut rng)
        .unwrap();
    assert_eq!(
        cache.answers(&q, 10000).len(),
        1,
        "new TSR removes stale data before cache-flush grace"
    );
    assert_eq!(cache.answers(&q, 10000)[0].data, Rdata::A([192, 0, 2, 2]));
    cache
        .receive(&make(2, 0, 0, 11000), 11000, &mut rng)
        .unwrap();
    assert_eq!(
        cache.answers(&q, 13000).len(),
        1,
        "older proxy's goodbye is ignored"
    );
    assert_eq!(
        cache.owner_stamp(&q.name, 13000),
        Some(Some(Stamp {
            key_checksum: 7,
            received_at: 10000
        }))
    );
    cache
        .receive(&make(3, 120, 0, 14000), 14000, &mut rng)
        .unwrap();
    assert_eq!(cache.answers(&q, 14000)[0].data, Rdata::A([192, 0, 2, 2]));
}
#[test]
fn s14_tsr_conflicting_checksum_or_absent_stamp_flushes_cached_owner_and_query_known_answers_never_do(
) {
    use snac_rs::{
        mdns::{
            cache::Cache,
            tsr::{attach, Stamp, OPTION_CODE},
        },
        time::ScriptedRandom,
    };
    let mut cache = Cache::default();
    let mut rng = ScriptedRandom::new([]);
    let name: Name = "host.local.".parse().unwrap();
    let mut m = Message::new(0, 0x8400);
    m.answers.push(record("host.local.", 1));
    let stamp = Stamp {
        key_checksum: 7,
        received_at: 0,
    };
    attach(&mut m, OPTION_CODE, 0, &|_| Some(stamp)).unwrap();
    cache.receive(&m, 0, &mut rng).unwrap();
    let mut known = Message::new(0, 0);
    known.answers.push(record("host.local.", 1));
    cache.receive(&known, 2000, &mut rng).unwrap();
    assert_eq!(cache.owner_stamp(&name, 2000), Some(Some(stamp)));
    let mut plain = Message::new(0, 0x8400);
    let mut v6 = record("host.local.", 28);
    v6.data = Rdata::Aaaa([1; 16]);
    plain.answers.push(v6);
    cache.receive(&plain, 3000, &mut rng).unwrap();
    assert_eq!(cache.owner_stamp(&name, 3000), Some(None));
    assert!(cache
        .answers(
            &Question {
                name: name.clone(),
                kind: 1,
                class: 1
            },
            3000
        )
        .is_empty());
    attach(&mut m, OPTION_CODE, 4000, &|_| {
        Some(Stamp {
            key_checksum: 8,
            received_at: 0,
        })
    })
    .unwrap();
    cache.receive(&m, 4000, &mut rng).unwrap();
    assert!(cache
        .answers(
            &Question {
                name: name.clone(),
                kind: 28,
                class: 1
            },
            4000
        )
        .is_empty());
    assert_eq!(
        cache
            .owner_stamp(&name, 4000)
            .unwrap()
            .unwrap()
            .key_checksum,
        8
    );
    let mut query = Message::new(0, 0);
    query.authority.push(record("probe.local.", 1));
    query.additional.push(record("extra.local.", 1));
    attach(&mut query, OPTION_CODE, 5000, &|_| Some(stamp)).unwrap();
    cache.receive(&query, 5000, &mut rng).unwrap();
    assert!(cache
        .owner_stamp(&"probe.local.".parse().unwrap(), 5000)
        .is_none());
    assert!(cache
        .owner_stamp(&"extra.local.".parse().unwrap(), 5000)
        .is_some());
}
#[test]
fn s14_tsr_time_comparison_tolerates_wire_quantization_without_changing_key_conflicts() {
    use snac_rs::mdns::tsr::{compare, Relation, Stamp};
    let local = Stamp {
        key_checksum: 7,
        received_at: 1234,
    };
    assert_eq!(
        compare(
            Some(local),
            Some(Stamp {
                received_at: 2000,
                ..local
            })
        ),
        Relation::Equal
    );
    assert_eq!(
        compare(
            Some(local),
            Some(Stamp {
                received_at: 12000,
                ..local
            })
        ),
        Relation::Newer
    );
    assert_eq!(
        compare(
            Some(local),
            Some(Stamp {
                received_at: -12000,
                ..local
            })
        ),
        Relation::Older
    );
    assert_eq!(
        compare(
            Some(local),
            Some(Stamp {
                key_checksum: 8,
                ..local
            })
        ),
        Relation::Conflict
    );
    assert_eq!(compare(Some(local), None), Relation::Conflict);
    assert_eq!(compare(None, Some(local)), Relation::Conflict);
    assert_eq!(compare(None, None), Relation::Unstamped);
}

#[test]
fn s14_metadata_budget_counts_dense_label_and_empty_txt_vector_allocations() {
    use snac_rs::{
        mdns::{cache::Cache, publish::Publisher},
        time::ScriptedRandom,
    };
    let mut rng = ScriptedRandom::new([]);
    let name = Name::from_labels(vec![vec![b'x']; 125]).unwrap();
    let name_heap = 125 * std::mem::size_of::<Vec<u8>>() + 125 + 251;
    let r = Record {
        name,
        kind: 1,
        class: 0x8001,
        ttl: 120,
        data: Rdata::A([192, 0, 2, 1]),
    };
    let mut m = Message::new(0, 0x8400);
    m.answers.push(r.clone());
    let mut c = Cache::default();
    c.receive(&m, 0, &mut rng).unwrap();
    assert!(
        c.counts().2 >= name_heap * 2,
        "cache entry and RRset key own distinct label vectors"
    );
    let mut p = Publisher::default();
    p.replace(1, &[], &[r], 0, &mut rng).unwrap();
    assert!(
        p.counts().2 >= name_heap * 4,
        "projection plus NSEC owner/next and publication identity"
    );
    let r = Record {
        name: "txt.local.".parse().unwrap(),
        kind: 16,
        class: 1,
        ttl: 120,
        data: Rdata::Txt(vec![vec![]; 2048]),
    };
    let mut m = Message::new(0, 0x8400);
    m.answers.push(r.clone());
    let mut c = Cache::default();
    c.receive(&m, 0, &mut rng).unwrap();
    assert!(c.counts().2 >= 2 * 2048 * std::mem::size_of::<Vec<u8>>());
    let mut p = Publisher::default();
    p.replace(1, &[], &[r], 0, &mut rng).unwrap();
    assert!(p.counts().2 >= 2 * 2048 * std::mem::size_of::<Vec<u8>>());
}

fn stamps(
    records: &[Record],
    time: i128,
) -> std::collections::BTreeMap<Name, snac_rs::mdns::tsr::Stamp> {
    records
        .iter()
        .filter(|r| r.class & 0x8000 != 0)
        .map(|r| {
            (
                r.name.clone(),
                snac_rs::mdns::tsr::Stamp {
                    key_checksum: 7,
                    received_at: time,
                },
            )
        })
        .collect()
}
#[test]
fn s14_tsr_local_registration_distinguishes_conflict_staleness_and_already_known_data() {
    use snac_rs::{
        mdns::{
            tsr::{attach, RegistrationError, OPTION_CODE},
            Engine,
        },
        time::ScriptedRandom,
    };
    let records = vec![record("host.local.", 1)];
    let mut rng = ScriptedRandom::new([]);
    for (cached_time, proposed_time, expected) in [
        (10000, 0, Some(RegistrationError::Stale)),
        (10000, 10000, None),
    ] {
        let mut e = Engine::default();
        let mut cached = Message::new(0, 0x8400);
        cached.answers = records.clone();
        let times = stamps(&records, cached_time);
        attach(&mut cached, OPTION_CODE, 10000, &|n| times.get(n).copied()).unwrap();
        e.querier.cache.receive(&cached, 10000, &mut rng).unwrap();
        let result = e.register_tsr(
            1,
            (&[], &records),
            &stamps(&records, proposed_time),
            10000,
            &mut rng,
        );
        assert_eq!(result.err(), expected);
        if expected.is_none() {
            assert!(e.publisher.ready(1));
            assert!(e
                .publisher
                .poll(&|_, _| records.clone(), 10000)
                .unwrap()
                .is_none());
            assert!(e
                .querier
                .cache
                .owner_stamp(&records[0].name, 10000)
                .is_none());
        }
    }
    let mut e = Engine::default();
    let mut cached = Message::new(0, 0x8400);
    cached.answers = records.clone();
    e.querier.cache.receive(&cached, 0, &mut rng).unwrap();
    assert_eq!(
        e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng),
        Err(RegistrationError::Conflict)
    );
    let mut shared = records.clone();
    shared[0].class = 1;
    assert_eq!(
        Engine::default().register_tsr(1, (&[], &shared), &stamps(&records, 0), 0, &mut rng),
        Err(RegistrationError::Invalid)
    );
}
#[test]
fn s14_tsr_filters_stale_packets_and_silently_suppresses_only_superseded_owners() {
    use snac_rs::{
        mdns::{
            tsr::{attach, OPTION_CODE},
            wire::Datagram,
            Engine,
        },
        time::ScriptedRandom,
    };
    let mut e = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let mut records = vec![record("host.local.", 1)];
    records.push(Record {
        name: "service.local.".parse().unwrap(),
        kind: 16,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Txt(vec![b"k=v".to_vec()]),
    });
    let source = |_, _| records.clone();
    e.register_tsr(
        1,
        (&[], &records),
        &stamps(&records, 10000),
        10000,
        &mut rng,
    )
    .unwrap();
    for at in [10000, 10250, 10500, 10750, 11750] {
        let b = e.publisher.poll(&source, at).unwrap().unwrap();
        e.publisher.sent(b.token, true, at);
    }
    let mut peer = Message::new(0, 0x8400);
    peer.answers.push(record("host.local.", 1));
    peer.answers[0].ttl = 0;
    attach(&mut peer, OPTION_CODE, 12000, &|n| {
        stamps(&records, 0).get(n).copied()
    })
    .unwrap();
    let mut d = Datagram {
        source: "[fe80::2]:5353".parse().unwrap(),
        destination: "[ff02::fb]:5353".parse().unwrap(),
        message: peer,
    };
    e.receive(&d, true, &source, 12000, &mut rng).unwrap();
    assert!(e
        .querier
        .cache
        .owner_stamp(&records[0].name, 12000)
        .is_none());
    assert!(e.publisher.ready(1));
    assert!(e.publisher.take_conflict().is_none());
    d.message.answers[0].ttl = 120;
    d.message.answers[0].data = Rdata::A([192, 0, 2, 200]);
    attach(&mut d.message, OPTION_CODE, 20000, &|n| {
        stamps(&records, 20000).get(n).copied()
    })
    .unwrap();
    e.receive(&d, true, &source, 20000, &mut rng).unwrap();
    assert_eq!(e.take_stale(), Some((1, records[0].name.clone())));
    assert!(e.take_stale().is_none());
    assert_eq!(e.publisher.goodbye_count(), 0);
    assert!(e.publisher.poll(&source, 20000).unwrap().is_none());
    let mut q = Message::new(0, 0);
    q.questions.push(Question {
        name: records[1].name.clone(),
        kind: 16,
        class: 1,
    });
    d.message = q;
    e.receive(&d, true, &source, 21000, &mut rng).unwrap();
    let reply = e
        .responder
        .poll(&e.publisher, &source, 21000)
        .unwrap()
        .unwrap();
    assert_eq!(reply.messages[0].answers[0].name, records[1].name);
}
#[test]
fn s14_equal_tsr_probes_and_announcements_suppress_redundant_work_and_time_only_refresh_does_not_probe(
) {
    use snac_rs::{
        mdns::{
            tsr::{attach, extract, OPTION_CODE},
            wire::Datagram,
            Engine,
        },
        time::ScriptedRandom,
    };
    let mut e = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let records = vec![record("host.local.", 1)];
    let source = |_, _| records.clone();
    e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
        .unwrap();
    let mut m = Message::new(0, 0);
    m.questions.push(Question {
        name: records[0].name.clone(),
        kind: 255,
        class: 0x8001,
    });
    m.authority = records.clone();
    attach(&mut m, OPTION_CODE, 0, &|n| {
        stamps(&records, 0).get(n).copied()
    })
    .unwrap();
    let mut d = Datagram {
        source: "[fe80::2]:5353".parse().unwrap(),
        destination: "[ff02::fb]:5353".parse().unwrap(),
        message: m,
    };
    e.receive(&d, true, &source, 0, &mut rng).unwrap();
    assert!(e.publisher.poll(&source, 0).unwrap().is_none());
    assert!(e.publisher.poll(&source, 749).unwrap().is_none());
    d.message = Message::new(0, 0x8400);
    d.message.answers = records.clone();
    attach(&mut d.message, OPTION_CODE, 750, &|n| {
        stamps(&records, 0).get(n).copied()
    })
    .unwrap();
    e.receive(&d, true, &source, 750, &mut rng).unwrap();
    assert!(e.publisher.ready(1));
    assert!(e.publisher.poll(&source, 1000).unwrap().is_none());
    e.register_tsr(
        1,
        (&records, &records),
        &stamps(&records, 10000),
        10000,
        &mut rng,
    )
    .unwrap();
    assert!(e.publisher.ready(1));
    assert!(e.publisher.poll(&source, 10000).unwrap().is_none());
    let mut answer = Message::new(0, 0x8400);
    answer.answers = records.clone();
    let output = e.prepare_outgoing(vec![answer], 12000).unwrap();
    assert_eq!(
        extract(&output[0], OPTION_CODE, 12000).unwrap()[&records[0].name].received_at,
        10000
    );
}
#[test]
fn s14_local_tsr_owner_metadata_has_a_tested_per_dataset_bound() {
    use snac_rs::{
        mdns::{tsr::RegistrationError, Engine},
        time::ScriptedRandom,
    };
    let mut e = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let mut records: Vec<_> = (0..128)
        .map(|i| record(&format!("n{i}.local."), 1))
        .collect();
    e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
        .unwrap();
    let before = e.publisher.counts();
    let old = records.clone();
    records.push(record("overflow.local.", 1));
    assert_eq!(
        e.register_tsr(1, (&old, &records), &stamps(&records, 0), 0, &mut rng),
        Err(RegistrationError::Capacity)
    );
    assert_eq!(e.publisher.counts(), before);
}

#[test]
fn s14_newer_local_owner_supersedes_older_registrant_and_never_sends_its_goodbye() {
    use snac_rs::{mdns::Engine, time::ScriptedRandom};
    let mut e = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let records = vec![record("host.local.", 1)];
    e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
        .unwrap();
    for at in [0, 250, 500, 750, 1750] {
        let b = e
            .publisher
            .poll(&|_, _| records.clone(), at)
            .unwrap()
            .unwrap();
        e.publisher.sent(b.token, true, at);
    }
    e.register_tsr(
        2,
        (&[], &records),
        &stamps(&records, 10000),
        10000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(e.take_stale(), Some((1, records[0].name.clone())));
    assert!(
        !e.publisher.ready(2),
        "newer registration probes even with identical RDATA"
    );
    e.register_tsr(1, (&records, &[]), &stamps(&[], 0), 10001, &mut rng)
        .unwrap();
    assert_eq!(
        e.publisher.goodbye_count(),
        0,
        "TSR 3.7 prohibits stale-owner goodbye"
    );
}
#[test]
fn s14_query_additional_data_is_cached_and_partial_same_key_data_never_conflicts() {
    use snac_rs::{
        mdns::{
            tsr::{attach, OPTION_CODE},
            wire::Datagram,
            Engine,
        },
        time::ScriptedRandom,
    };
    let mut e = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let records = vec![record("host.local.", 1)];
    e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
        .unwrap();
    for at in [0, 250, 500, 750, 1750] {
        let b = e
            .publisher
            .poll(&|_, _| records.clone(), at)
            .unwrap()
            .unwrap();
        e.publisher.sent(b.token, true, at);
    }
    let mut m = Message::new(0, 0);
    let mut v6 = record("host.local.", 28);
    v6.data = Rdata::Aaaa([0x20; 16]);
    m.authority.push(v6);
    m.additional.push(record("extra.local.", 1));
    attach(&mut m, OPTION_CODE, 2000, &|_| {
        Some(snac_rs::mdns::tsr::Stamp {
            key_checksum: 7,
            received_at: 0,
        })
    })
    .unwrap();
    e.receive(
        &Datagram {
            source: "[fe80::2]:5353".parse().unwrap(),
            destination: "[ff02::fb]:5353".parse().unwrap(),
            message: m,
        },
        true,
        &|_, _| records.clone(),
        2000,
        &mut rng,
    )
    .unwrap();
    assert!(e.publisher.ready(1));
    assert!(e.publisher.take_conflict().is_none());
    assert!(e
        .querier
        .cache
        .owner_stamp(&"extra.local.".parse().unwrap(), 2000)
        .is_some());
    assert!(e
        .querier
        .cache
        .owner_stamp(&records[0].name, 2000)
        .is_none());
}
#[test]
fn s14_tsr_options_are_included_in_packet_budget_without_losing_records() {
    use snac_rs::{
        mdns::{
            tsr::{extract, OPTION_CODE},
            Engine,
        },
        time::ScriptedRandom,
    };
    let mut e = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let records: Vec<_> = (0..100)
        .map(|i| record(&format!("host-{i}.local."), 1))
        .collect();
    e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
        .unwrap();
    let batch = e
        .publisher
        .poll(&|_, _| records.clone(), 0)
        .unwrap()
        .unwrap();
    let count: usize = batch.messages.iter().map(|m| m.authority.len()).sum();
    let output = e.prepare_outgoing(batch.messages, 2000).unwrap();
    assert_eq!(
        output.iter().map(|m| m.authority.len()).sum::<usize>(),
        count
    );
    for m in output {
        assert!(
            m.encode_context(Context::Mdns).unwrap().len() <= 1200,
            "TSR growth must repacketize multi-RR output"
        );
        let values = extract(&m, OPTION_CODE, 2000).unwrap();
        assert!(m
            .authority
            .iter()
            .all(|r| values.get(&r.name).is_some_and(|s| s.received_at == 0)));
        assert!(m
            .questions
            .iter()
            .all(|q| m.authority.iter().any(|r| r.name == q.name)));
    }
}

#[test]
fn s14_durable_registrar_drives_publication_refresh_expiry_and_restart() {
    use snac_rs::{
        mdns::{
            tsr::{extract, OPTION_CODE},
            Engine,
        },
        srp::{registry::LeasePolicy, service::Registrar},
        time::ScriptedRandom,
    };
    let (_, update, _) = registered();
    let store = common::srp::Store::default();
    let mut registrar = Registrar::open(Box::new(store.clone()), 1000, common::srp::NOW).unwrap();
    registrar
        .set_policy(LeasePolicy {
            max_lease: 30,
            max_key_lease: 60,
            ..LeasePolicy::default()
        })
        .unwrap();
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    registrar.apply(&update, 1000, common::srp::NOW).unwrap();
    registrar
        .sync_advertising(&mut engine, 1000, &mut rng)
        .unwrap();
    assert_eq!(registrar.advertising_counts().0, 1);
    for at in [1000, 1250, 1500, 1750, 2750] {
        let b = engine
            .publisher
            .poll(&|id, t| registrar.advertised(id, t), at)
            .unwrap()
            .unwrap();
        let output = engine.prepare_outgoing(b.messages, at).unwrap();
        assert!(output
            .iter()
            .flat_map(|m| m.authority.iter().chain(&m.answers))
            .all(|r| r.ttl <= 30));
        assert!(output
            .iter()
            .any(|m| !extract(m, OPTION_CODE, at).unwrap().is_empty()));
        engine.publisher.sent(b.token, true, at);
    }
    // Exact durable retry neither refreshes the original reception time nor announces.
    registrar
        .apply(&update, 3000, common::srp::NOW + 2)
        .unwrap();
    registrar
        .sync_advertising(&mut engine, 3000, &mut rng)
        .unwrap();
    assert!(engine
        .publisher
        .poll(&|id, t| registrar.advertised(id, t), 3000)
        .unwrap()
        .is_none());
    let mut restored = Registrar::open(Box::new(store.clone()), 0, common::srp::NOW + 10).unwrap();
    let mut fresh = Engine::default();
    restored.sync_advertising(&mut fresh, 0, &mut rng).unwrap();
    let b = fresh
        .publisher
        .poll(&|id, t| restored.advertised(id, t), 0)
        .unwrap()
        .unwrap();
    let output = fresh.prepare_outgoing(b.messages, 0).unwrap();
    assert!(output
        .iter()
        .flat_map(|m| extract(m, OPTION_CODE, 0).unwrap().into_values())
        .all(|s| s.received_at == -10000));
    registrar.expire(31000);
    registrar
        .sync_advertising(&mut engine, 31000, &mut rng)
        .unwrap();
    let b = engine
        .publisher
        .poll(&|id, t| registrar.advertised(id, t), 31000)
        .unwrap()
        .unwrap();
    assert!(b
        .messages
        .iter()
        .flat_map(|m| &m.answers)
        .all(|r| r.ttl == 0));
    engine.publisher.sent(b.token, true, 31000);
    assert_eq!(engine.publisher.counts().0, 0);
    assert_eq!(registrar.advertising_counts(), (0, 0, 0));
}
#[test]
fn s14_registrar_failed_durability_keeps_advertised_data_and_conflict_renames_only_publication() {
    use snac_rs::{
        mdns::{wire::Datagram, Engine},
        srp::{
            service::Registrar,
            wire::{CryptoBudget, Validator},
        },
        time::ScriptedRandom,
    };
    let (_, update, _) = registered();
    let store = common::srp::Store::default();
    let mut registrar = Registrar::open(Box::new(store.clone()), 0, common::srp::NOW).unwrap();
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    registrar.apply(&update, 0, common::srp::NOW).unwrap();
    registrar
        .sync_advertising(&mut engine, 0, &mut rng)
        .unwrap();
    let b = engine
        .publisher
        .poll(&|id, t| registrar.advertised(id, t), 0)
        .unwrap()
        .unwrap();
    let old = b.messages[0].authority[0].name.clone();
    engine.publisher.sent(b.token, true, 0);
    let mut conflict = Message::new(0, 0x8400);
    let mut r = b.messages[0].authority[0].clone();
    r.class |= 0x8000;
    r.data = Rdata::Aaaa([0x30; 16]);
    conflict.answers.push(r);
    engine
        .receive(
            &Datagram {
                source: "[fe80::2]:5353".parse().unwrap(),
                destination: "[ff02::fb]:5353".parse().unwrap(),
                message: conflict,
            },
            true,
            &|id, t| registrar.advertised(id, t),
            100,
            &mut rng,
        )
        .unwrap();
    registrar
        .sync_advertising(&mut engine, 100, &mut rng)
        .unwrap();
    let b = engine
        .publisher
        .poll(&|id, t| registrar.advertised(id, t), 5100)
        .unwrap()
        .unwrap();
    assert!(b
        .messages
        .iter()
        .flat_map(|m| &m.authority)
        .all(|r| r.name != old));
    assert!(registrar.registry().hosts().any(|(n, _)| *n == update.host));
    let mut request = common::srp::update();
    request.id += 1;
    if let Some(r) = request.authority.iter_mut().find(|r| r.kind == 16) {
        r.data = Rdata::Txt(vec![b"changed".to_vec()]);
    }
    let bytes = common::srp::sign(request);
    let changed = Validator::new(&[])
        .unwrap()
        .verify(
            &bytes,
            common::srp::NOW,
            &mut CryptoBudget::default(),
            |_| None,
        )
        .unwrap();
    let before = registrar.advertising_counts();
    store.fail.set(true);
    assert!(registrar.apply(&changed, 5200, common::srp::NOW).is_err());
    assert_eq!(registrar.advertising_counts(), before);
    assert!(registrar.registry().services().all(|(_, s)| s
        .records
        .iter()
        .all(|r| r.data != Rdata::Txt(vec![b"changed".to_vec()]))));
}

#[test]
fn s14_experimental_tsr_code_is_configurable_and_used_for_both_directions() {
    use snac_rs::{
        config::Config,
        mdns::{
            tsr::{attach, extract, OPTION_CODE},
            wire::Datagram,
            Engine,
        },
        time::ScriptedRandom,
    };
    let base = ["--backend", "tap", "--infra", "a", "--stub", "b"];
    assert_eq!(
        Config::parse(base).unwrap().unwrap().tsr_option_code,
        OPTION_CODE
    );
    assert_eq!(
        Config::parse(base.into_iter().chain(["--tsr-option-code", "65003"]))
            .unwrap()
            .unwrap()
            .tsr_option_code,
        65003
    );
    for bad in ["0", "65536", "-1", "invalid"] {
        assert!(Config::parse(base.into_iter().chain(["--tsr-option-code", bad])).is_err());
    }
    let mut e = Engine::default();
    assert!(e.set_tsr_code(0).is_err());
    e.set_tsr_code(65003).unwrap();
    let mut rng = ScriptedRandom::new([]);
    let records = vec![record("host.local.", 1)];
    e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
        .unwrap();
    assert!(
        e.set_tsr_code(OPTION_CODE).is_err(),
        "active publications retain their negotiated convention"
    );
    let b = e
        .publisher
        .poll(&|_, _| records.clone(), 0)
        .unwrap()
        .unwrap();
    let output = e.prepare_outgoing(b.messages, 2000).unwrap();
    assert!(!extract(&output[0], 65003, 2000).unwrap().is_empty());
    assert!(extract(&output[0], OPTION_CODE, 2000).unwrap().is_empty());
    let mut m = Message::new(0, 0x8400);
    m.answers = records.clone();
    attach(&mut m, 65003, 10000, &|n| {
        stamps(&records, 10000).get(n).copied()
    })
    .unwrap();
    e.receive(
        &Datagram {
            source: "[fe80::2]:5353".parse().unwrap(),
            destination: "[ff02::fb]:5353".parse().unwrap(),
            message: m,
        },
        true,
        &|_, _| records.clone(),
        10000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(e.take_stale(), Some((1, records[0].name.clone())));
    assert_eq!(
        e.querier.cache.owner_stamp(&records[0].name, 10000),
        Some(stamps(&records, 10000).get(&records[0].name).copied())
    );
}
#[test]
fn s14_registrar_slot_and_pending_tables_fill_coalesce_and_release_at_their_bound() {
    use snac_rs::{
        mdns::Engine,
        srp::{
            registry::LeasePolicy,
            service::Registrar,
            wire::{CryptoBudget, Error, Validator},
        },
        time::ScriptedRandom,
    };
    let mut registrar = Registrar::open(
        Box::new(snac_rs::persist::MemoryStore::default()),
        0,
        common::srp::NOW,
    )
    .unwrap();
    registrar
        .set_policy(LeasePolicy {
            max_lease: 20,
            max_key_lease: 30,
            ..LeasePolicy::default()
        })
        .unwrap();
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let make = |i: usize, change: bool| {
        let name: Name = format!("host{i}.default.service.arpa.").parse().unwrap();
        let mut m = common::srp::update();
        m.id = i as u16 + if change { 1000 } else { 0 };
        m.authority.truncate(3);
        for r in &mut m.authority {
            r.name = name.clone();
        }
        if let Rdata::Sig { signer, .. } = &mut m.additional.last_mut().unwrap().data {
            *signer = name;
        }
        Validator::new(&[])
            .unwrap()
            .verify(
                &common::srp::sign(m),
                common::srp::NOW,
                &mut CryptoBudget::default(),
                |_| None,
            )
            .unwrap()
    };
    for i in 0..128 {
        registrar
            .apply(&make(i, false), 0, common::srp::NOW)
            .unwrap();
    }
    registrar
        .sync_advertising(&mut engine, 0, &mut rng)
        .unwrap();
    assert_eq!(registrar.advertising_counts(), (128, 0, 0));
    for i in 0..128 {
        registrar
            .apply(&make(i, true), 1000, common::srp::NOW + 1)
            .unwrap();
    }
    let before = registrar.advertising_counts();
    assert_eq!((before.0, before.1), (128, 128));
    assert!(before.2 <= 4 * 1024 * 1024);
    assert_eq!(
        registrar.apply(&make(128, false), 1000, common::srp::NOW + 1),
        Err(Error::ServFail)
    );
    assert_eq!(registrar.advertising_counts(), before);
    registrar.expire(21000);
    registrar
        .sync_advertising(&mut engine, 21000, &mut rng)
        .unwrap();
    assert_eq!(registrar.advertising_counts(), (0, 0, 0));
    assert_eq!(engine.publisher.counts().0, 0);
}

#[test]
fn s14_equal_goodbye_or_nonprobe_query_cannot_cancel_local_probing() {
    use snac_rs::{
        mdns::{
            tsr::{attach, OPTION_CODE},
            wire::Datagram,
            Engine,
        },
        time::ScriptedRandom,
    };
    for goodbye in [false, true] {
        let mut e = Engine::default();
        let mut rng = ScriptedRandom::new([]);
        let records = vec![record("host.local.", 1)];
        e.register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
            .unwrap();
        let mut m = Message::new(0, if goodbye { 0x8400 } else { 0 });
        if goodbye {
            m.answers = records.clone();
            m.answers[0].ttl = 0;
        } else {
            m.additional = records.clone();
        }
        attach(&mut m, OPTION_CODE, 0, &|n| {
            stamps(&records, 0).get(n).copied()
        })
        .unwrap();
        e.receive(
            &Datagram {
                source: "[fe80::2]:5353".parse().unwrap(),
                destination: "[ff02::fb]:5353".parse().unwrap(),
                message: m,
            },
            true,
            &|_, _| records.clone(),
            0,
            &mut rng,
        )
        .unwrap();
        let b = e
            .publisher
            .poll(&|_, _| records.clone(), 0)
            .unwrap()
            .expect("only actual peer probes/live announcements suppress probing");
        assert!(!b.messages[0].authority.is_empty());
    }
}
#[test]
fn s14_srp_admission_reserves_tsr_and_probe_overhead_before_durable_success() {
    use snac_rs::{
        mdns::advertise::Mapping,
        srp::{
            service::Registrar,
            wire::{CryptoBudget, Error, Validator},
        },
    };
    let mut m = common::srp::update();
    let txt = m.authority.iter_mut().find(|r| r.kind == 16).unwrap();
    txt.data = Rdata::Txt(vec![vec![]]);
    let mapping = Mapping::new(m.questions[0].name.clone(), &[0; 8]).unwrap();
    let mut single = Message::new(0, 0x8400);
    single.answers.push(mapping.rewrite(txt).unwrap().unwrap());
    let overhead = single.encode_context(Context::Mdns).unwrap().len() - 1;
    let length = 8930 - overhead;
    let mut chunks = vec![vec![b'x'; 255]; length / 256];
    if length % 256 != 0 {
        chunks.push(vec![b'x'; length % 256 - 1]);
    }
    txt.data = Rdata::Txt(chunks);
    let u = Validator::new(&[])
        .unwrap()
        .verify(
            &common::srp::sign(m),
            common::srp::NOW,
            &mut CryptoBudget::default(),
            |_| None,
        )
        .unwrap();
    let store = common::srp::Store::default();
    let mut registrar = Registrar::open(Box::new(store.clone()), 0, common::srp::NOW).unwrap();
    assert_eq!(
        registrar.apply(&u, 0, common::srp::NOW),
        Err(Error::ServFail)
    );
    assert!(store.bytes.borrow().is_none());
    assert_eq!(registrar.registry().counts(), (0, 0, 0));
}
#[test]
fn s14_expired_full_publication_table_admits_new_host_before_the_next_sync() {
    use snac_rs::{
        mdns::Engine,
        srp::{
            registry::LeasePolicy,
            service::Registrar,
            wire::{CryptoBudget, Validator},
        },
        time::ScriptedRandom,
    };
    let mut registrar = Registrar::open(
        Box::new(snac_rs::persist::MemoryStore::default()),
        0,
        common::srp::NOW,
    )
    .unwrap();
    registrar
        .set_policy(LeasePolicy {
            max_lease: 10,
            max_key_lease: 20,
            ..LeasePolicy::default()
        })
        .unwrap();
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let make = |label: &str| {
        let name: Name = format!("{label}.default.service.arpa.").parse().unwrap();
        let mut m = common::srp::update();
        m.authority.truncate(3);
        for r in &mut m.authority {
            r.name = name.clone();
        }
        if let Rdata::Sig { signer, .. } = &mut m.additional.last_mut().unwrap().data {
            *signer = name;
        }
        Validator::new(&[])
            .unwrap()
            .verify(
                &common::srp::sign(m),
                common::srp::NOW,
                &mut CryptoBudget::default(),
                |_| None,
            )
            .unwrap()
    };
    for i in 0..128 {
        registrar
            .apply(&make(&format!("host{i}")), 0, common::srp::NOW)
            .unwrap();
    }
    registrar
        .sync_advertising(&mut engine, 0, &mut rng)
        .unwrap();
    assert_eq!(registrar.advertising_counts().0, 128);
    registrar
        .apply(&make("new"), 21000, common::srp::NOW + 21)
        .unwrap();
    registrar
        .sync_advertising(&mut engine, 21000, &mut rng)
        .unwrap();
    assert_eq!(registrar.advertising_counts().0, 1);
    assert_eq!(engine.publisher.counts().0, 1);
}

#[test]
fn s14_legacy_unicast_reply_to_a_stamped_publication_keeps_ordinary_dns_limits() {
    use snac_rs::{
        mdns::{wire::Datagram, Engine},
        time::ScriptedRandom,
    };
    let mut engine = Engine::default();
    let mut rng = ScriptedRandom::new([]);
    let records = vec![record("host.local.", 1)];
    engine
        .register_tsr(1, (&[], &records), &stamps(&records, 0), 0, &mut rng)
        .unwrap();
    for at in [0, 250, 500, 750, 1750] {
        let b = engine
            .publisher
            .poll(&|_, _| records.clone(), at)
            .unwrap()
            .unwrap();
        engine.publisher.sent(b.token, true, at);
    }
    let mut m = Message::new(55, 0);
    m.questions.push(Question {
        name: records[0].name.clone(),
        kind: 1,
        class: 1,
    });
    engine
        .receive(
            &Datagram {
                source: "[fe80::2]:40000".parse().unwrap(),
                destination: "[ff02::fb]:5353".parse().unwrap(),
                message: m,
            },
            true,
            &|_, _| records.clone(),
            3000,
            &mut rng,
        )
        .unwrap();
    let b = engine
        .responder
        .poll(&engine.publisher, &|_, _| records.clone(), 3000)
        .unwrap()
        .unwrap();
    assert_eq!(b.destination.port(), 40000);
    let output = engine.prepare_outgoing(b.messages, 3000).unwrap();
    assert_eq!(output[0].id, 55);
    assert_eq!(output[0].questions.len(), 1);
    assert!(output[0]
        .answers
        .iter()
        .all(|r| r.class == 1 && r.ttl <= 10));
    assert!(
        output[0].additional.iter().all(|r| r.kind != 41),
        "legacy request did not negotiate EDNS"
    );
    assert!(output[0].encode().unwrap().len() <= 512);
}
