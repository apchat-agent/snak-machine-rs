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
