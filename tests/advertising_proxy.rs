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
