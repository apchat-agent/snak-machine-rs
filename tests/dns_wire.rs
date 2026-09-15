use snac_rs::dns::wire::{Context, Message, Name, Question, Rdata, Record, TcpFrames};
fn query() -> Vec<u8> {
    b"\x12\x34\x01\x00\0\x01\0\0\0\0\0\0\x03WwW\x07example\x03com\0\0\x1c\0\x01".to_vec()
}
fn rr(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut b = vec![0xc0, 12];
    b.extend(kind.to_be_bytes());
    b.extend([0, 1, 0, 0, 0, 60]);
    b.extend((data.len() as u16).to_be_bytes());
    b.extend(data);
    b
}
fn answer(kind: u16, data: &[u8]) -> Vec<u8> {
    let mut b = query();
    b[2] = 0x81;
    b[3] = 0x80;
    b[7] = 1;
    b.extend(rr(kind, data));
    b
}
#[test]
fn s08_literal_names_records_and_original_wire() {
    let q = query();
    let m = Message::parse(&q, Context::Unicast).unwrap();
    assert_eq!(m.id, 0x1234);
    assert_eq!(m.questions[0].name.labels()[0], b"WwW");
    assert_eq!(
        m.questions[0].name,
        Name::from_labels(vec![b"www".to_vec(), b"EXAMPLE".to_vec(), b"com".to_vec()]).unwrap()
    );
    assert_eq!(m.encode().unwrap(), q);
    assert_eq!(m.original(), q);
    let mut binary = query();
    binary[13..16].copy_from_slice(&[0xff, 0, b'A']);
    assert_eq!(
        Message::parse(&binary, Context::Unicast)
            .unwrap()
            .encode()
            .unwrap(),
        binary
    );
    let a = answer(1, &[192, 0, 2, 9]);
    let m = Message::parse(&a, Context::Unicast).unwrap();
    assert_eq!(m.answers[0].data, Rdata::A([192, 0, 2, 9]));
    assert_eq!(m.original(), a);
    let b = m.encode().unwrap();
    assert_eq!(
        Message::parse(&b, Context::Unicast).unwrap().answers,
        m.answers
    );
    for (kind, data) in [
        (28, vec![42; 16]),
        (12, vec![0xc0, 12]),
        (5, vec![0xc0, 12]),
        (2, vec![0xc0, 12]),
        (39, vec![1, b'x', 0]),
        (16, vec![0, 3, 0xff, 0, b'a']),
        (25, vec![0, 0, 3, 13, 1, 2]),
        (48, vec![1, 0, 3, 13, 1, 2]),
        (43, [vec![0, 1, 13, 2], vec![9; 32]].concat()),
    ] {
        let m = Message::parse(&answer(kind, &data), Context::Unicast).unwrap();
        assert_eq!(
            Message::parse(&m.encode().unwrap(), Context::Unicast)
                .unwrap()
                .answers,
            m.answers
        );
    }
    let mut soa = vec![0xc0, 12, 0xc0, 16];
    soa.extend([0, 0, 0, 1].repeat(5));
    assert!(matches!(
        Message::parse(&answer(6, &soa), Context::Unicast)
            .unwrap()
            .answers[0]
            .data,
        Rdata::Soa { .. }
    ));
}
#[test]
fn s08_signed_updates_srv_context_and_opaque_provenance() {
    let srv = [0, 0, 0, 0, 0, 80, 0xc0, 12];
    assert!(Message::parse(&answer(33, &srv), Context::Unicast).is_err());
    assert!(Message::parse(&answer(33, &srv), Context::Mdns).is_ok());
    let mut update = answer(33, &srv);
    update[2] = 0x28;
    update[3] = 0;
    assert!(Message::parse(&update, Context::Unicast).is_ok());
    let mut sig = vec![0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2];
    sig.extend(b"\x03WwW\x07example\x03com\0");
    sig.extend([42; 64]);
    update[11] = 1;
    update.extend(rr(24, &sig));
    let m = Message::parse(&update, Context::Unicast).unwrap();
    assert_eq!(m.original(), update);
    assert!(matches!(m.additional[0].data, Rdata::Sig { .. }));
    let unknown = answer(65200, &[0xc0, 12, 99]);
    let m = Message::parse(&unknown, Context::Unicast).unwrap();
    assert_eq!(m.original(), unknown);
    assert!(
        m.encode().is_err(),
        "opaque legacy compression cannot be moved"
    );
}
#[test]
fn s08_edns_nsec_svcb_and_dnssec() {
    let mut b = query();
    b[11] = 1;
    b.extend([0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 8, 0, 2, 0, 4, 1, 2, 3, 4]);
    let m = Message::parse(&b, Context::Unicast).unwrap();
    assert!(matches!(m.additional[0].data, Rdata::Opt(_)));
    assert_eq!(m.encode().unwrap(), b);
    for (kind, data) in [
        (47, vec![0, 0, 4, 0x40, 0, 0, 8]),
        (50, vec![1, 0, 0, 0, 0, 1, 9, 0, 1, 0x40]),
        (51, vec![1, 0, 0, 0, 0]),
        (64, vec![0, 1, 0, 0, 3, 0, 2, 3, 85]),
        (65, vec![0, 0, 1, b'x', 0]),
    ] {
        let m = Message::parse(&answer(kind, &data), Context::Unicast).unwrap();
        assert_eq!(
            Message::parse(&m.encode().unwrap(), Context::Unicast)
                .unwrap()
                .answers,
            m.answers
        );
    }
    let mut sig = vec![0, 1, 13, 3, 0, 0, 0, 60, 0, 0, 0, 1, 0, 0, 0, 0, 1, 2, 0];
    sig.extend([9; 64]);
    assert!(Message::parse(&answer(46, &sig), Context::Unicast).is_ok());
}
#[test]
fn s08_hostile_lengths_pointers_and_fixed_work_mutations() {
    let good = answer(1, &[192, 0, 2, 1]);
    for end in 0..good.len() {
        assert!(
            Message::parse(&good[..end], Context::Unicast).is_err(),
            "truncation {end}"
        );
    }
    for (offset, value) in [
        (12, 64),
        (12, 0x80),
        (12, 0xc0),
        (4, 255),
        (5, 255),
        (6, 255),
        (good.len() - 5, 255),
    ] {
        let mut b = good.clone();
        b[offset] = value;
        assert!(
            Message::parse(&b, Context::Unicast).is_err(),
            "offset {offset}"
        );
    }
    // A pointer into label content, a forward reference, and a self reference.
    for target in [13, 35, 33] {
        let mut b = good.clone();
        b[34] = target;
        assert!(Message::parse(&b, Context::Unicast).is_err());
    }
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(Message::parse(&trailing, Context::Unicast).is_err());
    assert!(Name::from_labels(vec![vec![0; 64]]).is_err());
    assert!(Name::from_labels(vec![vec![0; 63]; 4]).is_err());
    for offset in 0..good.len() {
        for byte in 0..=255 {
            let mut b = good.clone();
            b[offset] = byte;
            let _ = Message::parse(&b, Context::Unicast);
        }
    }
    assert!(Message::parse(&vec![0; 65536], Context::Unicast).is_err());
}
#[test]
fn s08_hostile_record_structures_and_opt_location() {
    for (kind, data) in [
        (1, vec![0; 3]),
        (28, vec![0; 15]),
        (16, vec![4, 1]),
        (6, vec![0, 0]),
        (25, vec![0; 3]),
        (24, vec![0; 18]),
        (47, vec![0, 0, 0]),
        (47, vec![0, 0, 1, 0]),
        (47, vec![0, 1, 1, 0x80, 0, 1, 0x80]),
        (64, vec![0, 1, 0, 0, 3, 0, 1, 1]),
        (64, vec![0, 1, 0, 0, 3, 0, 2, 3, 85, 0, 3, 0, 2, 3, 85]),
        (64, vec![0, 1, 0, 0, 4, 0, 3, 1, 2, 3]),
        (64, vec![0, 1, 0, 0, 0, 0, 2, 0, 3]),
        (50, vec![1, 0, 0, 0, 255]),
        (51, vec![1, 0, 0, 0, 0, 1]),
    ] {
        assert!(
            Message::parse(&answer(kind, &data), Context::Unicast).is_err(),
            "type {kind} data {data:?}"
        );
    }
    assert!(Message::parse(&answer(41, &[]), Context::Unicast).is_err());
    for data in [vec![0, 1, 0], vec![0, 1, 0, 2, 1]] {
        let mut b = query();
        b[11] = 1;
        b.extend([0, 0, 41, 4, 208, 0, 0, 0, 0]);
        b.extend((data.len() as u16).to_be_bytes());
        b.extend(data);
        assert!(Message::parse(&b, Context::Unicast).is_err());
    }
}
#[test]
fn s08_tcp_split_coalesced_and_frame_queue_caps() {
    let q = query();
    let framed = TcpFrames::frame(&q).unwrap();
    let mut f = TcpFrames::new(65535).unwrap();
    for b in &framed[..framed.len() - 1] {
        f.input(&[*b]).unwrap();
        assert!(f.pop().is_none());
    }
    f.input(&framed[framed.len() - 1..]).unwrap();
    assert_eq!(f.pop().unwrap(), q);
    f.input(&framed.repeat(3)).unwrap();
    for _ in 0..3 {
        assert_eq!(f.pop().unwrap(), q);
    }
    let mut small = TcpFrames::new(512).unwrap();
    assert!(small.input(&[2, 1]).is_err());
    assert_eq!(small.buffered(), 0);
    assert!(TcpFrames::frame(&vec![0; 65536]).is_err());
    assert!(TcpFrames::frame(&[0; 11]).is_err());
    let mut f = TcpFrames::new(65535).unwrap();
    for _ in 0..32 {
        f.input(&framed).unwrap();
    }
    assert!(f.input(&framed).is_err());
    assert!(f.buffered() <= 65537);
    let huge = TcpFrames::frame(&vec![0; 65535]).unwrap();
    let mut f = TcpFrames::new(65535).unwrap();
    f.input(&huge).unwrap();
    assert!(f.input(&framed).is_err());
    assert_eq!(f.pop().unwrap().len(), 65535);
    assert_eq!(f.buffered(), 0);
}

#[test]
fn s08_dnssec_digest_lengths_and_cdnskey_are_relocatable() {
    for (digest, n) in [(1, 20), (2, 32), (4, 48)] {
        let mut data = vec![0, 1, 13, digest];
        data.extend(vec![9; n]);
        assert!(Message::parse(&answer(43, &data), Context::Unicast).is_ok());
        data.pop();
        assert!(Message::parse(&answer(43, &data), Context::Unicast).is_err());
    }
    let m = Message::parse(&answer(60, &[1, 0, 3, 13, 1, 2]), Context::Unicast).unwrap();
    assert!(m.encode().is_ok(), "CDNSKEY is pointer-free DNSSEC data");
}
#[test]
fn s08_exact_message_table_and_compression_depth_bounds() {
    let mut b = vec![0; 12];
    b[4..6].copy_from_slice(&4096u16.to_be_bytes());
    for _ in 0..4096 {
        b.extend([0, 0, 1, 0, 1]);
    }
    assert_eq!(
        Message::parse(&b, Context::Unicast)
            .unwrap()
            .questions
            .len(),
        4096
    );
    b[4..6].copy_from_slice(&4097u16.to_be_bytes());
    b.extend([0, 0, 1, 0, 1]);
    assert!(Message::parse(&b, Context::Unicast).is_err());
    let mut b = query();
    let mut prev = 12;
    for n in 1..=65 {
        let at = b.len();
        b.extend((0xc000 | prev as u16).to_be_bytes());
        b.extend([0, 1, 0, 1]);
        b[4..6].copy_from_slice(&(n + 1u16).to_be_bytes());
        assert_eq!(
            Message::parse(&b, Context::Unicast).is_ok(),
            n <= 64,
            "depth {n}"
        );
        prev = at;
    }
    // More bounded name-decoding work than the global budget, within the wire cap.
    let mut b = vec![0; 12];
    let mut name = vec![1, b'x'];
    name = name.repeat(127);
    name.push(0);
    b.extend(name);
    b.extend([0, 1, 0, 1]);
    for _ in 0..4095 {
        b.extend([0xc0, 12, 0, 1, 0, 1]);
    }
    b[4..6].copy_from_slice(&4096u16.to_be_bytes());
    assert!(b.len() < 65535);
    assert!(Message::parse(&b, Context::Unicast).is_err());
}
#[test]
fn s08_nsec_mdns_compression_and_name_boundary_provenance() {
    let b = answer(47, &[0xc0, 12, 0, 4, 0x40, 0, 0, 8]);
    assert!(Message::parse(&b, Context::Mdns).is_ok());
    assert!(Message::parse(&b, Context::Unicast).is_err());
    let mut b = answer(65200, &[1, b'x', 0]);
    b[7] = 2;
    let start = b.len();
    b.extend([0xc0, 45, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 1]);
    assert!(start > 45);
    assert!(
        Message::parse(&b, Context::Unicast).is_err(),
        "opaque bytes never establish a name boundary"
    );
}

#[test]
fn s08_mdns_embedded_names_are_typed_for_proxy_rewriting() {
    for (kind, data) in [
        (39, vec![0xc0, 12]),
        (15, vec![0, 10, 0xc0, 12]),
        (18, vec![0, 1, 0xc0, 12]),
        (21, vec![0, 1, 0xc0, 12]),
        (36, vec![0, 1, 0xc0, 12]),
        (17, vec![0xc0, 12, 0xc0, 12]),
        (26, vec![0, 1, 0xc0, 12, 0xc0, 12]),
    ] {
        let m = Message::parse(&answer(kind, &data), Context::Mdns).unwrap();
        assert!(
            !matches!(m.answers[0].data, Rdata::Opaque(_)),
            "mDNS record {kind}"
        );
        assert!(Message::parse(&m.encode().unwrap(), Context::Unicast).is_ok());
    }
}

#[test]
fn s13_mdns_compresses_embedded_names_and_preserves_binary_labels() {
    let mut m = Message::new(0, 0x8400);
    let host: Name = "Mixed.Host.local.".parse().unwrap();
    m.questions.push(Question {
        name: host.clone(),
        kind: 255,
        class: 0x8001,
    });
    let instance = Name::from_labels(vec![
        vec![0xff, 0xc0, 0],
        b"_x".to_vec(),
        b"_tcp".to_vec(),
        b"local".to_vec(),
    ])
    .unwrap();
    m.answers.push(Record {
        name: instance.clone(),
        kind: 33,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Srv {
            priority: 0,
            weight: 0,
            port: 80,
            target: host.clone(),
        },
    });
    m.answers.push(Record {
        name: instance.clone(),
        kind: 16,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Txt(vec![vec![0xc0, 0, 255]]),
    });
    m.answers.push(Record {
        name: host.clone(),
        kind: 47,
        class: 0x8001,
        ttl: 120,
        data: Rdata::Nsec {
            next: host,
            bitmap: vec![0, 4, 0, 0, 0, 8],
        },
    });
    let plain = m.encode().unwrap();
    let compressed = m.encode_context(Context::Mdns).unwrap();
    assert!(compressed.len() + 20 < plain.len());
    let decoded = Message::parse(&compressed, Context::Mdns).unwrap();
    assert_eq!(decoded.questions, m.questions);
    assert_eq!(decoded.answers, m.answers);
    assert_eq!(decoded.answers[0].name.labels(), instance.labels());
    assert!(Message::parse(&compressed, Context::Unicast).is_err());
    for n in 0..compressed.len() {
        assert!(Message::parse(&compressed[..n], Context::Mdns).is_err());
    }
}
