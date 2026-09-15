use snac_rs::dns::wire::{Context, Message, Name, Rdata, TcpFrames};
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
        (43, vec![0, 1, 13, 2, 1, 2]),
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
