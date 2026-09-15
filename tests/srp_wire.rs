mod common;
use snac_rs::{
    dns::wire::{Context, Message, Rdata},
    srp::wire::{CryptoBudget, Error, Validator},
};
const NOW: u64 = 1789473600;
const A13: &[u8] = include_bytes!("fixtures/srp/alg13.bin");
fn validator() -> Validator {
    Validator::new(&["srp.test.".parse().unwrap()]).unwrap()
}
#[test]
fn s11_independent_signatures_all_algorithms_compression_and_subtypes() {
    for (alg, b) in [
        (13, A13),
        (14, include_bytes!("fixtures/srp/alg14.bin").as_slice()),
        (15, include_bytes!("fixtures/srp/alg15.bin").as_slice()),
        (16, include_bytes!("fixtures/srp/alg16.bin").as_slice()),
    ] {
        let u = validator()
            .verify(b, NOW, &mut CryptoBudget::default(), |_| None)
            .unwrap();
        assert_eq!(u.key.algorithm, alg);
        assert_eq!(u.host, "host.default.service.arpa.".parse().unwrap());
        assert_eq!((u.lease, u.key_lease), (7200, 1209600));
        assert_eq!(u.addresses.len(), 1);
        assert_eq!(u.services.len(), 1);
        assert_eq!(u.services[0].discovery.len(), 2);
        assert_eq!(u.services[0].records.len(), 2);
        assert!(!u.services[0].deleted);
        assert_eq!(u.id, 0x1234);
        let mut corrupt = b.to_vec();
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            validator()
                .verify(&corrupt, NOW, &mut CryptoBudget::default(), |_| None)
                .unwrap_err(),
            Error::Refused
        );
    }
}
#[test]
fn s11_flags_and_leases_and_zero_time_constrained_clients() {
    let v = validator();
    let mut jobs = CryptoBudget::default();
    let a = v.verify(A13, NOW, &mut jobs, |_| None).unwrap();
    let b = v
        .verify(
            include_bytes!("fixtures/srp/alg13-flags.bin"),
            NOW,
            &mut jobs,
            |_| None,
        )
        .unwrap();
    assert_eq!(b.key.flags, 65535);
    assert!(a.key.same_public_key(&b.key));
    let short = v
        .verify(
            include_bytes!("fixtures/srp/alg13-short_lease.bin"),
            NOW,
            &mut jobs,
            |_| None,
        )
        .unwrap();
    assert_eq!((short.lease, short.key_lease), (7200, 7200));
    v.verify(
        include_bytes!("fixtures/srp/alg13-zero_time.bin"),
        NOW,
        &mut jobs,
        |_| None,
    )
    .unwrap();
    for b in [
        include_bytes!("fixtures/srp/alg13-remove.bin").as_slice(),
        include_bytes!("fixtures/srp/alg13-delete_key.bin").as_slice(),
    ] {
        let u = v
            .verify(b, NOW, &mut jobs, |n| (n == &a.host).then(|| a.key.clone()))
            .unwrap();
        assert_eq!(u.lease, 0);
        assert_eq!(u.key_lease, 1209600);
        assert!(u.addresses.is_empty());
        assert!(u.services.is_empty());
    }
    assert!(v
        .verify(
            include_bytes!("fixtures/srp/alg13-remove.bin"),
            NOW,
            &mut CryptoBudget::default(),
            |_| None
        )
        .is_err());
    assert_eq!(
        v.verify(A13, NOW + 301, &mut CryptoBudget::default(), |_| None)
            .unwrap_err(),
        Error::Refused
    );
    assert_eq!(
        v.verify(A13, NOW - 301, &mut CryptoBudget::default(), |_| None)
            .unwrap_err(),
        Error::Refused
    );
}
#[test]
fn s11_truncations_wire_mutations_and_zone_and_crypto_caps() {
    let v = validator();
    for end in 0..A13.len() {
        assert!(
            v.verify(&A13[..end], NOW, &mut CryptoBudget::default(), |_| None)
                .is_err(),
            "prefix {end}"
        );
    }
    // All bytes covered by SIG(0), including original compressed names/counts.
    let m = Message::parse(A13, Context::Unicast).unwrap();
    let end = m.record_spans().last().unwrap().wire.start;
    for at in 0..end {
        let mut b = A13.to_vec();
        b[at] ^= 1;
        assert!(
            v.verify(&b, NOW, &mut CryptoBudget::default(), |_| None)
                .is_err(),
            "byte {at}"
        );
    }
    let mut budget = CryptoBudget::default();
    for _ in 0..8 {
        v.verify(A13, NOW, &mut budget, |_| None).unwrap();
    }
    assert_eq!(budget.remaining(), 0);
    assert_eq!(
        v.verify(A13, NOW, &mut budget, |_| None).unwrap_err(),
        Error::ServFail
    );
    let zones: Vec<_> = (0..8)
        .map(|n| format!("z{n}.test.").parse().unwrap())
        .collect();
    assert!(Validator::new(&zones).is_ok());
    let mut too_many = zones;
    too_many.push("ninth.test.".parse().unwrap());
    assert!(Validator::new(&too_many).is_err());
    assert!(Validator::new(&[".".parse().unwrap()]).is_err());
    let mut wrong_zone = Message::parse(A13, Context::Unicast).unwrap();
    wrong_zone.questions[0].name = "outside.test.".parse().unwrap();
    assert_eq!(
        v.verify(
            &wrong_zone.encode().unwrap(),
            NOW,
            &mut CryptoBudget::default(),
            |_| None
        )
        .unwrap_err(),
        Error::NotAuth
    );
    // No signature data is interpreted as a general-purpose DNS update.
    let mut no_sig = Message::parse(A13, Context::Unicast).unwrap();
    no_sig.additional.pop();
    assert_eq!(
        v.verify(
            &no_sig.encode().unwrap(),
            NOW,
            &mut CryptoBudget::default(),
            |_| None
        )
        .unwrap_err(),
        Error::Refused
    );
    assert!(matches!(
        m.additional.last().unwrap().data,
        Rdata::Sig { .. }
    ));
}

#[test]
fn s11_valid_signatures_do_not_bypass_update_semantics() {
    use common::srp::{sign, update};
    let mut cases = vec![];
    let m = update();
    let host = m.authority[0].name.clone();
    let mut b = m.clone();
    b.answers.push(b.authority[0].clone());
    cases.push(b);
    let mut b = m.clone();
    b.authority.remove(0);
    cases.push(b);
    let mut b = m.clone();
    b.authority.swap(0, 1);
    cases.push(b);
    let mut b = m.clone();
    b.authority.insert(0, b.authority[0].clone());
    cases.push(b);
    let mut b = m.clone();
    b.authority[1].class = 254;
    cases.push(b);
    let mut b = m.clone();
    b.authority[2].name = "second.default.service.arpa.".parse().unwrap();
    cases.push(b);
    let mut b = m.clone();
    b.authority[4].data = Rdata::Srv {
        priority: 0,
        weight: 0,
        port: 1,
        target: "other.default.service.arpa.".parse().unwrap(),
    };
    cases.push(b);
    let mut b = m.clone();
    b.authority.remove(5);
    cases.push(b); // SRV without TXT
    let mut b = m.clone();
    b.authority.insert(5, b.authority[4].clone());
    cases.push(b);
    let mut b = m.clone();
    b.authority[6].data = Rdata::Name(host.clone());
    cases.push(b);
    let mut b = m.clone();
    b.authority[0].ttl = 1;
    cases.push(b);
    let mut b = m.clone();
    b.authority[0].data = Rdata::Bytes(vec![0]);
    cases.push(b);
    let mut b = m.clone();
    b.authority[2].kind = 5;
    b.authority[2].data = Rdata::Name(host.clone());
    cases.push(b);
    let mut b = m.clone();
    if let Rdata::Key { protocol, .. } = &mut b.authority[1].data {
        *protocol = 2;
    }
    cases.push(b);
    let mut b = m.clone();
    if let Rdata::Key { key, .. } = &mut b.authority[1].data {
        key.pop();
    }
    cases.push(b);
    let mut b = m.clone();
    if let Rdata::Key { algorithm, .. } = &mut b.authority[1].data {
        *algorithm = 12;
    }
    cases.push(b);
    let mut b = m.clone();
    let mut k = b.authority[1].clone();
    k.name = b.authority[3].name.clone();
    if let Rdata::Key { flags, .. } = &mut k.data {
        *flags = 1;
    }
    b.authority.push(k);
    cases.push(b);
    for n in [0, 3, 5, 7, 9] {
        let mut b = m.clone();
        b.additional[0].data = Rdata::Opt(vec![(2, vec![0; n])]);
        cases.push(b);
    }
    let mut b = m.clone();
    b.additional[0].data = Rdata::Opt(vec![(
        2,
        [7200u32.to_be_bytes(), 1u32.to_be_bytes()].concat(),
    )]);
    cases.push(b);
    let mut b = m.clone();
    b.additional[0].data = Rdata::Opt(vec![(2, vec![0; 8]), (2, vec![0; 8])]);
    cases.push(b);
    let mut b = m.clone();
    b.additional[0].data = Rdata::Opt(vec![]);
    cases.push(b);
    let mut b = m.clone();
    b.authority.push({
        let mut r = b.authority[2].clone();
        r.ttl += 1;
        r
    });
    cases.push(b); // independent valid signature, inconsistent RRset TTL
    for (i, bad) in cases.into_iter().enumerate() {
        let mut jobs = CryptoBudget::default();
        assert_eq!(
            validator()
                .verify(&sign(bad), NOW, &mut jobs, |_| None)
                .unwrap_err(),
            Error::Refused,
            "case {i}"
        );
        assert_eq!(
            jobs.remaining(),
            8,
            "structural rejection before crypto: {i}"
        );
    }
}
#[test]
fn s11_signed_service_replacement_deletion_and_instruction_bounds() {
    use common::srp::{sign, update};
    let mut replacement = update();
    let mut del = replacement.authority[6].clone();
    del.class = 254;
    del.ttl = 0;
    replacement.authority.insert(6, del);
    let u = validator()
        .verify(
            &sign(replacement),
            NOW,
            &mut CryptoBudget::default(),
            |_| None,
        )
        .unwrap();
    assert_eq!(u.services[0].discovery.len(), 2);
    let mut remove = update();
    remove.authority.retain(|r| ![33, 16, 12].contains(&r.kind));
    let u = validator()
        .verify(&sign(remove), NOW, &mut CryptoBudget::default(), |_| None)
        .unwrap();
    assert!(u.services[0].deleted);
    let mut large = update();
    large.authority.truncate(3);
    let address = large.authority[2].clone();
    for n in 1..254u16 {
        let mut a = address.clone();
        if let Rdata::Aaaa(ip) = &mut a.data {
            ip[14..].copy_from_slice(&n.to_be_bytes());
        }
        large.authority.push(a);
    }
    assert_eq!(large.authority.len(), 256);
    validator()
        .verify(
            &sign(large.clone()),
            NOW,
            &mut CryptoBudget::default(),
            |_| None,
        )
        .unwrap();
    large.authority.push(address);
    assert_eq!(
        validator()
            .verify(&sign(large), NOW, &mut CryptoBudget::default(), |_| None)
            .unwrap_err(),
        Error::ServFail
    );
    let mut groups = update();
    groups.authority.truncate(3);
    for n in 0..8 {
        let mut deletion = groups.authority[0].clone();
        deletion.name = format!("n{n}._http._tcp.default.service.arpa.")
            .parse()
            .unwrap();
        groups.authority.push(deletion);
    }
    validator()
        .verify(
            &sign(groups.clone()),
            NOW,
            &mut CryptoBudget::default(),
            |_| None,
        )
        .unwrap();
    let mut extra = groups.authority[0].clone();
    extra.name = "n9._http._tcp.default.service.arpa.".parse().unwrap();
    groups.authority.push(extra);
    assert_eq!(
        validator()
            .verify(&sign(groups), NOW, &mut CryptoBudget::default(), |_| None)
            .unwrap_err(),
        Error::ServFail
    );
}
