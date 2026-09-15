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
