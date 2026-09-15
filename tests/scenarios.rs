mod common;
use common::*;
use snac_rs::{
    scheduler::RaScheduler,
    time::{ManualClock, ScriptedRandom},
};
#[test]
fn ra_scheduler_honors_random_delay_and_spacing() {
    let mut rng = ScriptedRandom::new([0, 16000, 0, 0, 52000]);
    let mut clock = ManualClock::default();
    let mut s = RaScheduler::new(0, &mut rng).unwrap();
    assert_eq!(s.deadline(), 0);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 16000);
    clock.advance(16000);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 19000);
    clock.advance(3000);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 173000);
    clock.advance(154000);
    s.sent(clock.now(), &mut rng).unwrap();
    assert_eq!(s.deadline(), 379000);
    let mut zero = ScriptedRandom::new([0, 0]);
    s.changed(clock.now(), &mut zero).unwrap();
    assert_eq!(s.deadline(), 176000);
    assert!(!s.due(175999));
    assert!(s.due(176000));
}

use snac_rs::{
    wire::{envelope, Advertisement, FrameKind, Pio, Prefix},
    Link,
};
#[test]
fn solicitations_coalesce_without_postponement() {
    let mut rng = ScriptedRandom::new([16000, 500, 0]);
    let mut s = RaScheduler::new(0, &mut rng).unwrap();
    let first = nd_packet("fe80::22", "ff02::2", vec![133, 0, 0, 0, 0, 0, 0, 0]);
    let second = nd_packet("::", "ff02::2", vec![133, 0, 0, 0, 0, 0, 0, 0]);
    s.receive_rs(
        &envelope(FrameKind::RawIpv6, &first).unwrap(),
        1000,
        &mut rng,
    )
    .unwrap();
    assert_eq!(s.deadline(), 1500);
    s.receive_rs(
        &envelope(FrameKind::RawIpv6, &second).unwrap(),
        1300,
        &mut rng,
    )
    .unwrap();
    assert_eq!(s.deadline(), 1500);
    let snapshot = Advertisement {
        link: Link::Stub,
        source: ip("fe80::1"),
        destination: ip("ff02::1"),
        mac: None,
        mtu: 1500,
        mo: 0,
        default_lifetime: 0,
        pios: vec![Pio::decode(&pio("fd00:1::", 64, 0xc0, 1800, 1800)).unwrap()],
        rios: vec![],
    };
    let mut sent = vec![];
    for now in [1499, 1500, 1501, 4499] {
        if s.due(now) {
            sent.push((snapshot.link, snapshot.encode().unwrap()));
            s.sent(now, &mut rng).unwrap();
        }
    }
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, Link::Stub);
    assert_eq!(&sent[0].1[24..40], &ip("ff02::1").octets());
    assert_eq!(&sent[0].1[64..], &pio("fd00:1::", 64, 0xc0, 1800, 1800));
}
