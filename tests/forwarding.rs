mod common;
use common::*;
use snac_rs::{
    persist::{Identity, MemoryStore},
    router::{Neighbor, NeighborState, Route, Router, RouterKey},
    time::Lifetime,
    time::ScriptedRandom,
    wire::{FrameKind, Preference, Prefix},
    Link,
};
fn router() -> Router {
    let id = Identity::load_or_create(
        &mut MemoryStore::default(),
        "forward",
        &mut ScriptedRandom::new([55, 1, 2, 3, 4, 5, 6]),
    )
    .unwrap();
    let mut r = Router::new(id, 0, &mut ScriptedRandom::new([])).unwrap();
    let mut rng = ScriptedRandom::new([]);
    for tx in r.tick(9000, &mut rng).unwrap() {
        r.transmitted(&tx, 9000, true, &mut rng).unwrap();
    }
    r
}
fn prime(r: &mut Router, link: Link, address: &str, mac: [u8; 6]) {
    r.neighbors.insert(
        RouterKey {
            link,
            address: ip(address),
        },
        Neighbor {
            mac: Some(mac),
            state: NeighborState::Reachable,
            deadline: Some(70000),
            probes_sent: 0,
            is_router: true,
            pending: None,
        },
    );
}
fn ethernet(source: [u8; 6], destination: [u8; 6], packet: &[u8]) -> Vec<u8> {
    let mut f = destination.to_vec();
    f.extend(source);
    f.extend([0x86, 0xdd]);
    f.extend(packet);
    f
}
#[test]
fn forwarding_uses_egress_next_hop_and_decrements_once() {
    let mut r = router();
    let target =
        std::net::Ipv6Addr::from(u128::from(r.identity.prefix(Link::Stub).address) | 0xabcd)
            .to_string();
    prime(&mut r, Link::Stub, &target, [2, 0, 0, 0, 0, 11]);
    prime(&mut r, Link::Ail, "fe80::9", [2, 0, 0, 0, 0, 22]);
    r.routes.insert(
        (ip("fe80::9"), Prefix::new(ip("fd99::"), 64).unwrap()),
        Route {
            valid: Lifetime::from_secs(10000, 900),
            preference: Preference::Low,
        },
    );
    for (ingress, destination, mac) in [
        (Link::Ail, target.as_str(), [2, 0, 0, 0, 0, 11]),
        (Link::Stub, "fd99::1234", [2, 0, 0, 0, 0, 22]),
    ] {
        let packet = packet("fd88::1234", destination, 17, 64, &[7, 6, 5, 4, 3, 2, 1, 0]);
        let frame = ethernet(
            [2, 0, 0, 0, 0, 33],
            r.identity.macs[ingress.index()],
            &packet,
        );
        let tx = r
            .receive_frame(
                ingress,
                FrameKind::Ethernet,
                &frame,
                10000,
                &mut ScriptedRandom::new([]),
            )
            .unwrap();
        assert_eq!(tx.len(), 1);
        assert_eq!(tx[0].link, ingress.other());
        let sent = r.encapsulate(&tx[0], FrameKind::Ethernet, 10000).unwrap();
        assert_eq!(&sent[..6], &mac);
        assert_eq!(&sent[6..12], &r.identity.macs[ingress.other().index()]);
        assert_eq!(sent[21], 63);
        assert_eq!(&sent[54..], &packet[40..]);
    }
}

#[test]
fn forwarding_errors_have_correct_scope_and_mtu() {
    for (hop, size, route, kind, code) in [
        (1, 8, true, 3, 0),
        (64, 1600, true, 2, 0),
        (64, 8, false, 1, 0),
    ] {
        let mut r = router();
        let mut rng = ScriptedRandom::new([]);
        let source = r
            .identity
            .address(Link::Stub, r.identity.prefix(Link::Stub));
        r.begin_dad(Link::Stub, source, 9000);
        r.tick(10000, &mut rng).unwrap();
        prime(&mut r, Link::Ail, "fe80::9", [2, 0, 0, 0, 0, 22]);
        if route {
            r.routes.insert(
                (ip("fe80::9"), Prefix::new(ip("::"), 0).unwrap()),
                Route {
                    valid: Lifetime::from_secs(10000, 900),
                    preference: Preference::Medium,
                },
            );
        }
        let p = packet("fd88::1234", "2001:db8::1234", 17, hop, &vec![7; size]);
        let out = r
            .receive_frame(Link::Stub, FrameKind::RawIpv6, &p, 20000, &mut rng)
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].link, Link::Stub);
        assert_eq!((out[0].packet[40], out[0].packet[41]), (kind, code));
        assert_eq!(sum(source, ip("fd88::1234"), 58, &out[0].packet[40..]), 0);
        assert!(out[0].packet.len() <= 1280);
        if kind == 2 {
            assert_eq!(&out[0].packet[44..48], &1500u32.to_be_bytes());
        }
    }
    let mut r = router();
    let mut rng = ScriptedRandom::new([]);
    let target = std::net::Ipv6Addr::from(u128::from(r.identity.prefix(Link::Stub).address) | 77)
        .to_string();
    for (source, dest) in [
        ("fe80::55", target.as_str()),
        ("fd88::1", "ff02::fb"),
        ("::", target.as_str()),
        ("ff02::1", target.as_str()),
        ("fd88::1", "fe80::55"),
    ] {
        let p = packet(source, dest, 17, 64, &[0; 8]);
        assert!(r
            .receive_frame(Link::Ail, FrameKind::RawIpv6, &p, 20000, &mut rng)
            .unwrap()
            .is_empty());
    }
    let local = packet("fd88::1", &target, 17, 64, &[0; 8]);
    assert!(r
        .receive_frame(Link::Stub, FrameKind::RawIpv6, &local, 21000, &mut rng)
        .unwrap()
        .is_empty());
    let p = packet("fd88::1", &target, 17, 64, &[7; 8]);
    let out = r
        .receive_frame(
            Link::Ail,
            FrameKind::Ethernet,
            &ethernet([2, 0, 0, 0, 0, 1], r.identity.macs[0], &p),
            22000,
            &mut rng,
        )
        .unwrap();
    assert_eq!(out[0].packet[40], 135);
    assert!(r.neighbors.values().any(|n| n.pending.is_some()));
    let source = r.identity.address(Link::Ail, r.identity.prefix(Link::Ail));
    r.begin_dad(Link::Ail, source, 22000);
    let mut errors = vec![];
    for now in [23000, 24000, 25000] {
        errors.extend(r.tick(now, &mut rng).unwrap());
    }
    assert!(errors
        .iter()
        .any(|x| x.packet[40] == 1 && x.packet[41] == 3));
    // Valid transit fragments retain their payload, without reassembly.
    prime(&mut r, Link::Stub, &target, [2, 0, 0, 0, 0, 11]);
    let mut fragment = vec![17, 0, 0, 9, 0, 0, 0, 7];
    fragment.extend([3; 24]);
    let p = packet("fd88::1", &target, 44, 5, &fragment);
    let out = r
        .receive_frame(Link::Ail, FrameKind::RawIpv6, &p, 26000, &mut rng)
        .unwrap();
    assert_eq!(out[0].packet[7], 4);
    assert_eq!(&out[0].packet[40..], &fragment);
}
