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
        let sent = r.encapsulate(&tx[0], FrameKind::Ethernet).unwrap();
        assert_eq!(&sent[..6], &mac);
        assert_eq!(&sent[6..12], &r.identity.macs[ingress.other().index()]);
        assert_eq!(sent[21], 63);
        assert_eq!(&sent[54..], &packet[40..]);
    }
}
