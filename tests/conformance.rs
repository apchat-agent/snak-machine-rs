mod common;
use common::*;
use snac_rs::{
    config::Config,
    persist::{Identity, MemoryStore},
    router::{
        pd::{Lease, PdClient, PdState},
        AilState, Lifecycle, Router, Tx,
    },
    time::{Lifetime, ScriptedRandom},
    wire::{envelope, FrameKind, Prefix},
    Link,
};
fn router(seed: u64) -> Router {
    let mut rng = ScriptedRandom::new([seed, seed + 11, seed + 12, 13, 14, 15, 16, 17]);
    let id =
        Identity::load_or_create(&mut MemoryStore::default(), "same-interface", &mut rng).unwrap();
    Router::new(id, 0, &mut rng).unwrap()
}
fn send(r: &mut Router, now: u64) {
    let mut rng = ScriptedRandom::new([]);
    for tx in r.tick(now, &mut rng).unwrap() {
        r.transmitted(&tx, now, true, &mut rng).unwrap();
    }
}
fn observe(r: &mut Router, source: &str, prefix: &str, now: u64) {
    let packet = nd_packet(
        source,
        "ff02::1",
        ra(0, 1800, &pio(prefix, 64, 0xc0, 1800, 1800)),
    );
    r.receive(Link::Ail, &packet, now, &mut ScriptedRandom::new([]))
        .unwrap();
}
#[test]
fn s02_stub_flag_does_not_change_two_router_election() {
    for flag in [0, 2] {
        let mut a = router(88);
        let mut b = router(99);
        for r in [&mut a, &mut b] {
            r.links[1].state = AilState::Advertising;
        }
        let low = a
            .identity
            .prefix(Link::Stub)
            .min(b.identity.prefix(Link::Stub));
        for (receiver, sender) in [(&mut a, &b)] {
            let packet = nd_packet(
                &sender.identity.link_local(Link::Stub).to_string(),
                "ff02::1",
                ra(
                    flag,
                    0,
                    &pio(
                        &sender.identity.prefix(Link::Stub).address.to_string(),
                        64,
                        0xc0,
                        1800,
                        1800,
                    ),
                ),
            );
            receiver
                .receive(Link::Stub, &packet, 100, &mut ScriptedRandom::new([]))
                .unwrap();
        }
        let packet = nd_packet(
            &a.identity.link_local(Link::Stub).to_string(),
            "ff02::1",
            ra(
                flag,
                0,
                &pio(
                    &a.identity.prefix(Link::Stub).address.to_string(),
                    64,
                    0xc0,
                    1800,
                    1800,
                ),
            ),
        );
        b.receive(Link::Stub, &packet, 100, &mut ScriptedRandom::new([]))
            .unwrap();
        for r in [&a, &b] {
            assert_eq!(r.lifecycle, Lifecycle::Running);
            let snap = r.snapshot(Link::Stub, 100);
            assert_eq!(snap.encode().unwrap()[45] & 2, 0);
            assert_eq!(
                snap.pios.iter().any(|p| p.preferred > 0),
                r.identity.prefix(Link::Stub) == low
            );
        }
    }
}
#[test]
fn s02_detected_attachment_rotates_only_after_discovery_and_retains_old_stub() {
    let mut r = router(90);
    r.links[1].state = AilState::Advertising;
    let tx = Tx {
        link: Link::Stub,
        packet: r.snapshot(Link::Stub, 0).encode().unwrap(),
    };
    r.transmitted(&tx, 0, true, &mut ScriptedRandom::new([]))
        .unwrap();
    let old = r.identity.site;
    let stub = r.identity.prefix(Link::Stub);
    observe(&mut r, "fe80::a", "2001:db8:1::", 0);
    send(&mut r, 9000);
    let saved = r.checkpoint(9000, 100).unwrap();
    r = Router::restore(&saved, 9000, 100, &mut ScriptedRandom::new([])).unwrap();
    observe(&mut r, "fe80::a", "2001:db8:2::", 9000);
    send(&mut r, 18000);
    assert_eq!(
        r.identity.site, old,
        "reboot and renumbering are not movement"
    );
    let mut rng = ScriptedRandom::new([12345, 12346]);
    r.set_link(Link::Ail, false, 20000, &mut rng).unwrap();
    r.set_link(Link::Ail, true, 21000, &mut rng).unwrap();
    observe(&mut r, "fe80::b", "2001:db8:2::", 21000);
    assert_eq!(r.identity.site, old, "one RA cannot establish movement");
    send(&mut r, 30000);
    assert_ne!(
        r.identity.site, old,
        "new router identity after discovery detects same-interface movement"
    );
    assert!(r
        .on_link
        .get(&(Link::Stub, stub))
        .unwrap()
        .valid
        .live(30000));
    let p = r
        .snapshot(Link::Stub, 30000)
        .pios
        .into_iter()
        .find(|p| p.prefix == stub)
        .unwrap();
    assert_eq!(p.preferred, 0);
    assert!(
        p.valid <= 1770,
        "rotation cannot extend the last advertised validity"
    );
}
#[test]
fn s02_no_evidence_reconnect_preserves_identity_and_cli_policy_is_explicit() {
    let mut r = router(90);
    let old = r.identity.site;
    let mut rng = ScriptedRandom::new([]);
    r.set_link(Link::Ail, false, 0, &mut rng).unwrap();
    r.set_link(Link::Ail, true, 0, &mut rng).unwrap();
    for now in [0, 4000, 8000, 9000] {
        send(&mut r, now);
    }
    assert_eq!(r.identity.site, old);
    let base = ["--backend", "tap", "--infra", "a", "--stub", "b"];
    assert!(Config::parse(base.into_iter().chain([
        "--ula-policy=fixed",
        "--attachment-id",
        "office"
    ]))
    .is_ok());
    assert!(Config::parse(base.into_iter().chain(["--ula-policy", "rotate"])).is_ok());
    assert!(Config::parse(base.into_iter().chain(["--ula-policy", "guess"])).is_err());
    assert!(Config::parse(
        base.into_iter()
            .chain(["--attachment-id", &"x".repeat(129)])
    )
    .is_err());
}
#[test]
fn s02_pd_renews_due_server_and_keeps_other_ia_lifetimes() {
    let mut pd = PdClient {
        state: PdState::Bound,
        ..PdClient::default()
    };
    for (iaid, prefix, server, t1, t2, valid) in [
        (1, "2001:db8:1::", vec![1], 100, 200, 400),
        (2, "fd01::", vec![2], 10, 20, 40),
    ] {
        pd.leases.insert(
            (iaid, Prefix::new(ip(prefix), 64).unwrap()),
            Lease {
                server,
                preferred: Lifetime::from_secs(0, valid),
                valid: Lifetime::from_secs(0, valid),
                t1: Lifetime::from_secs(0, t1),
                t2: Lifetime::from_secs(0, t2),
                used: true,
            },
        );
    }
    pd.advance(10000, &mut ScriptedRandom::new([])).unwrap();
    assert_eq!(
        pd.exchange.as_ref().unwrap().server,
        vec![2],
        "earliest IA selects its own server"
    );
    let key = (1, Prefix::new(ip("2001:db8:1::"), 64).unwrap());
    let xid = pd.exchange.as_ref().unwrap().xid;
    let reply = dhcp_packet(
        "fe80::1",
        7,
        xid,
        &[4],
        &[2],
        &ia(2, 30, 60, &[("fd01::", 64, 90, 120)]),
    );
    pd.receive(
        &envelope(FrameKind::RawIpv6, &reply).unwrap(),
        &[4],
        11000,
        &mut ScriptedRandom::new([]),
    )
    .unwrap();
    assert_eq!(pd.leases[&key].valid, Lifetime::from_secs(0, 400));
    assert_eq!(pd.leases[&key].t1, Lifetime::from_secs(0, 100));
}
