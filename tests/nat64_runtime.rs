mod common;
use snac_rs::{
    nat64::{Mode, Policy, Readiness},
    persist::{Identity, MemoryStore},
    router::Router,
    time::ScriptedRandom,
    wire::{FrameKind, Prefix},
    Link,
};
fn router() -> Router {
    let mut rng = ScriptedRandom::new([18]);
    let id = Identity::load_or_create(&mut MemoryStore::default(), "nat64", &mut rng).unwrap();
    Router::new(id, 0, &mut rng).unwrap()
}
fn packet(source: &str, dest: &str) -> Vec<u8> {
    // Literal RFC 8781 option: 64:ff9b::/96, eighty seconds, PLC zero.
    let option = [38, 2, 0, 80, 0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0];
    common::nd_packet(source, dest, common::ra(2, 0, &option))
}
fn selected(r: &mut Router, now: u64) -> Mode {
    r.nat64
        .select(
            now,
            Readiness {
                pd: Some(100000),
                ipv4: None,
                stub: Some(100000),
                translator: false,
            },
            |_, _| true,
            |_| Some(100000),
        )
        .mode
}
#[test]
fn s18_router_native_ra_entry_feeds_selection_and_clears_evidence_on_link_loss() {
    let mut r = router();
    let mut rng = ScriptedRandom::new([]);
    r.receive(Link::Ail, &packet("2001:db8::1", "ff02::1"), 0, &mut rng)
        .unwrap();
    assert_eq!(selected(&mut r, 0), Mode::None);
    r.receive(Link::Ail, &packet("fe80::99", "2001:db8::99"), 0, &mut rng)
        .unwrap();
    assert_eq!(selected(&mut r, 0), Mode::None);
    let mut own = vec![0x33, 0x33, 0, 0, 0, 1];
    own.extend(r.links[0].mac.unwrap_or(r.identity.macs[0]));
    own.extend([0x86, 0xdd]);
    own.extend(packet("fe80::99", "ff02::1"));
    r.receive_frame(Link::Ail, FrameKind::Ethernet, &own, 0, &mut rng)
        .unwrap();
    assert_eq!(selected(&mut r, 0), Mode::None);
    r.receive(Link::Ail, &packet("fe80::99", "ff02::1"), 0, &mut rng)
        .unwrap();
    assert_eq!(selected(&mut r, 0), Mode::Infrastructure);
    assert_eq!(r.nat64.next_deadline(), Some(80000));
    r.set_link(Link::Ail, false, 1, &mut rng).unwrap();
    assert_eq!(selected(&mut r, 1), Mode::None);
    r.set_link(Link::Ail, true, 2, &mut rng).unwrap();
    assert_eq!(selected(&mut r, 2), Mode::None);
    r.configure_nat64(
        Policy {
            enabled: false,
            ..Policy::default()
        },
        3,
        &mut rng,
    )
    .unwrap();
    r.receive(Link::Ail, &packet("fe80::99", "ff02::1"), 3, &mut rng)
        .unwrap();
    assert_eq!(selected(&mut r, 3), Mode::Disabled);
    r.configure_nat64(Policy::default(), 4, &mut rng).unwrap();
    assert_eq!(selected(&mut r, 4), Mode::None);
    r.receive(Link::Ail, &packet("fe80::99", "ff02::1"), 5, &mut rng)
        .unwrap();
    assert_eq!(selected(&mut r, 5), Mode::Infrastructure);
    r.tick(80005, &mut rng).unwrap();
    assert_eq!(r.nat64.next_deadline(), None);
    assert_eq!(r.nat64.local_prefix().length, 96);
    assert!(Prefix::new(r.nat64.local_prefix().address, 48).unwrap() == r.identity.site);
}
