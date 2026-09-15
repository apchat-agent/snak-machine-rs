mod common;
use common::*;
use snac_rs::{
    persist::{Identity, MemoryStore},
    router::{AilState, Lifecycle, Router},
    time::ScriptedRandom,
    Link,
};
fn router() -> Router {
    let id = Identity::load_or_create(
        &mut MemoryStore::default(),
        "review",
        &mut ScriptedRandom::new([9, 11, 12, 13, 14, 15, 16]),
    )
    .unwrap();
    Router::new(id, 0, &mut ScriptedRandom::new([])).unwrap()
}
fn receive_ra(
    r: &mut Router,
    link: Link,
    source: &str,
    options: &[u8],
    now: u64,
) -> std::io::Result<Vec<snac_rs::router::Tx>> {
    r.receive(
        link,
        &nd_packet(source, "ff02::1", ra(0, 0, options)),
        now,
        &mut ScriptedRandom::new([]),
    )
}
fn ns(source: &str, target: std::net::Ipv6Addr, mac: Option<[u8; 6]>) -> Vec<u8> {
    let mut b = vec![135, 0, 0, 0, 0, 0, 0, 0];
    b.extend(target.octets());
    if let Some(mac) = mac {
        b.extend([1, 1]);
        b.extend(mac);
    }
    nd_packet(
        source,
        &snac_rs::wire::solicited_node(target).to_string(),
        b,
    )
}
#[test]
fn review_01_p_only_hints_are_bounded_and_ra_is_atomic() {
    let mut r = router();
    for i in 0..128 {
        receive_ra(
            &mut r,
            Link::Ail,
            "fe80::99",
            &pio(&format!("2001:db8:{i:x}::"), 64, 0x10, u32::MAX, u32::MAX),
            0,
        )
        .unwrap();
    }
    let mut options = pio("2001:db8:ffff::", 64, 0xc0, 1800, 1800);
    options.extend(pio("2001:db8:eeee::", 64, 0x10, u32::MAX, u32::MAX));
    assert!(receive_ra(&mut r, Link::Ail, "fe80::99", &options, 0).is_err());
    assert_eq!(r.pd_hints.len(), 128);
    assert!(r.on_link.is_empty());
    assert_eq!(r.lifecycle, Lifecycle::Degraded);
}
#[test]
fn review_01_ra_shares_ns_neighbor_cap() {
    let mut r = router();
    let target = r.identity.link_local(Link::Ail);
    for i in 256..512 {
        r.receive(
            Link::Ail,
            &ns(&format!("fe80::{i:x}"), target, Some([2, 0, 0, 0, 0, 9])),
            0,
            &mut ScriptedRandom::new([]),
        )
        .unwrap();
    }
    assert!(receive_ra(&mut r, Link::Ail, "fe80::99", &[], 0).is_err());
    assert_eq!(r.neighbors.len(), 256);
    assert!(r.headers.is_empty());
}
#[test]
fn review_01_expired_hints_reclaimed_before_admission() {
    let mut r = router();
    for i in 0..128 {
        receive_ra(
            &mut r,
            Link::Ail,
            "fe80::99",
            &pio(&format!("2001:db8:{i:x}::"), 64, 0x10, 1, 1),
            0,
        )
        .unwrap();
    }
    receive_ra(
        &mut r,
        Link::Ail,
        "fe80::99",
        &pio("2001:db8:ffff::", 64, 0x10, 1, 1),
        1000,
    )
    .unwrap();
    assert_eq!(r.pd_hints.len(), 1);
}
