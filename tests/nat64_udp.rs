use snac_rs::{
    nat64::bindings::{Bindings, UdpFiltering},
    time::ScriptedRandom,
};
use std::net::{Ipv6Addr, SocketAddrV4};
fn host(n: u16) -> Ipv6Addr {
    format!("fd11::{n:x}").parse().unwrap()
}
fn remote(n: u8, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new([192, 0, 2, n].into(), port)
}
#[test]
fn s19_udp_mapping_is_endpoint_independent_and_default_filter_is_address_dependent() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    let p = b
        .udp_out(host(1), 12345, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    assert_eq!(p, 12345);
    assert_eq!(
        b.udp_out(host(1), 12345, remote(2, 8080), 1, &mut rng, |_| false)
            .unwrap(),
        p
    );
    assert_eq!(b.counts(), (1, 2, 1));
    assert_eq!(
        b.udp_in(p, remote(1, 99), 2).unwrap(),
        Some((host(1), 12345)),
        "filter permits a new remote port at an already-contacted address"
    );
    assert_eq!(b.counts(), (1, 3, 1));
    assert_eq!(b.udp_in(p, remote(3, 99), 2).unwrap(), None);
    assert_eq!(b.udp_in(54321, remote(1, 53), 2).unwrap(), None);
    assert_eq!(b.counts(), (1, 3, 1));
    b.set_udp_filtering(UdpFiltering::EndpointIndependent);
    assert_eq!(
        b.udp_in(p, remote(3, 99), 3).unwrap(),
        Some((host(1), 12345))
    );
    assert_eq!(b.counts(), (1, 4, 1));
}
#[test]
fn s19_udp_allocation_preserves_free_ports_respects_shared_ownership_and_bounds_search() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    let a = b
        .udp_out(host(1), 50000, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    let c = b
        .udp_out(host(2), 50000, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    assert_ne!(a, c);
    assert_eq!(c % 2, 0);
    assert!(c >= 1024);
    let p = b
        .udp_out(host(3), 53, remote(1, 53), 0, &mut rng, |p| p == 53)
        .unwrap();
    assert_ne!(p, 53);
    assert!(p < 1024);
    assert_eq!(p % 2, 1);
    let before = b.counts();
    let probes = std::cell::Cell::new(0);
    assert!(b
        .udp_out(host(4), 40000, remote(1, 53), 0, &mut rng, |_| {
            probes.set(probes.get() + 1);
            true
        })
        .is_err());
    assert!(
        probes.get() <= 18433,
        "allocation scan must terminate even if all ports are reserved"
    );
    assert_eq!(b.counts(), before);
    assert_eq!(
        b.udp_in(a, remote(1, 53), 1).unwrap(),
        Some((host(1), 50000)),
        "collision attempts never overwrite a live mapping"
    );
}
#[test]
fn s19_udp_timeouts_refresh_sessions_and_release_binding_only_after_the_last_session() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    assert!(b.set_udp_timeout(119).is_err());
    assert!(b.set_udp_timeout(86401).is_err());
    let p = b
        .udp_out(host(1), 40000, remote(1, 53), 0, &mut rng, |_| false)
        .unwrap();
    b.udp_out(host(1), 40000, remote(2, 53), 1000, &mut rng, |_| false)
        .unwrap();
    assert!(b.expire(300000).is_empty());
    assert_eq!(b.counts(), (1, 1, 1));
    assert_eq!(
        b.udp_in(p, remote(2, 99), 300001).unwrap(),
        Some((host(1), 40000))
    );
    assert!(b.expire(301000).is_empty());
    assert_eq!(b.counts(), (1, 1, 1));
    assert_eq!(b.expire(600001), vec![(17, p)]);
    assert_eq!(b.counts(), (0, 0, 0));
    assert_eq!(b.udp_in(p, remote(2, 99), 600002).unwrap(), None);
    b.set_udp_timeout(120).unwrap();
    b.udp_out(host(1), p, remote(1, 53), 700000, &mut rng, |_| false)
        .unwrap();
    assert_eq!(b.next_deadline(), Some(820000));
    b.expire(820000);
    assert_eq!(b.counts(), (0, 0, 0));
}
#[test]
fn s19_udp_host_and_global_binding_session_limits_never_evict_live_state() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    for n in 0..128 {
        b.udp_out(host(1), 10000 + n, remote(1, 53), 0, &mut rng, |_| false)
            .unwrap();
    }
    assert!(b
        .udp_out(host(1), 20000, remote(1, 53), 0, &mut rng, |_| false)
        .is_err());
    assert_eq!(b.counts(), (128, 128, 1));
    for n in 0..128 {
        b.udp_out(host(1), 10000 + n, remote(2, 53), 0, &mut rng, |_| false)
            .unwrap();
    }
    assert!(b
        .udp_out(host(1), 10000, remote(3, 53), 0, &mut rng, |_| false)
        .is_err());
    assert_eq!(b.counts(), (128, 256, 1));
    for h in 2..=32 {
        for n in 0..128 {
            b.udp_out(host(h), 10000 + n, remote(1, 53), 0, &mut rng, |_| false)
                .unwrap();
            b.udp_out(host(h), 10000 + n, remote(2, 53), 0, &mut rng, |_| false)
                .unwrap();
        }
    }
    assert_eq!(b.counts(), (4096, 8192, 32));
    assert!(b.charged_bytes() <= 4 * 1024 * 1024);
    assert!(b
        .udp_out(host(33), 20000, remote(1, 53), 0, &mut rng, |_| false)
        .is_err());
    assert_eq!(
        b.udp_out(host(1), 10000, remote(1, 53), 1, &mut rng, |_| false)
            .unwrap(),
        10000
    );
    b.set_udp_filtering(UdpFiltering::EndpointIndependent);
    for port in 1..=2048 {
        let _ = b.udp_in(10000, remote(99, port), 2);
    }
    assert_eq!(b.counts(), (4096, 8192, 32));
    b.expire(300000);
    assert_eq!(b.counts(), (1, 1, 1));
    b.expire(300001);
    assert_eq!(b.counts(), (0, 0, 0));
    assert_eq!(
        b.udp_out(host(33), 10000, remote(1, 53), 300002, &mut rng, |_| false)
            .unwrap(),
        10000
    );
}
