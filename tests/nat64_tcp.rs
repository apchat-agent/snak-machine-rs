use snac_rs::{
    nat64::{bindings::Bindings, tcp::State},
    time::ScriptedRandom,
};
use std::net::{Ipv6Addr, SocketAddrV4};
const SYN: u8 = 2;
const ACK: u8 = 16;
const FIN: u8 = 1;
const RST: u8 = 4;
const EST: u64 = 7_200_000;
const TRANS: u64 = 240_000;
fn host(n: u16) -> Ipv6Addr {
    format!("fd22::{n:x}").parse().unwrap()
}
fn remote(n: u16) -> SocketAddrV4 {
    SocketAddrV4::new([198, 51, 100, 7].into(), n)
}
fn out(b: &mut Bindings, r: u16, flags: u8, now: u64) -> Option<u16> {
    b.tcp_out(
        host(1),
        40000,
        remote(r),
        flags,
        now,
        &mut ScriptedRandom::new([]),
    )
    .unwrap()
}
fn incoming(b: &mut Bindings, r: u16, flags: u8, now: u64) -> Option<(Ipv6Addr, u16)> {
    b.tcp_in(40000, remote(r), flags, now).unwrap()
}
fn state(b: &Bindings, r: u16) -> Option<(State, u64)> {
    b.tcp_state(host(1), 40000, remote(r))
}
#[test]
fn s20_closed_init_and_both_initiation_directions_follow_rfc6146() {
    let mut b = Bindings::default();
    for flags in [ACK, FIN, RST] {
        assert_eq!(out(&mut b, 80, flags, 0), None);
        assert_eq!(incoming(&mut b, 80, flags, 0), None);
    }
    assert_eq!(
        incoming(&mut b, 80, SYN, 0),
        None,
        "no unsolicited binding creation"
    );
    assert_eq!(b.counts(), (0, 0, 0));
    assert_eq!(out(&mut b, 80, SYN, 10), Some(40000));
    assert_eq!(state(&b, 80), Some((State::V6Init, 10 + TRANS)));
    assert_eq!(out(&mut b, 80, SYN, 1000), Some(40000));
    assert_eq!(state(&b, 80), Some((State::V6Init, 1000 + TRANS)));
    assert_eq!(out(&mut b, 80, ACK, 2000), Some(40000));
    assert_eq!(
        state(&b, 80),
        Some((State::V6Init, 1000 + TRANS)),
        "non-SYN cannot refresh initiation"
    );
    assert_eq!(
        incoming(&mut b, 80, SYN | ACK, 3000),
        Some((host(1), 40000))
    );
    assert_eq!(state(&b, 80), Some((State::Established, 3000 + EST)));
    assert_eq!(
        incoming(&mut b, 443, ACK, 4000),
        None,
        "midstream remote cannot borrow another session"
    );
    assert_eq!(
        incoming(&mut b, 443, SYN, 4000),
        Some((host(1), 40000)),
        "existing binding permits IPv4 initiation"
    );
    assert_eq!(state(&b, 443), Some((State::V4Init, 4000 + TRANS)));
    incoming(&mut b, 443, SYN, 5000);
    assert_eq!(state(&b, 443), Some((State::V4Init, 4000 + TRANS)));
    assert_eq!(out(&mut b, 443, SYN | ACK, 6000), Some(40000));
    assert_eq!(state(&b, 443), Some((State::Established, 6000 + EST)));
    assert_eq!(b.counts(), (1, 2, 1));
    // Simultaneous open: a bare SYN, without ACK, establishes either direction.
    out(&mut b, 81, SYN, 7000);
    incoming(&mut b, 81, SYN, 8000);
    assert_eq!(state(&b, 81), Some((State::Established, 8000 + EST)));
}
#[test]
fn s20_every_established_fin_and_transitory_packet_transition_is_independent() {
    // (initial first FIN side, event side, event, resulting state, timeout)
    for (first, event_v6, flags, expected, timeout) in [
        (None, true, ACK, State::Established, EST),
        (None, false, ACK, State::Established, EST),
        (None, true, FIN, State::V6Fin, EST - 1),
        (None, false, FIN, State::V4Fin, EST - 1),
        (None, true, RST, State::Transitory, TRANS),
        (None, false, RST, State::Transitory, TRANS),
        (Some(true), true, FIN, State::V6Fin, EST),
        (Some(true), false, ACK, State::V6Fin, EST),
        (Some(true), true, RST, State::V6Fin, EST),
        (Some(true), false, FIN, State::BothFin, TRANS),
        (Some(false), false, FIN, State::V4Fin, EST),
        (Some(false), true, ACK, State::V4Fin, EST),
        (Some(false), false, RST, State::V4Fin, EST),
        (Some(false), true, FIN, State::BothFin, TRANS),
    ] {
        let mut b = Bindings::default();
        out(&mut b, 80, SYN, 0);
        incoming(&mut b, 80, SYN | ACK, 1);
        if let Some(v6) = first {
            if v6 {
                out(&mut b, 80, FIN, 1);
            } else {
                incoming(&mut b, 80, FIN, 1);
            }
        }
        if event_v6 {
            assert!(out(&mut b, 80, flags, 2).is_some());
        } else {
            assert!(incoming(&mut b, 80, flags, 2).is_some());
        }
        assert_eq!(
            state(&b, 80),
            Some((expected, 2 + timeout)),
            "{first:?} {event_v6} {flags}"
        );
    }
    for side in [false, true] {
        let mut b = Bindings::default();
        out(&mut b, 80, SYN, 0);
        incoming(&mut b, 80, SYN, 1);
        out(&mut b, 80, RST, 2);
        incoming(&mut b, 80, RST, 3);
        assert_eq!(
            state(&b, 80),
            Some((State::Transitory, 2 + TRANS)),
            "RST retries do not extend transitory timeout"
        );
        if side {
            out(&mut b, 80, ACK, 4);
        } else {
            incoming(&mut b, 80, ACK, 4);
        }
        assert_eq!(state(&b, 80), Some((State::Established, 4 + EST)));
        out(&mut b, 80, FIN, 5);
        incoming(&mut b, 80, FIN, 6);
        for flags in [ACK, FIN, RST, SYN] {
            out(&mut b, 80, flags, 7);
            incoming(&mut b, 80, flags, 7);
        }
        assert_eq!(
            state(&b, 80),
            Some((State::BothFin, 6 + TRANS)),
            "closedown retransmissions never renew state"
        );
    }
}
#[test]
fn s20_established_timeout_probes_once_then_transitory_expiry_or_recovery() {
    let mut b = Bindings::default();
    out(&mut b, 80, SYN, 0);
    incoming(&mut b, 80, SYN, 1);
    assert!(b.expire(EST).is_empty());
    assert!(b.take_tcp_probes(32).is_empty());
    assert!(b.expire(EST + 1).is_empty());
    assert_eq!(state(&b, 80), Some((State::Transitory, EST + 1 + TRANS)));
    assert_eq!(
        b.take_tcp_probes(32),
        vec![(host(1), 40000, 40000, remote(80))]
    );
    assert!(b.take_tcp_probes(32).is_empty());
    incoming(&mut b, 80, ACK, EST + 2);
    assert_eq!(state(&b, 80), Some((State::Established, 2 * EST + 2)));
    b.expire(2 * EST + 2);
    assert_eq!(b.counts(), (1, 1, 1));
    assert_eq!(b.expire(2 * EST + 2 + TRANS), vec![(6, 40000)]);
    assert!(b.take_tcp_probes(32).is_empty());
    assert_eq!(b.counts(), (0, 0, 0));
    // A late poll cannot restart an already expired four-minute grace interval.
    out(&mut b, 80, SYN, 20_000_000);
    incoming(&mut b, 80, SYN, 20_000_001);
    b.expire(20_000_001 + EST + TRANS);
    assert_eq!(b.counts(), (0, 0, 0));
}
#[test]
fn s20_all_non_established_timeouts_release_only_the_matching_session() {
    for variant in 0..5 {
        let mut b = Bindings::default();
        out(&mut b, 80, SYN, 0);
        if variant == 1 {
            incoming(&mut b, 81, SYN, 1);
        } else if variant >= 2 {
            incoming(&mut b, 80, SYN, 1);
            if variant == 2 {
                out(&mut b, 80, FIN, 2);
            } else {
                incoming(&mut b, 80, FIN, 2);
            }
            if variant == 4 {
                out(&mut b, 80, FIN, 3);
            }
        }
        let port = if variant == 1 { 81 } else { 80 };
        let deadline = state(&b, port).unwrap().1;
        b.expire(deadline - 1);
        assert!(state(&b, port).is_some());
        b.expire(deadline);
        assert_eq!(state(&b, port), None);
    }
}
#[test]
fn s20_tcp_udp_share_global_and_per_source_caps_without_live_mapping_eviction() {
    let mut b = Bindings::default();
    let mut rng = ScriptedRandom::new([]);
    for h in 1..=32 {
        for p in 10000..10128 {
            b.udp_out(host(h), p, remote(53), 0, &mut rng, |_| false)
                .unwrap();
        }
    }
    assert!(b
        .tcp_out(host(33), 40000, remote(80), SYN, 0, &mut rng)
        .is_err());
    assert_eq!(b.counts(), (4096, 4096, 32));
    b.expire(300000);
    for h in 1..=32 {
        for p in 10000..10128 {
            let assigned = b
                .tcp_out(host(h), p, remote(80), SYN, 300001, &mut rng)
                .unwrap()
                .unwrap();
            b.tcp_in(assigned, remote(80), SYN, 300002).unwrap();
            b.tcp_in(assigned, remote(443), SYN, 300002).unwrap();
        }
    }
    assert_eq!(b.counts(), (4096, 8192, 32));
    assert!(b.charged_bytes() <= 4 * 1024 * 1024);
    assert!(b
        .tcp_out(host(33), 40000, remote(80), SYN, 300003, &mut rng)
        .is_err());
    assert!(b.tcp_in(10000, remote(444), SYN, 300003).is_err());
    assert_eq!(
        b.tcp_in(10000, remote(80), ACK, 300003).unwrap(),
        Some((host(1), 10000))
    );
    b.expire(300002 + TRANS);
    assert_eq!(b.counts(), (4096, 4096, 32));
    b.expire(300002 + EST);
    let probes = b.take_tcp_probes(usize::MAX);
    assert_eq!(
        probes.len(),
        32,
        "work cap applies even to caller's oversized request"
    );
    assert_eq!(
        b.tcp_out(host(1), 10000, remote(80), ACK, 300002 + EST, &mut rng)
            .unwrap(),
        Some(10000)
    );
}
