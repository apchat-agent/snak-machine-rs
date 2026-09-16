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

#[path = "support/nat64_driver.rs"]
mod native;
#[path = "support/nat64.rs"]
mod packets;
const TCP_OUT:&str="6000000000140640fd220000000000000000000000000001fd1122334455ffff00000000c63364079c4001bb0123456789abcdef50022000c8c80000";
const TCP_OUT_EXPECTED: &str =
    "45000028000000003f068f8bc000020ac63364079c4001bb0123456789abcdef50022000677c0000";
const TCP_IN: &str =
    "450000280000000040068e8bc6336407c000020a01bb9c400123456789abcdef50122000676c0000";
const TCP_IN_EXPECTED:&str="600000000014063ffd1122334455ffff00000000c6336407fd22000000000000000000000000000101bb9c400123456789abcdef50122000c8b80000";
fn translator() -> snac_rs::nat64::Translator {
    snac_rs::nat64::Translator::new(
        snac_rs::wire::Prefix::new("fd11:2233:4455:ffff::".parse().unwrap(), 96).unwrap(),
        [192, 0, 2, 10].into(),
        Default::default(),
    )
    .unwrap()
}
fn send(
    t: &mut snac_rs::nat64::Translator,
    p: &[u8],
    now: u64,
) -> std::io::Result<Vec<snac_rs::router::Tx>> {
    t.outbound(p, now, &mut ScriptedRandom::new([]), |_| true, |_| true)
}
#[test]
fn s20_literal_tcp_segments_translate_sequence_flags_checksum_and_payload() {
    let mut t = translator();
    assert_eq!(
        send(&mut t, &packets::hex(TCP_OUT), 0).unwrap()[0].packet,
        packets::hex(TCP_OUT_EXPECTED)
    );
    assert_eq!(
        t.inbound(&packets::hex(TCP_IN), 1).unwrap()[0].packet,
        packets::hex(TCP_IN_EXPECTED)
    );
    let destination = "fd11:2233:4455:ffff::c633:6407".parse().unwrap();
    let data = packets::tcp6(
        host(1),
        destination,
        40000,
        443,
        ACK | 8,
        b"TCP payload with sequence numbers intact",
    );
    let output = send(&mut t, &data, 2).unwrap();
    let p = &output[0].packet;
    assert!(packets::tcp_valid(p));
    assert_eq!(&p[24..36], &data[44..56]);
    assert_eq!(&p[40..], &data[60..]);
    assert_eq!(p[8], 63);
    assert_eq!(packets::sum(&p[..20]), 0);
    let reply = packets::tcp4(
        [198, 51, 100, 7].into(),
        [192, 0, 2, 10].into(),
        443,
        40000,
        ACK | 8,
        b"reply bytes",
    );
    let output = t.inbound(&reply, 3).unwrap();
    assert!(packets::tcp_valid(&output[0].packet));
    assert_eq!(&output[0].packet[60..], b"reply bytes");
}
#[test]
fn s20_hostile_tcp_headers_options_and_checksum_cannot_create_or_refresh_sessions() {
    let good = packets::hex(TCP_OUT);
    let mut t = translator();
    for n in 0..good.len() {
        assert!(send(&mut t, &good[..n], 0).is_err());
    }
    for offset in [0, 4, 6, 15] {
        let mut bad = good.clone();
        bad[52] = offset << 4;
        packets::tcp_fix(&mut bad);
        assert!(send(&mut t, &bad, 0).is_err());
    }
    for flags in [SYN | FIN, SYN | RST] {
        let mut bad = good.clone();
        bad[53] = flags;
        packets::tcp_fix(&mut bad);
        assert!(send(&mut t, &bad, 0).is_err());
    }
    for option in [
        [2, 3, 1, 0],
        [3, 4, 0, 0],
        [8, 4, 0, 0],
        [30, 0, 0, 0],
        [0, 1, 0, 0],
        [5, 4, 0, 0],
    ] {
        let mut bad = good.clone();
        bad[4..6].copy_from_slice(&24u16.to_be_bytes());
        bad[52] = 0x60;
        bad.extend(option);
        packets::tcp_fix(&mut bad);
        assert!(send(&mut t, &bad, 0).is_err(), "{option:?}");
    }
    assert_eq!(t.bindings.counts(), (0, 0, 0));
    send(&mut t, &good, 100).unwrap();
    let before = t.bindings.tcp_state(host(1), 40000, remote(443));
    let mut corrupt = packets::hex(TCP_IN);
    corrupt[24] ^= 1;
    assert!(t.inbound(&corrupt, 1000).is_err());
    assert_eq!(t.bindings.tcp_state(host(1), 40000, remote(443)), before);
    let mut valid = good.clone();
    valid[4..6].copy_from_slice(&24u16.to_be_bytes());
    valid[52] = 0x60;
    valid.extend([2, 4, 5, 180]);
    packets::tcp_fix(&mut valid);
    let out = send(&mut t, &valid, 101).unwrap();
    assert_eq!(&out[0].packet[40..], &[2, 4, 5, 180]);
    assert!(packets::tcp_valid(&out[0].packet));
}
#[test]
fn s20_tcp_poll_emits_exact_idle_probe_and_bounded_initial_syn_timeout_errors() {
    use snac_rs::Link;
    let mut t = translator();
    send(&mut t, &packets::hex(TCP_OUT), 0).unwrap();
    t.inbound(&packets::hex(TCP_IN), 1).unwrap();
    assert!(t.poll(EST).unwrap().is_empty());
    let out = t.poll(EST + 1).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].link, Link::Stub);
    let probe = &out[0].packet;
    assert_eq!(probe.len(), 60);
    assert_eq!(&probe[24..40], &host(1).octets());
    assert_eq!(&probe[40..44], &[1, 187, 156, 64]);
    assert_eq!(&probe[44..52], &[0; 8]);
    assert_eq!(probe[53], ACK);
    assert!(packets::tcp_valid(probe));
    assert!(t.poll(EST + 2).unwrap().is_empty());
    let mut t = translator();
    send(&mut t, &packets::hex(TCP_OUT), 0).unwrap();
    t.inbound(&packets::hex(TCP_IN), 1).unwrap();
    for port in 1000..1064 {
        let p = packets::tcp4(
            [198, 51, 100, 7].into(),
            [192, 0, 2, 10].into(),
            port,
            40000,
            SYN,
            &[],
        );
        assert_eq!(t.inbound(&p, 2).unwrap().len(), 1);
    }
    t.bindings.expire(TRANS + 2);
    assert_eq!(t.bindings.tcp_timeout_load(), (32, 32 * 28));
    let out = t.poll(TRANS + 2).unwrap();
    assert_eq!(out.len(), 32);
    assert_eq!(t.bindings.tcp_timeout_load(), (0, 0));
    for tx in out {
        assert_eq!(tx.link, Link::Ail);
        let p = tx.packet;
        assert_eq!(p[9], 1);
        assert_eq!(&p[20..22], &[3, 3]);
        assert_eq!(packets::sum(&p[20..]), 0);
        assert_eq!(&p[28 + 12..28 + 20], &[198, 51, 100, 7, 192, 0, 2, 10]);
    }
    assert!(t.poll(TRANS + 3).unwrap().is_empty());
    assert_eq!(t.bindings.counts(), (1, 1, 1));
}
#[test]
fn s20_native_tcp_handshake_data_and_half_close_use_translation_without_endpoint_proxy() {
    use snac_rs::Link;
    let mut d = native::driver(30, [192, 0, 2, 10].into());
    let h = native::host(&d, 99);
    let target = native::synth(&d, [198, 51, 100, 7].into());
    native::learn(&mut d, h, 20001);
    d.io.output.clear();
    native::packet(
        &mut d,
        Link::Stub,
        &packets::tcp6(h, target, 40000, 443, SYN, &[]),
        20002,
    );
    native::arp(&mut d, [192, 0, 2, 1].into(), 20003);
    let out = native::translated(&mut d, Link::Ail, 6);
    assert_eq!(out.len(), 1);
    assert!(packets::tcp_valid(&out[0]));
    native::packet(
        &mut d,
        Link::Ail,
        &packets::tcp4(
            [198, 51, 100, 7].into(),
            [192, 0, 2, 10].into(),
            443,
            40000,
            SYN | ACK,
            &[],
        ),
        20004,
    );
    d.step(20004, &mut ScriptedRandom::new([])).unwrap();
    let out = native::translated(&mut d, Link::Stub, 6);
    assert_eq!(out.len(), 1);
    assert!(packets::tcp_valid(&out[0]));
    native::packet(
        &mut d,
        Link::Stub,
        &packets::tcp6(h, target, 40000, 443, ACK | 8, b"native TCP data"),
        20005,
    );
    let out = native::translated(&mut d, Link::Ail, 6);
    assert_eq!(out.len(), 1);
    assert_eq!(&out[0][40..], b"native TCP data");
    assert!(packets::tcp_valid(&out[0]));
    native::packet(
        &mut d,
        Link::Stub,
        &packets::tcp6(h, target, 40000, 443, FIN | ACK, &[]),
        20006,
    );
    assert_eq!(
        d.nat64
            .as_ref()
            .unwrap()
            .bindings
            .tcp_state(h, 40000, remote(443))
            .unwrap()
            .0,
        State::V6Fin
    );
    assert!(d.stack_mut(Link::Ail).unwrap().connections().is_empty());
    assert!(d.stack_mut(Link::Stub).unwrap().connections().is_empty());
}

#[test]
fn s20_tcp_saved_syn_quotes_count_toward_the_shared_byte_budget_before_admission() {
    let mut t = translator();
    let mut rng = ScriptedRandom::new([]);
    let mut ports = vec![];
    for h in 1..=4096 {
        ports.push(
            t.bindings
                .tcp_out(host(h), 40000, remote(443), SYN, 0, &mut rng)
                .unwrap()
                .unwrap(),
        );
    }
    let initial = t.bindings.charged_bytes();
    let packet = |assigned, remote_port| {
        let mut p = packets::tcp4(
            [198, 51, 100, 7].into(),
            [192, 0, 2, 10].into(),
            remote_port,
            assigned,
            SYN,
            &[],
        );
        p.splice(20..20, [1; 40]);
        p[0] = 0x4f;
        p[2..4].copy_from_slice(&80u16.to_be_bytes());
        p[10..12].fill(0);
        let c = packets::sum(&p[..60]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p
    };
    for (n, p) in ports.iter().enumerate() {
        t.inbound(&packet(*p, 1000), 1).unwrap();
        assert_eq!(
            t.bindings.charged_bytes(),
            initial + (n + 1) * (256 + 68),
            "saved IPv4 option bytes must be charged"
        );
    }
    t.bindings.expire(TRANS);
    assert_eq!(t.bindings.counts(), (4096, 4096, 4096));
    let mut rejected = 0;
    for p in &ports {
        let before = t.bindings.counts();
        if t.inbound(&packet(*p, 1001), TRANS).is_err() {
            rejected += 1;
            assert_eq!(t.bindings.counts(), before, "byte-cap refusal is atomic");
        }
        assert!(t.bindings.charged_bytes() <= 4 * 1024 * 1024);
    }
    assert!(
        rejected > 0,
        "byte cap must limit maximum-size SYN quotes before count caps"
    );
    t.bindings.expire(TRANS + 1);
    assert!(t.bindings.charged_bytes() <= 4 * 1024 * 1024);
    // An existing surviving session still progresses and releases its quote.
    let p = ports[0];
    let before = t.bindings.charged_bytes();
    t.bindings
        .tcp_out(host(1), 40000, remote(1001), SYN | ACK, TRANS + 2, &mut rng)
        .unwrap();
    assert_eq!(t.bindings.charged_bytes(), before - 68);
    assert!(t.bindings.owns(6, p));
}
