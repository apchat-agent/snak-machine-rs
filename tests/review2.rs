//! Regression tests for the independent REVIEW2 findings (task 8).
use snac_rs::wire::{Pref64, Prefix};
use std::net::Ipv6Addr;

fn pref64(length: u8, lifetime: u32) -> Pref64 {
    Pref64 {
        prefix: Prefix::new(
            "2001:db8:1234:5678:abcd:eeee::"
                .parse::<Ipv6Addr>()
                .unwrap(),
            length,
        )
        .unwrap(),
        lifetime,
    }
}

fn scaled_lifetime(wire: &[u8]) -> u32 {
    (u16::from_be_bytes([wire[2], wire[3]]) & 0xfff8) as u32
}

/// R2-1: RFC 8781 §4.2 requires a PREF64 Router Lifetime that is not evenly
/// divisible by eight to be rounded UP before the 13-bit Scaled Lifetime
/// field is filled, so the advertisement never expires before the backing
/// validity. The reviewer repro: 618 s must encode 78 (624 s), not 77 (616 s).
#[test]
fn review2_r2_1_pref64_scaled_lifetime_rounds_up_per_rfc_8781() {
    for (plc, length) in [96u8, 64, 56, 48, 40, 32].into_iter().enumerate() {
        for lifetime in [0u32, 1, 7, 8, 9, 616, 618, 65528, 65529, u32::MAX] {
            let wire = pref64(length, lifetime).encode().unwrap();
            assert_eq!(wire[0], 38);
            assert_eq!(wire[1], 2);
            assert_eq!(wire[3] & 7, plc as u8, "PREF64 /{length} PLC bits");
            let expected = lifetime.min(65528).div_ceil(8) * 8;
            assert_eq!(
                scaled_lifetime(&wire),
                expected,
                "PREF64 /{length} lifetime {lifetime} must encode rounded up"
            );
            let decoded = Pref64::decode(&wire).unwrap();
            assert_eq!(decoded.prefix.length, length);
            assert_eq!(decoded.lifetime, expected);
        }
    }
    let wire = pref64(96, 618).encode().unwrap();
    assert_eq!(&wire[..4], &[38, 2, 0x02, 0x70]);
    assert_eq!(scaled_lifetime(&wire), 624);
}

/// R2-2: ledger row R096 ("stub DHCPv6 service is NOT RECOMMENDED") is
/// satisfied by absence, so its evidence must cite the substantive stub
/// listener setup (DNS 53/853 only) rather than a bare module declaration.
#[test]
fn review2_r2_2_r096_evidence_cites_stub_dns_listeners_not_module_declarations() {
    let tsv = std::fs::read_to_string("tests/requirements.tsv").unwrap();
    let row = tsv
        .lines()
        .find(|l| l.starts_with("R096\t"))
        .expect("R096 ledger row");
    let cols: Vec<&str> = row.split('\t').collect();
    assert_eq!(cols[1], "DONE", "R096 must remain implemented");
    let citations: Vec<&str> = cols[2].split(';').filter(|c| !c.is_empty()).collect();
    assert!(
        !citations.is_empty(),
        "R096 needs code evidence for the absence claim"
    );
    for cite in &citations {
        let (path, line) = cite.rsplit_once(':').unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        let source = text
            .lines()
            .nth(line.parse::<usize>().unwrap() - 1)
            .unwrap();
        let trimmed = source.trim_start();
        assert!(
            !trimmed.starts_with("pub mod ") && !trimmed.starts_with("mod "),
            "R096 evidence {cite} cites a module declaration, not evidence: {source:?}"
        );
    }
    let listeners: Vec<&str> = citations
        .iter()
        .copied()
        .filter(|c| c.starts_with("src/runtime.rs:"))
        .collect();
    assert!(
        !listeners.is_empty(),
        "R096 must cite the stub listener setup (DNS 53/853 only) in src/runtime.rs"
    );
    for cite in &listeners {
        let (path, line) = cite.rsplit_once(':').unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        let source = text
            .lines()
            .nth(line.parse::<usize>().unwrap() - 1)
            .unwrap();
        assert!(
            source.contains("listen_udp(53)")
                || source.contains("listen_tcp(53)")
                || source.contains("listen_tcp_buffered(853"),
            "R096 listener citation {cite} is not a DNS 53/853 listener: {source:?}"
        );
    }
}
