#![allow(dead_code)]
use std::net::Ipv6Addr;
pub fn ip(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}
pub fn sum(source: Ipv6Addr, dest: Ipv6Addr, next: u8, payload: &[u8]) -> u16 {
    let mut bytes = source.octets().to_vec();
    bytes.extend(dest.octets());
    bytes.extend((payload.len() as u32).to_be_bytes());
    bytes.extend([0, 0, 0, next]);
    bytes.extend(payload);
    if bytes.len() % 2 != 0 {
        bytes.push(0);
    }
    let mut n: u32 = bytes
        .chunks_exact(2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]) as u32)
        .sum();
    while n > 65535 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
pub fn packet(source: &str, dest: &str, next: u8, hop: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 40];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    b[6] = next;
    b[7] = hop;
    b[8..24].copy_from_slice(&ip(source).octets());
    b[24..40].copy_from_slice(&ip(dest).octets());
    b.extend(payload);
    b
}
pub fn nd_packet(source: &str, dest: &str, mut body: Vec<u8>) -> Vec<u8> {
    body[2] = 0;
    body[3] = 0;
    let c = sum(ip(source), ip(dest), 58, &body);
    body[2..4].copy_from_slice(&c.to_be_bytes());
    packet(source, dest, 58, 255, &body)
}
pub fn ra(flags: u8, lifetime: u16, options: &[u8]) -> Vec<u8> {
    let mut b = vec![134, 0, 0, 0, 0, flags];
    b.extend(lifetime.to_be_bytes());
    b.extend([0; 8]);
    b.extend(options);
    b
}
pub fn pio(prefix: &str, length: u8, flags: u8, preferred: u32, valid: u32) -> Vec<u8> {
    let mut b = vec![3, 4, length, flags];
    b.extend(valid.to_be_bytes());
    b.extend(preferred.to_be_bytes());
    b.extend([0; 4]);
    b.extend(ip(prefix).octets());
    b
}
pub fn rio(prefix: &str, length: u8, flags: u8, lifetime: u32, units: u8) -> Vec<u8> {
    let mut b = vec![24, units, length, flags];
    b.extend(lifetime.to_be_bytes());
    b.extend(&ip(prefix).octets()[..(units as usize - 1) * 8]);
    b
}

pub fn dhcp_opts(b: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = vec![];
    let mut p = b;
    while !p.is_empty() {
        assert!(p.len() >= 4);
        let n = u16::from_be_bytes([p[2], p[3]]) as usize;
        assert!(p.len() >= 4 + n);
        out.push((u16::from_be_bytes([p[0], p[1]]), p[4..4 + n].to_vec()));
        p = &p[4 + n..];
    }
    out
}
pub fn option(code: u16, b: &[u8]) -> Vec<u8> {
    let mut out = code.to_be_bytes().to_vec();
    out.extend((b.len() as u16).to_be_bytes());
    out.extend(b);
    out
}

pub fn ia(iaid: u32, t1: u32, t2: u32, prefixes: &[(&str, u8, u32, u32)]) -> Vec<u8> {
    let mut b = iaid.to_be_bytes().to_vec();
    b.extend(t1.to_be_bytes());
    b.extend(t2.to_be_bytes());
    for (prefix, length, preferred, valid) in prefixes {
        let mut p = preferred.to_be_bytes().to_vec();
        p.extend(valid.to_be_bytes());
        p.push(*length);
        p.extend(ip(prefix).octets());
        b.extend(option(26, &p));
    }
    option(25, &b)
}
pub fn dhcp_packet(
    dest: &str,
    kind: u8,
    xid: [u8; 3],
    duid: &[u8],
    server: &[u8],
    extra: &[u8],
) -> Vec<u8> {
    let mut body = vec![kind];
    body.extend(xid);
    body.extend(option(1, duid));
    body.extend(option(2, server));
    body.extend(extra);
    let mut udp = vec![2, 35, 2, 34];
    udp.extend(((body.len() + 8) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(body);
    let c = sum(ip("fe80::feed"), ip(dest), 17, &udp);
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    packet("fe80::feed", dest, 17, 1, &udp)
}

pub mod srp;
