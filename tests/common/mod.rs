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
