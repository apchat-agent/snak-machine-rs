#![allow(dead_code)]
use std::net::{Ipv4Addr, Ipv6Addr};
pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
pub fn sum(b: &[u8]) -> u16 {
    let mut n = 0u32;
    for pair in b.chunks(2) {
        n += u32::from(pair[0]) * 256 + u32::from(*pair.get(1).unwrap_or(&0));
    }
    while n >> 16 != 0 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}
pub fn udp6(source: Ipv6Addr, destination: Ipv6Addr, sp: u16, dp: u16, data: &[u8]) -> Vec<u8> {
    let mut udp = sp.to_be_bytes().to_vec();
    udp.extend(dp.to_be_bytes());
    udp.extend(((data.len() + 8) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(data);
    let mut pseudo = source.octets().to_vec();
    pseudo.extend(destination.octets());
    pseudo.extend((udp.len() as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, 17]);
    pseudo.extend(&udp);
    let c = sum(&pseudo);
    udp[6..8].copy_from_slice(&(if c == 0 { 65535 } else { c }).to_be_bytes());
    let mut out = vec![0x60, 0, 0, 0];
    out.extend((udp.len() as u16).to_be_bytes());
    out.extend([17, 64]);
    out.extend(source.octets());
    out.extend(destination.octets());
    out.extend(udp);
    out
}
pub fn udp4(source: Ipv4Addr, destination: Ipv4Addr, sp: u16, dp: u16, data: &[u8]) -> Vec<u8> {
    let mut udp = sp.to_be_bytes().to_vec();
    udp.extend(dp.to_be_bytes());
    udp.extend(((data.len() + 8) as u16).to_be_bytes());
    udp.extend([0, 0]);
    udp.extend(data);
    let mut out = vec![0x45, 0];
    out.extend(((udp.len() + 20) as u16).to_be_bytes());
    out.extend([0, 0, 0, 0, 64, 17, 0, 0]);
    out.extend(source.octets());
    out.extend(destination.octets());
    let c = sum(&out);
    out[10..12].copy_from_slice(&c.to_be_bytes());
    out.extend(udp);
    out
}
pub fn udp6_valid(b: &[u8]) -> bool {
    let mut pseudo = b[8..40].to_vec();
    pseudo.extend(((b.len() - 40) as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, 17]);
    pseudo.extend(&b[40..]);
    sum(&pseudo) == 0 && b[46..48] != [0, 0]
}
pub fn tcp6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    sp: u16,
    dp: u16,
    flags: u8,
    data: &[u8],
) -> Vec<u8> {
    let tcp = tcp(sp, dp, flags, data);
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((tcp.len() as u16).to_be_bytes());
    p.extend([6, 64]);
    p.extend(source.octets());
    p.extend(destination.octets());
    p.extend(tcp);
    tcp_fix(&mut p);
    p
}
pub fn tcp4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    sp: u16,
    dp: u16,
    flags: u8,
    data: &[u8],
) -> Vec<u8> {
    let tcp = tcp(sp, dp, flags, data);
    let mut p = vec![0x45, 0];
    p.extend(((tcp.len() + 20) as u16).to_be_bytes());
    p.extend([0, 0, 0, 0, 64, 6, 0, 0]);
    p.extend(source.octets());
    p.extend(destination.octets());
    let c = sum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend(tcp);
    tcp_fix(&mut p);
    p
}
fn tcp(sp: u16, dp: u16, flags: u8, data: &[u8]) -> Vec<u8> {
    let mut p = sp.to_be_bytes().to_vec();
    p.extend(dp.to_be_bytes());
    p.extend([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x50, flags, 0x20, 0, 0, 0, 0, 0,
    ]);
    p.extend(data);
    p
}
fn tcp_sum(p: &[u8]) -> u16 {
    let header = if p[0] >> 4 == 6 {
        40
    } else {
        usize::from(p[0] & 15) * 4
    };
    let mut pseudo = if header == 40 && p[0] >> 4 == 6 {
        p[8..40].to_vec()
    } else {
        p[12..20].to_vec()
    };
    if p[0] >> 4 == 6 {
        pseudo.extend(((p.len() - header) as u32).to_be_bytes());
        pseudo.extend([0, 0, 0, 6]);
    } else {
        pseudo.extend([0, 6]);
        pseudo.extend(((p.len() - header) as u16).to_be_bytes());
    }
    pseudo.extend(&p[header..]);
    sum(&pseudo)
}
pub fn tcp_fix(p: &mut [u8]) {
    let h = if p[0] >> 4 == 6 {
        40
    } else {
        usize::from(p[0] & 15) * 4
    };
    p[h + 16..h + 18].fill(0);
    let c = tcp_sum(p);
    p[h + 16..h + 18].copy_from_slice(&c.to_be_bytes());
}
pub fn tcp_valid(p: &[u8]) -> bool {
    tcp_sum(p) == 0
}
pub fn icmp6(source: Ipv6Addr, destination: Ipv6Addr, body: &[u8]) -> Vec<u8> {
    let mut b = body.to_vec();
    b[2..4].fill(0);
    let mut pseudo = source.octets().to_vec();
    pseudo.extend(destination.octets());
    pseudo.extend((b.len() as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, 58]);
    pseudo.extend(&b);
    let c = sum(&pseudo);
    b[2..4].copy_from_slice(&c.to_be_bytes());
    let mut p = vec![0x60, 0, 0, 0];
    p.extend((b.len() as u16).to_be_bytes());
    p.extend([58, 64]);
    p.extend(source.octets());
    p.extend(destination.octets());
    p.extend(b);
    p
}
pub fn icmp4(source: Ipv4Addr, destination: Ipv4Addr, body: &[u8]) -> Vec<u8> {
    let mut b = body.to_vec();
    b[2..4].fill(0);
    let c = sum(&b);
    b[2..4].copy_from_slice(&c.to_be_bytes());
    let mut p = vec![0x45, 0];
    p.extend(((b.len() + 20) as u16).to_be_bytes());
    p.extend([0, 0, 0, 0, 64, 1, 0, 0]);
    p.extend(source.octets());
    p.extend(destination.octets());
    let c = sum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend(b);
    p
}
pub fn icmp6_valid(b: &[u8]) -> bool {
    let mut p = b[8..40].to_vec();
    p.extend(((b.len() - 40) as u32).to_be_bytes());
    p.extend([0, 0, 0, 58]);
    p.extend(&b[40..]);
    sum(&p) == 0
}
