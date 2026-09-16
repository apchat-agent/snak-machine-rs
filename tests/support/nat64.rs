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
