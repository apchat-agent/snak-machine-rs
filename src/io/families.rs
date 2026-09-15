//! Ethernet family dispatch precedes each protocol's checked packet parser.
use std::collections::VecDeque;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Ipv6,
    Ipv4,
    Arp,
}
pub fn ethernet_family(frame: &[u8]) -> Option<Family> {
    if frame.len() < 14 {
        return None;
    }
    match u16::from_be_bytes([frame[12], frame[13]]) {
        0x86dd => Some(Family::Ipv6),
        0x0800 => Some(Family::Ipv4),
        0x0806 => Some(Family::Arp),
        _ => None,
    }
}
/// Bounded ingress handoff to the IPv4/ARP reducer (installed in S05).
#[derive(Default)]
pub struct AilFrames {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
}
impl AilFrames {
    pub fn push(&mut self, frame: &[u8]) -> bool {
        if self.frames.len() >= 64 || frame.len() > 65535 || self.bytes + frame.len() > 65535 {
            return false;
        }
        self.bytes += frame.len();
        self.frames.push_back(frame.to_vec());
        true
    }
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let frame = self.frames.pop_front()?;
        self.bytes -= frame.len();
        Some(frame)
    }
    pub fn len(&self) -> usize {
        self.frames.len()
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}
