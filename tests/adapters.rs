mod common;
use common::*;
use snac_rs::io::{CaptureApi, CapturePort, Device, NativeFraming, PacketPort};
use std::{collections::VecDeque, io};
#[derive(Default)]
struct FakePort {
    input: VecDeque<Vec<u8>>,
    output: Vec<Vec<u8>>,
    short: bool,
}
impl PacketPort for FakePort {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.input.pop_front())
    }
    fn send(&mut self, p: &[u8]) -> io::Result<usize> {
        self.output.push(p.to_vec());
        Ok(p.len() - usize::from(self.short))
    }
}
struct FakeCapture {
    buffer: Vec<u8>,
}
impl CaptureApi for FakeCapture {
    fn next_packet(&mut self) -> io::Result<Option<&[u8]>> {
        Ok(Some(&self.buffer))
    }
    fn inject(&mut self, p: &[u8]) -> io::Result<usize> {
        Ok(p.len() - 1)
    }
}
#[test]
fn virtual_and_pcap_adapters_preserve_packet_contract() {
    let raw = packet("fe80::1", "ff02::1", 59, 64, &[1, 2, 3]);
    let mut header = vec![0, 0, 0, 30];
    header.extend(&raw);
    let mut utun = Device::new(
        FakePort {
            input: VecDeque::from([header.clone()]),
            ..Default::default()
        },
        NativeFraming::Utun,
        None,
    );
    assert_eq!(utun.receive().unwrap().unwrap(), raw);
    utun.send(&raw).unwrap();
    assert_eq!(utun.port.output[0], header);
    utun.port.short = true;
    assert!(utun.send(&raw).is_err());
    for bad in [vec![0, 0, 0], vec![30, 0, 0, 0], vec![0, 0, 0, 10]] {
        utun.port.input.push_back(bad);
        assert!(utun.receive().unwrap().is_none());
    }
    let mut frame = vec![0x33, 0x33, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0x86, 0xdd];
    frame.extend(&raw);
    let own = [2, 0, 0, 0, 0, 2];
    let mut tap = Device::new(
        FakePort {
            input: VecDeque::from([frame.clone()]),
            ..Default::default()
        },
        NativeFraming::Tap,
        None,
    );
    assert_eq!(tap.receive().unwrap().unwrap(), frame);
    tap.send(&frame).unwrap();
    assert_eq!(tap.port.output[0], frame);
    let mut capture = CapturePort::new(FakeCapture {
        buffer: frame.clone(),
    });
    let copied = capture.receive().unwrap().unwrap();
    capture.api.buffer.fill(0);
    assert_eq!(copied, frame);
    let mut pcap = Device::new(
        CapturePort::new(FakeCapture {
            buffer: frame.clone(),
        }),
        NativeFraming::Tap,
        Some(own),
    );
    assert!(pcap.receive().unwrap().is_none());
    assert!(pcap.send(&frame).is_err());
}

#[test]
fn review_09_utun_ipv4_and_truncated_capture_are_packet_drops() {
    let raw = packet("fe80::1", "ff02::1", 59, 64, &[1, 2, 3]);
    let mut ipv6 = vec![0, 0, 0, 30];
    ipv6.extend(&raw);
    let mut utun = Device::new(
        FakePort {
            input: VecDeque::from([vec![0, 0, 0, 2, 0x45, 0, 0, 0], ipv6]),
            ..Default::default()
        },
        NativeFraming::Utun,
        None,
    );
    assert!(utun.receive().unwrap().is_none());
    assert_eq!(utun.receive().unwrap().unwrap(), raw);
    struct TruncatedCapture {
        truncated: bool,
        data: Vec<u8>,
    }
    impl CaptureApi for TruncatedCapture {
        fn next_packet(&mut self) -> io::Result<Option<&[u8]>> {
            if self.truncated {
                self.truncated = false;
                return Err(io::Error::new(io::ErrorKind::InvalidData, "caplen < len"));
            }
            Ok(Some(&self.data))
        }
        fn inject(&mut self, b: &[u8]) -> io::Result<usize> {
            Ok(b.len())
        }
    }
    let mut capture = Device::new(
        CapturePort::new(TruncatedCapture {
            truncated: true,
            data: raw.clone(),
        }),
        NativeFraming::RawIpv6,
        None,
    );
    assert!(capture.receive().unwrap().is_none());
    assert_eq!(capture.receive().unwrap().unwrap(), raw);
}
