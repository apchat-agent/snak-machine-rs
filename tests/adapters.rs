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

#[test]
fn s04_ethernet_ipv4_and_arp_preserve_atomic_transmit_contract() {
    for (family, payload) in [(0x0800u16, vec![0x45; 20]), (0x0806, vec![0; 28])] {
        let mut frame = vec![0xff; 6];
        frame.extend([2, 0, 0, 0, 0, 1]);
        frame.extend(family.to_be_bytes());
        frame.extend(payload);
        let mut tap = Device::new(FakePort::default(), NativeFraming::Tap, None);
        tap.send(&frame).unwrap();
        assert_eq!(tap.port.output[0], frame);
        tap.port.short = true;
        assert_eq!(
            tap.send(&frame).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        let mut l3 = Device::new(FakePort::default(), NativeFraming::RawIpv6, None);
        assert!(l3.send(&frame).is_err());
        for n in 0..14 {
            assert!(tap.send(&frame[..n]).is_err());
        }
        frame[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        assert!(tap.send(&frame).is_err());
    }
}

#[test]
fn s04_native_status_bridge_and_fd_provenance_are_checked() {
    use snac_rs::{
        io::LinkInfo,
        platform::{
            validate_descriptor_with, validate_pair_with, DescriptorInfo, LinkStatus, NativeQueries,
        },
        wire::FrameKind,
    };
    struct Query {
        carrier: bool,
        bridge: Option<u32>,
        fd: Option<DescriptorInfo>,
    }
    impl NativeQueries for Query {
        fn status(&self, _: &str) -> io::Result<LinkStatus> {
            Ok(LinkStatus {
                administrative_up: true,
                carrier: self.carrier,
            })
        }
        fn bridge(&self, _: &str) -> io::Result<Option<u32>> {
            Ok(self.bridge)
        }
        fn descriptor(&self, _: i32) -> io::Result<DescriptorInfo> {
            self.fd
                .clone()
                .ok_or_else(|| io::Error::other("unsupported descriptor"))
        }
    }
    let info = [1, 2].map(|index| LinkInfo {
        name: format!("tap{index}"),
        index,
        kind: FrameKind::Ethernet,
        mtu: 1500,
        mac: None,
    });
    let mut query = Query {
        carrier: false,
        bridge: None,
        fd: None,
    };
    assert!(!query.status("tap1").unwrap().usable());
    query.carrier = true;
    assert!(query.status("tap1").unwrap().usable());
    assert!(validate_pair_with(&info, &query).is_ok());
    query.bridge = Some(3);
    assert!(validate_pair_with(&info, &query).is_err());
    assert!(validate_descriptor_with(4, "tap1", NativeFraming::Tap, &query).is_err());
    query.fd = Some(DescriptorInfo {
        name: "tap1".into(),
        framing: NativeFraming::Tap,
    });
    assert!(validate_descriptor_with(4, "tap1", NativeFraming::Tap, &query).is_ok());
    assert!(validate_descriptor_with(4, "tap2", NativeFraming::Tap, &query).is_err());
    assert!(validate_descriptor_with(4, "tap1", NativeFraming::RawIpv6, &query).is_err());
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open("Cargo.toml").unwrap();
    for fd in [-1, f.as_raw_fd()] {
        assert!(validate_descriptor_with(
            fd,
            "tap1",
            NativeFraming::Tap,
            &snac_rs::platform::Native
        )
        .is_err());
    }
    let (a, b) = std::os::unix::net::UnixDatagram::pair().unwrap();
    for fd in [a.as_raw_fd(), b.as_raw_fd()] {
        assert!(validate_descriptor_with(
            fd,
            "tap1",
            NativeFraming::Tap,
            &snac_rs::platform::Native
        )
        .is_err());
    }
}

#[test]
fn s04_driver_dispatches_bounded_ail_families_and_joins_mdns() {
    use snac_rs::{
        io::{Direction, LinkInfo, MemoryIo, Received},
        persist::{Identity, MemoryStore},
        router::Router,
        runtime::Driver,
        time::ScriptedRandom,
        wire::FrameKind,
        Link,
    };
    let mut rng = ScriptedRandom::new([123, 1, 2, 3, 4, 5, 6, 7]);
    let id = Identity::load_or_create(&mut MemoryStore::default(), "test", &mut rng).unwrap();
    let router = Router::new(id, 0, &mut rng).unwrap();
    let info = [1, 2].map(|index| LinkInfo {
        name: format!("memory{index}"),
        index,
        kind: FrameKind::Ethernet,
        mtu: 1500,
        mac: None,
    });
    let mut driver = Driver::new(router, MemoryIo::new(info)).unwrap();
    driver.start(0, &mut rng).unwrap();
    assert!(driver.io.groups[0].contains(&ip("ff02::fb")));
    assert!(driver.io.ipv4_groups[0].contains(&"224.0.0.251".parse().unwrap()));
    for family in [0x0800u16, 0x0806] {
        let mut frame = vec![0xff; 6];
        frame.extend([2, 0, 0, 0, 0, 99]);
        frame.extend(family.to_be_bytes());
        frame.extend([0; 28]);
        driver
            .accept(
                Received {
                    link: Link::Stub,
                    bytes: frame.clone(),
                    kind: FrameKind::Ethernet,
                    direction: Direction::Ingress,
                },
                0,
                &mut rng,
            )
            .unwrap();
        driver
            .accept(
                Received {
                    link: Link::Ail,
                    bytes: frame.clone(),
                    kind: FrameKind::Ethernet,
                    direction: Direction::OwnEgress,
                },
                0,
                &mut rng,
            )
            .unwrap();
        assert!(driver.router.ail_frames.pop().is_none());
        driver
            .accept(
                Received {
                    link: Link::Ail,
                    bytes: frame.clone(),
                    kind: FrameKind::Ethernet,
                    direction: Direction::Ingress,
                },
                0,
                &mut rng,
            )
            .unwrap();
        assert_eq!(driver.router.ail_frames.pop().unwrap(), frame);
    }
    let mut frame = vec![0xff; 6];
    frame.extend([2, 0, 0, 0, 0, 99]);
    frame.extend(0x0806u16.to_be_bytes());
    frame.extend([0; 28]);
    for _ in 0..65 {
        driver.router.ail_frames.push(&frame);
    }
    assert_eq!(driver.router.ail_frames.len(), 64);
    while driver.router.ail_frames.pop().is_some() {}
    let mut big = frame.clone();
    big.resize(65536, 0);
    assert!(!driver.router.ail_frames.push(&big));
    driver
        .router
        .set_link(Link::Ail, false, 1000, &mut rng)
        .unwrap();
    driver.io.up[0] = false;
    driver.step(1000, &mut rng).unwrap();
    assert!(driver.io.ipv4_groups[0].is_empty());
    assert!(!driver.io.groups[0].contains(&ip("ff02::fb")));
}
