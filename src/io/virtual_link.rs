use super::*;
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
};
pub struct VirtualPort {
    file: File,
}
impl PacketPort for VirtualPort {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut b = vec![0; 65593];
        match self.file.read(&mut b) {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "virtual interface closed",
            )),
            Ok(n) => {
                b.truncate(n);
                Ok(Some(b))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
    fn send(&mut self, b: &[u8]) -> io::Result<usize> {
        self.file.write(b)
    }
}
impl VirtualPort {
    pub fn from_fd(fd: BorrowedFd<'_>) -> io::Result<Self> {
        let owned = fd.try_clone_to_owned()?;
        crate::platform::nonblocking(&owned)?;
        Ok(Self {
            file: File::from(owned),
        })
    }
    fn from_owned(fd: OwnedFd) -> Self {
        Self {
            file: File::from(fd),
        }
    }
    pub fn descriptor(&self) -> i32 {
        self.file.as_raw_fd()
    }
}
pub fn open(ail: &str, stub: &str) -> io::Result<Backend> {
    #[cfg(target_os = "linux")]
    let (kind, framing) = (FrameKind::Ethernet, NativeFraming::Tap);
    #[cfg(target_os = "macos")]
    let (kind, framing) = (FrameKind::RawIpv6, NativeFraming::Utun);
    let (a, an) = crate::platform::open_virtual(ail)?;
    let (s, sn) = crate::platform::open_virtual(stub)?;
    let mut ai = crate::platform::info(&an, kind)?;
    let mut si = crate::platform::info(&sn, kind)?;
    // TAP kernel endpoint MACs belong to the peer; the router uses saved userspace MACs.
    ai.mac = None;
    si.mac = None;
    Backend::new(
        [
            Box::new(Device::new(VirtualPort::from_owned(a), framing, None)),
            Box::new(Device::new(VirtualPort::from_owned(s), framing, None)),
        ],
        [ai, si],
    )
}
