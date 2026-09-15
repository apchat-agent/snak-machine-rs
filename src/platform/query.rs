use super::*;
use crate::io::{LinkInfo, NativeFraming};
#[derive(Clone, Copy, Debug)]
pub struct LinkStatus {
    pub administrative_up: bool,
    pub carrier: bool,
}
impl LinkStatus {
    pub fn usable(self) -> bool {
        self.administrative_up && self.carrier
    }
}
#[derive(Clone, Debug)]
pub struct DescriptorInfo {
    pub name: String,
    pub framing: NativeFraming,
}
pub trait NativeQueries {
    fn status(&self, name: &str) -> io::Result<LinkStatus>;
    fn bridge(&self, name: &str) -> io::Result<Option<u32>>;
    fn descriptor(&self, fd: i32) -> io::Result<DescriptorInfo>;
}
pub struct Native;
impl NativeQueries for Native {
    fn status(&self, name: &str) -> io::Result<LinkStatus> {
        let r = ioctl_request(name, GET_FLAGS)?;
        // SAFETY: successful SIOCGIFFLAGS initialized this union member.
        let flags = unsafe { r.ifr_ifru.ifru_flags } as i32;
        Ok(LinkStatus {
            administrative_up: flags & libc::IFF_UP != 0,
            carrier: carrier(name, flags)?,
        })
    }
    fn bridge(&self, name: &str) -> io::Result<Option<u32>> {
        bridge(name)
    }
    fn descriptor(&self, fd: i32) -> io::Result<DescriptorInfo> {
        descriptor(fd)
    }
}
pub fn validate_pair_with(info: &[LinkInfo; 2], query: &impl NativeQueries) -> io::Result<()> {
    if info[0].index == info[1].index {
        return Err(io::Error::other("AIL and stub must be distinct interfaces"));
    }
    let a = query.bridge(&info[0].name)?;
    let b = query.bridge(&info[1].name)?;
    if a.is_some() && (a == b || a == Some(info[1].index)) || b == Some(info[0].index) {
        return Err(io::Error::other("AIL and stub share a bridge/master"));
    }
    Ok(())
}
pub fn validate_pair(info: &[LinkInfo; 2]) -> io::Result<()> {
    validate_pair_with(info, &Native)
}
pub fn validate_descriptor_with(
    fd: i32,
    name: &str,
    framing: NativeFraming,
    query: &impl NativeQueries,
) -> io::Result<()> {
    let observed = query.descriptor(fd)?;
    if observed.name != name || observed.framing != framing {
        return Err(io::Error::other(
            "packet descriptor interface/framing mismatch",
        ));
    }
    Ok(())
}
