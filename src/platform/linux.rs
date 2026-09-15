use super::*;
use std::os::unix::fs::OpenOptionsExt;
pub fn open_virtual(name: &str) -> io::Result<(OwnedFd, String)> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/net/tun")?;
    let fd: OwnedFd = f.into();
    let mut r = interface_request(name)?;
    r.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
    // SAFETY: TUNSETIFF/TUNGETIFF take a native ifreq pointer; fd owns /dev/net/tun.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut r) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNGETIFF, &mut r) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = unsafe { r.ifr_ifru.ifru_flags } as i32;
    if flags & (libc::IFF_TAP | libc::IFF_NO_PI) != (libc::IFF_TAP | libc::IFF_NO_PI)
        || flags & libc::IFF_VNET_HDR != 0
    {
        return Err(io::Error::other("incompatible TAP framing"));
    }
    let name = interface_name(&r)?;
    bring_up(&name)?;
    Ok((fd, name))
}
pub fn mac_address(name: &str) -> io::Result<Option<[u8; 6]>> {
    find_mac(name, libc::AF_PACKET, |p| {
        // SAFETY: getifaddrs checked AF_PACKET, so address is sockaddr_ll.
        let a = unsafe { &*p.cast::<libc::sockaddr_ll>() };
        if a.sll_halen == 6 {
            Some(a.sll_addr[..6].try_into().unwrap())
        } else {
            None
        }
    })
}
pub(super) fn carrier(_name: &str, flags: i32) -> io::Result<bool> {
    Ok(flags & libc::IFF_RUNNING != 0)
}
pub(super) fn bridge(name: &str) -> io::Result<Option<u32>> {
    interface_request(name)?;
    match std::fs::read_link(format!("/sys/class/net/{name}/master")) {
        Ok(path) => {
            let name = path
                .file_name()
                .ok_or_else(|| io::Error::other("invalid master name"))?
                .to_str()
                .ok_or_else(|| io::Error::other("non-UTF8 master name"))?;
            let name = CString::new(name).map_err(io::Error::other)?;
            // SAFETY: live, terminated name is passed to a read-only interface lookup.
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Some(index))
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
pub(super) fn descriptor(fd: i32) -> io::Result<DescriptorInfo> {
    let mut request = interface_request("unused")?;
    // SAFETY: ioctl validates fd and writes a native, bounded ifreq.
    if unsafe { libc::ioctl(fd, libc::TUNGETIFF, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = unsafe { request.ifr_ifru.ifru_flags } as i32;
    if flags & libc::IFF_NO_PI == 0 || flags & libc::IFF_VNET_HDR != 0 {
        return Err(io::Error::other("unsupported packet descriptor framing"));
    }
    let framing = match flags & (libc::IFF_TAP | libc::IFF_TUN) {
        libc::IFF_TAP => crate::io::NativeFraming::Tap,
        libc::IFF_TUN => crate::io::NativeFraming::RawIpv6,
        _ => return Err(io::Error::other("unknown interface descriptor")),
    };
    Ok(DescriptorInfo {
        name: interface_name(&request)?,
        framing,
    })
}
