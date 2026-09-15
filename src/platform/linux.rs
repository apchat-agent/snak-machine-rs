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
pub fn validate_pair(info: &[LinkInfo; 2]) -> io::Result<()> {
    if info[0].index == info[1].index {
        return Err(io::Error::other("AIL and stub must be distinct interfaces"));
    }
    let master = |name: &str| std::fs::canonicalize(format!("/sys/class/net/{name}/master")).ok();
    let a = master(&info[0].name);
    let b = master(&info[1].name);
    let root = |n: &str| std::fs::canonicalize(format!("/sys/class/net/{n}")).ok();
    if (a.is_some() && a == b)
        || (a.is_some() && a == root(&info[1].name))
        || (b.is_some() && b == root(&info[0].name))
    {
        return Err(io::Error::other("AIL and stub share a bridge/master"));
    }
    Ok(())
}
