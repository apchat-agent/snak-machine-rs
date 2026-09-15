use crate::io::LinkInfo;
use std::{
    collections::BTreeMap,
    ffi::{CStr, CString},
    io,
    net::Ipv6Addr,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
pub use linux::{mac_address, open_virtual, validate_pair};
#[cfg(target_os = "macos")]
pub use macos::{mac_address, open_virtual, validate_pair};
pub fn owned_fd(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: caller supplies a newly returned owned OS descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
pub fn interface_request(name: &str) -> io::Result<libc::ifreq> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.as_bytes().contains(&0) {
        return Err(io::Error::other("invalid interface name"));
    } // SAFETY: ifreq is a C POD structure whose all-zero representation is valid.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (a, b) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *a = b as libc::c_char;
    }
    Ok(request)
}
pub fn ioctl_request(name: &str, command: libc::c_ulong) -> io::Result<libc::ifreq> {
    let mut r = interface_request(name)?; // SAFETY: native socket and ioctl use a correctly sized ifreq; fd is owned and closed on return.
    let socket = owned_fd(unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) })?;
    #[cfg(target_os = "linux")]
    let command = command as libc::Ioctl;
    if unsafe { libc::ioctl(socket.as_raw_fd(), command, &mut r) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(r)
}
pub fn is_up(name: &str) -> io::Result<bool> {
    let r = ioctl_request(name, GET_FLAGS)?; // SAFETY: SIOCGIFFLAGS populated the flags union member.
    Ok(unsafe { r.ifr_ifru.ifru_flags } as i32 & libc::IFF_UP != 0)
}
pub fn info(name: &str, kind: crate::wire::FrameKind) -> io::Result<LinkInfo> {
    let n = CString::new(name).map_err(io::Error::other)?; // SAFETY: null-terminated name remains alive for the call.
    let index = unsafe { libc::if_nametoindex(n.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    let r = ioctl_request(name, GET_MTU)?; // SAFETY: SIOCGIFMTU populated the MTU member.
    let mtu = unsafe { r.ifr_ifru.ifru_mtu };
    if mtu < 1280 {
        return Err(io::Error::other("IPv6 interface MTU below 1280"));
    }
    Ok(LinkInfo {
        name: name.to_owned(),
        index,
        kind,
        mtu: mtu as u32,
        mac: mac_address(name)?,
    })
}
pub fn interface_name(r: &libc::ifreq) -> io::Result<String> {
    // SAFETY: zero-initialized ifreq name is bounded; kernel ABI supplies a NUL-terminated interface name.
    let end = r
        .ifr_name
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| io::Error::other("unterminated interface name"))?;
    Ok(String::from_utf8_lossy(
        &r.ifr_name[..end]
            .iter()
            .map(|b| *b as u8)
            .collect::<Vec<_>>(),
    )
    .into_owned())
}
pub fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: all fcntl operations use a live descriptor and valid commands.
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0
            || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
            || libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
pub struct Membership {
    socket: OwnedFd,
    index: u32,
    groups: BTreeMap<Ipv6Addr, usize>,
}
impl Membership {
    pub fn new(index: u32) -> io::Result<Self> {
        // SAFETY: creates an owned IPv6 UDP socket for scoped memberships, no data listeners.
        let socket = owned_fd(unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) })?;
        nonblocking(&socket)?;
        Ok(Self {
            socket,
            index,
            groups: BTreeMap::new(),
        })
    }
    fn change(&self, group: Ipv6Addr, join: bool) -> io::Result<()> {
        let request = libc::ipv6_mreq {
            ipv6mr_multiaddr: libc::in6_addr {
                s6_addr: group.octets(),
            },
            ipv6mr_interface: self.index,
        };
        // SAFETY: native ipv6_mreq pointer and exact length are valid during setsockopt.
        #[cfg(target_os = "linux")]
        let option = if join {
            libc::IPV6_ADD_MEMBERSHIP
        } else {
            libc::IPV6_DROP_MEMBERSHIP
        };
        #[cfg(target_os = "macos")]
        let option = if join {
            libc::IPV6_JOIN_GROUP
        } else {
            libc::IPV6_LEAVE_GROUP
        };
        let rc = unsafe {
            libc::setsockopt(
                self.socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                option,
                (&request as *const libc::ipv6_mreq).cast(),
                std::mem::size_of_val(&request) as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn join(&mut self, g: Ipv6Addr) -> io::Result<()> {
        if !self.groups.contains_key(&g) {
            self.change(g, true)?;
        }
        *self.groups.entry(g).or_default() += 1;
        Ok(())
    }
    pub fn leave(&mut self, g: Ipv6Addr) -> io::Result<()> {
        if self.groups.get(&g) == Some(&1) {
            self.change(g, false)?;
            self.groups.remove(&g);
        } else if let Some(n) = self.groups.get_mut(&g) {
            *n -= 1;
        }
        Ok(())
    }
}
pub fn find_mac(
    name: &str,
    family: libc::c_int,
    extract: impl Fn(*const libc::sockaddr) -> Option<[u8; 6]>,
) -> io::Result<Option<[u8; 6]>> {
    let mut first = std::ptr::null_mut(); // SAFETY: getifaddrs initializes the linked list; every pointer checked before dereference and freed once.
    if unsafe { libc::getifaddrs(&mut first) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut cursor = first;
    let mut result = None;
    unsafe {
        while !cursor.is_null() {
            let a = &*cursor;
            if !a.ifa_addr.is_null()
                && (*a.ifa_addr).sa_family as i32 == family
                && CStr::from_ptr(a.ifa_name).to_bytes() == name.as_bytes()
            {
                result = extract(a.ifa_addr);
                break;
            }
            cursor = a.ifa_next;
        }
        libc::freeifaddrs(first);
    }
    Ok(result)
}

pub fn bring_up(name: &str) -> io::Result<()> {
    let mut r = ioctl_request(name, GET_FLAGS)?; // SAFETY: flags union initialized by query; write same native ifreq with IFF_UP.
    unsafe {
        r.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        let fd = owned_fd(libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0))?;
        if libc::ioctl(fd.as_raw_fd(), SET_FLAGS as _, &r) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
const GET_FLAGS: libc::c_ulong = libc::SIOCGIFFLAGS as libc::c_ulong;
#[cfg(target_os = "linux")]
const SET_FLAGS: libc::c_ulong = libc::SIOCSIFFLAGS as libc::c_ulong;
#[cfg(target_os = "linux")]
const GET_MTU: libc::c_ulong = libc::SIOCGIFMTU as libc::c_ulong;
// XNU bsd/sys/sockio.h, ioccom.h: _IOWR('i',17/51,ifreq), _IOW('i',16,ifreq).
// libc 0.2.177 supplies ifreq but omits these Darwin ioctl constants.
#[cfg(target_os = "macos")]
const GET_FLAGS: libc::c_ulong = 0xc0206911;
#[cfg(target_os = "macos")]
const SET_FLAGS: libc::c_ulong = 0x80206910;
#[cfg(target_os = "macos")]
const GET_MTU: libc::c_ulong = 0xc0206933;
#[cfg(target_os = "macos")]
const _: () = assert!(std::mem::size_of::<libc::ifreq>() == 32);
