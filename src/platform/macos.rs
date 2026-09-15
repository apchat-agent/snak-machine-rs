//! Darwin ABI: XNU bsd/sys/kern_control.h and bsd/net/if_utun.h.
//! PF_SYSTEM/SYSPROTO_CONTROL, CTLIOCGINFO, sockaddr_ctl, UTUN_OPT_IFNAME=2.
use super::*;
pub fn open_virtual(name: &str) -> io::Result<(OwnedFd, String)> {
    let unit = if name == "utun" {
        0
    } else {
        name.strip_prefix("utun")
            .ok_or_else(|| io::Error::other("macOS tap backend requires utun or utunN"))?
            .parse::<u32>()
            .map_err(io::Error::other)?
            .checked_add(1)
            .ok_or_else(|| io::Error::other("utun unit overflow"))?
    };
    // SAFETY: native kernel-control socket and libc's SDK-compatible POD layouts.
    let fd = owned_fd(unsafe {
        libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL)
    })?;
    let mut ctl: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (a, b) in ctl.ctl_name.iter_mut().zip(b"com.apple.net.utun_control") {
        *a = *b as libc::c_char;
    }
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut ctl) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let address = libc::sockaddr_ctl {
        sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
        sc_family: libc::AF_SYSTEM as u8,
        ss_sysaddr: libc::AF_SYS_CONTROL as u16,
        sc_id: ctl.ctl_id,
        sc_unit: unit,
        sc_reserved: [0; 5],
    };
    if unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&address as *const libc::sockaddr_ctl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SYSPROTO_CONTROL,
            2,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let end = name
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| io::Error::other("unterminated utun name"))?;
    let name = String::from_utf8(name[..end].to_vec()).map_err(io::Error::other)?;
    nonblocking(&fd)?;
    bring_up(&name)?;
    Ok((fd, name))
}
pub fn mac_address(name: &str) -> io::Result<Option<[u8; 6]>> {
    find_mac(name, libc::AF_LINK, |p| {
        // SAFETY: address is AF_LINK sockaddr_dl; bounds validate six MAC octets after name.
        let a = unsafe { &*p.cast::<libc::sockaddr_dl>() };
        let start = a.sdl_nlen as usize;
        if a.sdl_alen == 6 && start + 6 <= a.sdl_data.len() {
            let mut mac = [0; 6];
            for (i, v) in mac.iter_mut().enumerate() {
                *v = a.sdl_data[start + i] as u8;
            }
            Some(mac)
        } else {
            None
        }
    })
}
// XNU if.h uses pack(4) for these native control request structures.
#[repr(C, packed(4))]
struct MediaRequest {
    name: [libc::c_char; 16],
    current: i32,
    mask: i32,
    status: i32,
    active: i32,
    count: i32,
    list: *mut i32,
}
#[repr(C, packed(4))]
struct DriverRequest {
    name: [libc::c_char; 16],
    command: libc::c_ulong,
    length: usize,
    data: *mut libc::c_void,
}
#[repr(C, packed(4))]
struct BridgeList {
    length: u32,
    data: *mut u8,
}
const _: () = assert!(std::mem::size_of::<MediaRequest>() == 44);
const _: () = assert!(std::mem::size_of::<DriverRequest>() == 40);
const _: () = assert!(std::mem::size_of::<BridgeList>() == 12);
pub(super) fn carrier(name: &str, flags: i32) -> io::Result<bool> {
    if flags & (libc::IFF_POINTOPOINT | libc::IFF_LOOPBACK) != 0 {
        return Ok(flags & libc::IFF_RUNNING != 0);
    }
    let mut request = MediaRequest {
        name: interface_request(name)?.ifr_name,
        current: 0,
        mask: 0,
        status: 0,
        active: 0,
        count: 0,
        list: std::ptr::null_mut(),
    };
    // SAFETY: SIOCGIFMEDIA uses the asserted native pack(4) layout; zero count requests only status.
    let fd = owned_fd(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) })?;
    if unsafe { libc::ioctl(fd.as_raw_fd(), 0xc02c6938 as libc::c_ulong, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // IFM_AVALID=1, IFM_ACTIVE=2. Unknown media status is not positive carrier evidence.
    Ok(request.status & 3 == 3)
}
pub(super) fn bridge(name: &str) -> io::Result<Option<u32>> {
    interface_request(name)?;
    // SAFETY: if_nameindex returns a terminated native array, freed exactly once.
    let first = unsafe { libc::if_nameindex() };
    if first.is_null() {
        return Err(io::Error::last_os_error());
    }
    struct Names(*mut libc::if_nameindex);
    impl Drop for Names {
        fn drop(&mut self) {
            unsafe {
                libc::if_freenameindex(self.0);
            }
        }
    }
    let names = Names(first);
    let fd = owned_fd(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) })?;
    for i in 0..256 {
        let entry = unsafe { &*names.0.add(i) };
        if entry.if_index == 0 {
            return Ok(None);
        }
        if entry.if_name.is_null() {
            return Err(io::Error::other("invalid native interface list"));
        }
        let candidate = unsafe { CStr::from_ptr(entry.if_name) }
            .to_str()
            .map_err(io::Error::other)?;
        // ifbreq is 80 bytes under XNU pack(4), including its reserved pad.
        let mut members = vec![0u8; 256 * 80];
        let mut list = BridgeList {
            length: members.len() as u32,
            data: members.as_mut_ptr(),
        };
        let mut request = DriverRequest {
            name: interface_request(candidate)?.ifr_name,
            command: 6,
            length: std::mem::size_of::<BridgeList>(),
            data: (&mut list as *mut BridgeList).cast(),
        };
        // SAFETY: BRDGGIFS writes only the provided bounded list and packet-sized records.
        if unsafe { libc::ioctl(fd.as_raw_fd(), 0xc028697b as libc::c_ulong, &mut request) } < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::EINVAL)
            ) {
                continue;
            }
            return Err(error);
        }
        let length = list.length as usize;
        if length > members.len() || length % 80 != 0 {
            return Err(io::Error::other("bridge membership capacity/layout"));
        }
        for record in members[..length].chunks_exact(80) {
            let n = record[..16]
                .iter()
                .position(|v| *v == 0)
                .ok_or_else(|| io::Error::other("unterminated bridge member"))?;
            if &record[..n] == name.as_bytes() {
                return Ok(Some(entry.if_index));
            }
        }
    }
    Err(io::Error::other("native interface list capacity"))
}
pub(super) fn descriptor(fd: i32) -> io::Result<DescriptorInfo> {
    // A packet FD must be the utun kernel control, not an arbitrary socket.
    let mut control: libc::ctl_info = unsafe { std::mem::zeroed() };
    for (dst, src) in control
        .ctl_name
        .iter_mut()
        .zip(b"com.apple.net.utun_control")
    {
        *dst = *src as libc::c_char;
    }
    if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut control) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getpeername(
            fd,
            (&mut address as *mut libc::sockaddr_ctl).cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of_val(&address)
        || address.sc_family != libc::AF_SYSTEM as u8
        || address.sc_id != control.ctl_id
    {
        return Err(io::Error::other(
            "descriptor is not the utun kernel control",
        ));
    }
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SYSPROTO_CONTROL,
            2,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let n = name
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| io::Error::other("unterminated utun name"))?;
    Ok(DescriptorInfo {
        name: String::from_utf8(name[..n].to_vec()).map_err(io::Error::other)?,
        framing: crate::io::NativeFraming::Utun,
    })
}
