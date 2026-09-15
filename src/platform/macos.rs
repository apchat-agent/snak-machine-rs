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
pub fn validate_pair(info: &[LinkInfo; 2]) -> io::Result<()> {
    if info[0].index == info[1].index {
        return Err(io::Error::other("AIL and stub must be distinct interfaces"));
    }
    Ok(())
}
