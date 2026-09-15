//! libpcap 1.5+ C ABI from upstream pcap/pcap.h; Darwin uses system BPF via libpcap.
//! Dynamic loading keeps default builds independent of headers and linker libraries.
use super::*;
use libloading::Library;
use std::{
    ffi::{c_char, c_int, c_void, CStr, CString},
    ptr::{self, NonNull},
    rc::Rc,
};
#[repr(C)]
struct PacketHeader {
    ts: libc::timeval,
    caplen: u32,
    len: u32,
}
#[repr(C)]
struct BpfProgram {
    len: u32,
    insns: *mut c_void,
}
type Handle = *mut c_void;
macro_rules! api {
    ($($name:ident: $ty:ty),+ $(,)?)=>{
        struct Api{$($name:$ty,)+_library:Library}
        impl Api{fn load(path:Option<&str>)->io::Result<Rc<Self>>{
            #[cfg(target_os="linux")]let defaults=&["libpcap.so.1","libpcap.so.0.8","libpcap.so"][..];
            #[cfg(target_os="macos")]let defaults=&["/usr/lib/libpcap.A.dylib"][..];
            let paths:Vec<&str>=path.map_or_else(||defaults.to_vec(),|p|vec![p]);let mut errors=vec![];
            for path in paths{// SAFETY: opt-in system C library; copied function pointers use exact upstream signatures. Library lifetime encloses every handle.
                let library=match unsafe{Library::new(path)}{Ok(l)=>l,Err(e)=>{errors.push(e.to_string());continue;}};
                unsafe{return Ok(Rc::new(Self{$($name:*library.get::<$ty>(concat!(stringify!($name),"\0").as_bytes()).map_err(io::Error::other)?,)+_library:library}));}
            }Err(io::Error::new(io::ErrorKind::NotFound,format!("cannot load libpcap: {}",errors.join("; "))))
        }}
    }
}
api! {
    pcap_create:unsafe extern "C" fn(*const c_char,*mut c_char)->Handle,
    pcap_set_snaplen:unsafe extern "C" fn(Handle,c_int)->c_int,
    pcap_set_promisc:unsafe extern "C" fn(Handle,c_int)->c_int,
    pcap_set_timeout:unsafe extern "C" fn(Handle,c_int)->c_int,
    pcap_set_immediate_mode:unsafe extern "C" fn(Handle,c_int)->c_int,
    pcap_activate:unsafe extern "C" fn(Handle)->c_int,
    pcap_datalink:unsafe extern "C" fn(Handle)->c_int,
    pcap_compile:unsafe extern "C" fn(Handle,*mut BpfProgram,*const c_char,c_int,u32)->c_int,
    pcap_setfilter:unsafe extern "C" fn(Handle,*mut BpfProgram)->c_int,
    pcap_freecode:unsafe extern "C" fn(*mut BpfProgram),
    pcap_setdirection:unsafe extern "C" fn(Handle,c_int)->c_int,
    pcap_setnonblock:unsafe extern "C" fn(Handle,c_int,*mut c_char)->c_int,
    pcap_next_ex:unsafe extern "C" fn(Handle,*mut *const PacketHeader,*mut *const u8)->c_int,
    pcap_inject:unsafe extern "C" fn(Handle,*const c_void,usize)->c_int,
    pcap_geterr:unsafe extern "C" fn(Handle)->*mut c_char,
    pcap_close:unsafe extern "C" fn(Handle),
}
struct PcapHandle {
    handle: NonNull<c_void>,
    api: Rc<Api>,
}
impl PcapHandle {
    fn error(&self) -> io::Error {
        // SAFETY: geterr returns a live NUL-terminated library-owned error string.
        let p = unsafe { (self.api.pcap_geterr)(self.handle.as_ptr()) };
        io::Error::other(if p.is_null() {
            "libpcap failure".to_owned()
        } else {
            unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
        })
    }
    fn open(api: Rc<Api>, name: &str) -> io::Result<Self> {
        let name = CString::new(name).map_err(io::Error::other)?;
        let mut err = [0; 256];
        // SAFETY: create consumes the terminated name and writes at most PCAP_ERRBUF_SIZE bytes.
        let handle = NonNull::new(unsafe { (api.pcap_create)(name.as_ptr(), err.as_mut_ptr()) })
            .ok_or_else(|| {
                io::Error::other(
                    unsafe { CStr::from_ptr(err.as_ptr()) }
                        .to_string_lossy()
                        .into_owned(),
                )
            })?;
        let this = Self { handle, api };
        let h = this.handle.as_ptr();
        let a = &this.api;
        // SAFETY: all operations use the owned pcap_t and exact C structures. Drop closes partial initialization on every error.
        unsafe {
            for (set, value) in [
                (a.pcap_set_snaplen, 65535),
                (a.pcap_set_promisc, 1),
                (a.pcap_set_timeout, 25),
                (a.pcap_set_immediate_mode, 1),
            ] {
                if set(h, value) != 0 {
                    return Err(this.error());
                }
            }
            let status = (a.pcap_activate)(h);
            if status != 0 {
                return Err(io::Error::other(format!(
                    "pcap activation status {status}: {}",
                    this.error()
                )));
            }
            if (a.pcap_datalink)(h) != 1 {
                return Err(io::Error::other("pcap backend requires DLT_EN10MB Ethernet; VLAN trunks/cooked/radiotap/utun unsupported"));
            }
            let filter =
                CString::new("ether proto 0x86dd or ether proto 0x0800 or ether proto 0x0806")
                    .unwrap();
            let mut program = BpfProgram {
                len: 0,
                insns: ptr::null_mut(),
            };
            if (a.pcap_compile)(h, &mut program, filter.as_ptr(), 1, u32::MAX) != 0 {
                return Err(this.error());
            }
            let status = (a.pcap_setfilter)(h, &mut program);
            (a.pcap_freecode)(&mut program);
            if status != 0 {
                return Err(this.error());
            }
            if (a.pcap_setdirection)(h, 1) != 0 {
                eprintln!("pcap: direction filtering unavailable; own-source MAC suppression remains active");
            }
            if (a.pcap_setnonblock)(h, 1, err.as_mut_ptr()) != 0 {
                return Err(this.error());
            }
        }
        Ok(this)
    }
}
impl CaptureApi for PcapHandle {
    fn next_packet(&mut self) -> io::Result<Option<&[u8]>> {
        let mut header = ptr::null();
        let mut data = ptr::null();
        // SAFETY: pcap_next_ex initializes both pointers on result 1; returned slice is borrowed until the next mutable handle call.
        let result =
            unsafe { (self.api.pcap_next_ex)(self.handle.as_ptr(), &mut header, &mut data) };
        match result {
            0 => Ok(None),
            1 => {
                if header.is_null() || data.is_null() {
                    return Err(io::Error::other("pcap null packet"));
                }
                let h = unsafe { &*header };
                if h.caplen != h.len || h.caplen > 65535 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated pcap capture",
                    ));
                }
                Ok(Some(unsafe {
                    std::slice::from_raw_parts(data, h.caplen as usize)
                }))
            }
            _ => Err(self.error()),
        }
    }
    fn inject(&mut self, b: &[u8]) -> io::Result<usize> {
        // SAFETY: packet slice remains valid for the synchronous injection call.
        let n = unsafe { (self.api.pcap_inject)(self.handle.as_ptr(), b.as_ptr().cast(), b.len()) };
        if n < 0 {
            Err(self.error())
        } else {
            Ok(n as usize)
        }
    }
}
impl Drop for PcapHandle {
    fn drop(&mut self) {
        // SAFETY: handle is owned once; API library is still held by this object.
        unsafe {
            (self.api.pcap_close)(self.handle.as_ptr());
        }
    }
}
pub fn open(ail: &str, stub: &str, library: Option<&str>) -> io::Result<Backend> {
    let ai = crate::platform::info(ail, FrameKind::Ethernet)?;
    let si = crate::platform::info(stub, FrameKind::Ethernet)?;
    crate::platform::validate_pair(&[ai.clone(), si.clone()])?;
    if ai.mac.is_none() || si.mac.is_none() {
        return Err(io::Error::other(
            "pcap Ethernet interface lacks a six-byte MAC",
        ));
    }
    let api = Api::load(library)?;
    let a = PcapHandle::open(api.clone(), ail)?;
    let s = PcapHandle::open(api, stub)?;
    Backend::new(
        [
            Box::new(Device::new(CapturePort::new(a), NativeFraming::Tap, ai.mac)),
            Box::new(Device::new(CapturePort::new(s), NativeFraming::Tap, si.mac)),
        ],
        [ai, si],
    )
}
