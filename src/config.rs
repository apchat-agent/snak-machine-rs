use std::{io, path::PathBuf};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    Tap,
    Pcap,
}
#[derive(Debug)]
pub struct Config {
    pub backend: BackendKind,
    pub infra: String,
    pub stub: String,
    pub state: PathBuf,
    pub no_stub_default: bool,
    pub always_advertise_ail_routes: bool,
    pub pcap_library: Option<String>,
    pub fds: Option<(i32, i32, crate::io::NativeFraming)>,
}
pub const HELP:&str="snac-router --backend tap|pcap --stub IF --infra IF [--state FILE]\n  --no-stub-default  --always-advertise-ail-routes\n  --pcap-library PATH  (requires cargo feature pcap)\n  --infra-fd N --stub-fd N --framing ethernet|utun|raw (tap harness mode)\n  --nat64 disabled (the only supported NAT64 setting)\nRouting prototype: DNS/DNS-SD/SRP/DoT and NAT64 are not implemented.\nReal backends require root; --help opens no interfaces.";
impl Config {
    pub fn parse<S: Into<String>>(args: impl IntoIterator<Item = S>) -> io::Result<Option<Self>> {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        if args.iter().any(|a| a == "--help" || a == "-h") {
            return Ok(None);
        }
        let mut iter = args.into_iter();
        let (mut backend, mut infra, mut stub) = (None, None, None);
        let mut state = PathBuf::from("snac.state");
        let (mut no_stub_default, mut always_advertise_ail_routes) = (false, false);
        let (mut pcap_library, mut af, mut sf, mut framing) = (None, None, None, None);
        while let Some(key) = iter.next() {
            if key == "--no-stub-default" {
                no_stub_default = true;
                continue;
            }
            if key == "--always-advertise-ail-routes" {
                always_advertise_ail_routes = true;
                continue;
            }
            let value = iter
                .next()
                .ok_or_else(|| io::Error::other(format!("missing value for {key}")))?;
            match key.as_str() {
                "--backend" => {
                    backend = Some(match value.as_str() {
                        "tap" => BackendKind::Tap,
                        "pcap" => BackendKind::Pcap,
                        _ => return Err(io::Error::other("backend must be tap or pcap")),
                    })
                }
                "--infra" => infra = Some(value),
                "--stub" => stub = Some(value),
                "--state" => state = value.into(),
                "--pcap-library" => pcap_library = Some(value),
                "--nat64" if value == "disabled" => {}
                "--nat64" => return Err(io::Error::other("NAT64 is not implemented")),
                "--infra-fd" => af = Some(value.parse::<i32>().map_err(io::Error::other)?),
                "--stub-fd" => sf = Some(value.parse::<i32>().map_err(io::Error::other)?),
                "--framing" => {
                    framing = Some(match value.as_str() {
                        "ethernet" => crate::io::NativeFraming::Tap,
                        "utun" => crate::io::NativeFraming::Utun,
                        "raw" => crate::io::NativeFraming::RawIpv6,
                        _ => return Err(io::Error::other("unknown descriptor framing")),
                    })
                }
                _ => return Err(io::Error::other(format!("unknown option {key}"))),
            }
        }
        let backend = backend.ok_or_else(|| io::Error::other("--backend is required"))?;
        let infra = infra.ok_or_else(|| io::Error::other("--infra is required"))?;
        let stub = stub.ok_or_else(|| io::Error::other("--stub is required"))?;
        if infra == stub || infra.is_empty() || stub.is_empty() {
            return Err(io::Error::other("select two distinct interface names"));
        }
        let fds = match (af, sf, framing) {
            (None, None, None) => None,
            (Some(a), Some(s), Some(f))
                if a >= 0 && s >= 0 && a != s && backend == BackendKind::Tap =>
            {
                Some((a, s, f))
            }
            _ => return Err(io::Error::other(
                "FD mode requires two distinct descriptors and explicit framing with backend tap",
            )),
        };
        Ok(Some(Self {
            backend,
            infra,
            stub,
            state,
            no_stub_default,
            always_advertise_ail_routes,
            pcap_library,
            fds,
        }))
    }
}
