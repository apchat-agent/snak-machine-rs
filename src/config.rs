use std::{io, path::PathBuf};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendKind {
    Tap,
    Pcap,
}
#[derive(Debug)]
pub struct Config {
    pub ula_policy: crate::router::attachment::UlaPolicy,
    pub attachment_id: Option<String>,
    pub backend: BackendKind,
    pub infra: String,
    pub stub: String,
    pub state: PathBuf,
    pub no_stub_default: bool,
    pub always_advertise_ail_routes: bool,
    pub pcap_library: Option<String>,
    pub dns_upstreams: Vec<std::net::SocketAddr>,
    pub no_additional_a: bool,
    pub fds: Option<(i32, i32, crate::io::NativeFraming)>,
}
pub const HELP:&str="snac-router --backend tap|pcap --stub IF --infra IF [--state FILE]\n  --ula-policy rotate|fixed  --attachment-id ID\n  --no-stub-default  --always-advertise-ail-routes\n  --dns-upstream IP:PORT (repeat up to 8)  --no-additional-a\n  --pcap-library PATH  (requires cargo feature pcap)\n  --infra-fd N --stub-fd N --framing ethernet|utun|raw (tap harness mode)\n  --nat64 disabled (the only supported NAT64 setting)\nDNS UDP/TCP and DoT use ports 53/853. SRP, discovery proxies and NAT64 are not yet implemented.\nReal backends require root; --help opens no interfaces.";
impl Config {
    pub fn tls_identity_path(&self) -> PathBuf {
        let mut name = self.state.as_os_str().to_owned();
        name.push(".tls");
        name.into()
    }

    pub fn parse<S: Into<String>>(args: impl IntoIterator<Item = S>) -> io::Result<Option<Self>> {
        let args: Vec<String> = args
            .into_iter()
            .map(Into::into)
            .flat_map(|s: String| {
                if let Some((key, value)) = s.split_once('=') {
                    vec![key.to_owned(), value.to_owned()]
                } else {
                    vec![s]
                }
            })
            .collect();
        if args.iter().any(|a| a == "--help" || a == "-h") {
            return Ok(None);
        }
        let mut dns_upstreams = vec![];
        let mut no_additional_a = false;
        let mut ula_policy = crate::router::attachment::UlaPolicy::Rotate;
        let mut attachment_id = None;
        let mut iter = args.into_iter();
        let (mut backend, mut infra, mut stub) = (None, None, None);
        let mut state = PathBuf::from("snac.state");
        let (mut no_stub_default, mut always_advertise_ail_routes) = (false, false);
        let (mut pcap_library, mut af, mut sf, mut framing) = (None, None, None, None);
        while let Some(key) = iter.next() {
            if key == "--no-additional-a" {
                no_additional_a = true;
                continue;
            }
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
                "--ula-policy" => {
                    ula_policy = match value.as_str() {
                        "rotate" => crate::router::attachment::UlaPolicy::Rotate,
                        "fixed" => crate::router::attachment::UlaPolicy::Fixed,
                        _ => return Err(io::Error::other("ULA policy must be rotate or fixed")),
                    }
                }
                "--attachment-id" => {
                    if value.is_empty() || value.len() > 128 {
                        return Err(io::Error::other("attachment ID must contain 1..128 bytes"));
                    }
                    attachment_id = Some(value);
                }
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
                "--dns-upstream" => {
                    let a: std::net::SocketAddr = value.parse().map_err(io::Error::other)?;
                    if dns_upstreams.len() >= 8
                        || a.port() == 0
                        || a.ip().is_unspecified()
                        || a.ip().is_multicast()
                    {
                        return Err(io::Error::other("invalid DNS upstream"));
                    }
                    dns_upstreams.push(a);
                }
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
            ula_policy,
            attachment_id,
            backend,
            infra,
            stub,
            state,
            no_stub_default,
            always_advertise_ail_routes,
            pcap_library,
            dns_upstreams,
            no_additional_a,
            fds,
        }))
    }
}
