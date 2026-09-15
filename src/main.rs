use snac_rs::{
    config::{BackendKind, Config, HELP},
    io::{self as packet_io, PacketIo},
    persist::{FileStore, Identity, StateStore},
    router::{Lifecycle, Router},
    runtime::Driver,
    time::OsRandom,
    Link,
};
use std::{
    io,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn signal_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn wall() -> io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs())
}
fn run() -> io::Result<()> {
    let Some(config) = Config::parse(std::env::args().skip(1))? else {
        println!("{HELP}");
        return Ok(());
    };
    // SAFETY: geteuid reads process credentials and has no pointer arguments.
    if unsafe { libc::geteuid() } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "real backends require root",
        ));
    }
    #[cfg(not(feature = "pcap"))]
    if config.backend == BackendKind::Pcap {
        return Err(io::Error::other(
            "pcap backend requires: cargo build --features pcap",
        ));
    }
    let mut store = FileStore::open(&config.state)?;
    let mut random = OsRandom;
    let attachment = format!("{:?}:{}:{}", config.backend, config.infra, config.stub);
    let mut router = match store.load()? {
        Some(bytes) if bytes.starts_with(b"SNAC-SNAPSHOT-") => {
            Router::restore(&bytes, 0, wall()?, &mut random)?
        }
        Some(bytes) => Router::new(Identity::decode(&bytes)?, 0, &mut random)?,
        None => {
            let identity = Identity::load_or_create(&mut store, &attachment, &mut random)?;
            Router::new(identity, 0, &mut random)?
        }
    };
    router.configure_attachment(
        config.ula_policy,
        Some(config.attachment_id.as_deref().unwrap_or(&attachment)),
        0,
        &mut random,
    )?;
    router.no_stub_default = config.no_stub_default;
    router.always_advertise_ail_routes = config.always_advertise_ail_routes;
    let backend = match config.backend {
        BackendKind::Tap => {
            if let Some((a, s, f)) = config.fds {
                packet_io::virtual_link::open_fds(&config.infra, &config.stub, a, s, f)?
            } else {
                packet_io::virtual_link::open(&config.infra, &config.stub)?
            }
        }
        BackendKind::Pcap => {
            #[cfg(feature = "pcap")]
            {
                packet_io::pcap::open(&config.infra, &config.stub, config.pcap_library.as_deref())?
            }
            #[cfg(not(feature = "pcap"))]
            {
                return Err(io::Error::other("pcap feature disabled"));
            }
        }
    };
    eprintln!("DNS UDP/TCP port 53; DoT port 853");
    for link in [Link::Ail, Link::Stub] {
        eprintln!(
            "{link:?}: {} {:?}, MTU {}, ULA {:?}, router {}",
            backend.info(link).name,
            backend.info(link).kind,
            backend.info(link).mtu,
            router.identity.prefix(link),
            router.identity.link_local(link)
        );
    }
    // SAFETY: handlers only set a lock-free atomic; no allocation or non-signal-safe I/O.
    unsafe {
        libc::signal(libc::SIGINT, signal_stop as *const () as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            signal_stop as *const () as libc::sighandler_t,
        );
    }
    let tls_path = config.tls_identity_path();
    let identity =
        snac_rs::service_io::identity::TlsIdentity::load_file(&tls_path, wall()?, &mut random)?;
    let mut tls_renew_at = identity.expires_at()?;
    let mut driver = Driver::new(router, backend)?;
    driver.enable_dot(identity.server_config()?.into())?;

    driver.dns.set_srp_clock(wall()?, 0);
    driver.dns.set_additional_a(!config.no_additional_a);
    driver.dns_discovery.set_configured(&config.dns_upstreams)?;
    let clock = Instant::now();
    driver.start(0, &mut random)?;
    let mut checkpoint_writer = snac_rs::persist::CheckpointWriter::default();
    let mut last_status = String::new();
    loop {
        let now = clock.elapsed().as_millis() as u64;
        let wall_now = wall()?;
        if wall_now >= tls_renew_at {
            let identity = snac_rs::service_io::identity::TlsIdentity::load_file(
                &tls_path,
                wall_now,
                &mut random,
            )?;
            driver.enable_dot(identity.server_config()?.into())?;
            tls_renew_at = identity.expires_at()?;
        }
        if STOP.load(Ordering::Relaxed) {
            driver.router.shutdown(now, &mut random)?;
        }
        driver.step(now, &mut random)?;
        let r = &driver.router;
        let prefixes: Vec<_> = [Link::Ail, Link::Stub]
            .into_iter()
            .flat_map(|l| {
                r.snapshot(l, now).pios.into_iter().map(move |p| {
                    (
                        l,
                        p.prefix,
                        if p.preferred == 0 {
                            "deprecated"
                        } else {
                            "preferred"
                        },
                    )
                })
            })
            .collect();
        let status = format!(
            "{:?}; AIL {:?} up={}; stub {:?} up={}; PD {:?}; default={}; prefixes={prefixes:?}",
            r.lifecycle,
            r.state(Link::Ail),
            r.links[0].up,
            r.state(Link::Stub),
            r.links[1].up,
            r.pd.state,
            r.default_lifetime(now) > 0,
        );
        if status != last_status {
            eprintln!("{now}ms {status}");
            last_status = status;
        }
        checkpoint_writer.save(&driver.router, &mut store, now, wall()?)?;
        if driver.router.lifecycle == Lifecycle::Stopped {
            break;
        }
        let timeout = Duration::from_millis(driver.next_deadline(now).saturating_sub(now).min(100));
        if let Some(rx) = driver.receive(timeout, now, &mut random)? {
            driver.accept(rx, clock.elapsed().as_millis() as u64, &mut random)?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("snac-router: {e}");
        std::process::exit(1);
    }
}
