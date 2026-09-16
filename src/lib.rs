pub mod dns;
pub mod ip_reassembly;
pub mod ipv4;
pub mod wire;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Link {
    Ail,
    Stub,
}
impl Link {
    pub fn index(self) -> usize {
        match self {
            Self::Ail => 0,
            Self::Stub => 1,
        }
    }
    pub fn other(self) -> Self {
        match self {
            Self::Ail => Self::Stub,
            Self::Stub => Self::Ail,
        }
    }
}
pub mod config;
pub mod io;
pub mod persist;
pub mod platform;
pub mod router;
pub mod runtime;
pub mod scheduler;
pub mod time;

pub mod service_io;

pub mod mdns;
pub mod srp;

pub mod discovery_proxy;
