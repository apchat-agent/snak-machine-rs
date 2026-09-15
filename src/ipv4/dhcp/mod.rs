pub mod wire;
use super::Route;
use std::net::Ipv4Addr;
#[derive(Clone, Debug)]
pub struct Configuration {
    pub address: Ipv4Addr,
    pub length: u8,
    pub routes: Vec<Route>,
    pub dns: Vec<Ipv4Addr>,
    pub search: Vec<Vec<Vec<u8>>>,
}
#[derive(Clone, Debug)]
pub struct Lease {
    pub config: Configuration,
    pub server: Ipv4Addr,
    pub t1: u64,
    pub t2: u64,
    pub expires: u64,
}
