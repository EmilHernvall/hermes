//! The ServerContext in this thread holds the common state across the server

use std::io::Result;
use std::sync::Arc;

use dns::resolve::{DnsResolver,RecursiveDnsResolver,ForwardingDnsResolver};
use dns::client::DnsUdpClient;
use dns::cache::SynchronizedCache;
use dns::authority::Authority;

pub struct ServerContext {
    pub authority: Authority,
    pub cache: SynchronizedCache,
    pub udp_client: DnsUdpClient,
    pub dns_port: u16,
    pub api_port: u16,
    pub forward_server: Option<(String, u16)>,
    pub allow_recursive: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub enable_api: bool,
}

impl ServerContext {
    pub fn new() -> ServerContext {
        ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            udp_client: DnsUdpClient::new(),
            dns_port: 53,
            api_port: 5380,
            forward_server: None,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true
        }
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Start UDP client thread
        try!(self.udp_client.run());

        // Load authority data
        try!(self.authority.load());

        Ok(())
    }

    pub fn create_resolver(&self, ptr: Arc<ServerContext>) -> Box<DnsResolver> {
        if self.forward_server.is_some() {
            Box::new(ForwardingDnsResolver::new(ptr))
        } else {
            Box::new(RecursiveDnsResolver::new(ptr))
        }
    }
}
