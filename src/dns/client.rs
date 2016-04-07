//! holds the Client trait describing an interface for sending DNS queries

use std::io::Result;

use dns::protocol::{QueryType, DnsPacket};

pub trait DnsClient {
    fn send_query(&self,
                  qname: &String,
                  qtype: QueryType,
                  server: (&str, u16),
                  recursive: bool) -> Result<DnsPacket>;
}
