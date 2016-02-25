use std::io::Result;

use dns::protocol::{QueryType, QueryResult};

pub trait DnsClient {
    fn send_query(&mut self,
                  qname: &String,
                  qtype: QueryType) -> Result<QueryResult>;
}

pub trait DnsServer {
    fn run(&mut self) -> bool;
}
