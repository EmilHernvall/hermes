use std::io::Result;

use dns::protocol::{QueryType, QueryResult};

pub trait DnsClient {
    fn send_query(&self,
                  qname: &String,
                  qtype: QueryType,
                  server: (&str, u16)) -> Result<QueryResult>;
}
