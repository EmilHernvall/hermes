//! resolver implementations implementing different strategies for answering
//! incoming queries

use std::io::Result;
use std::vec::Vec;
use std::io::{Error, ErrorKind};
use std::sync::Arc;

use dns::protocol::{QueryType, DnsPacket, ResultCode};
use dns::client::DnsClient;
use dns::context::ServerContext;

pub trait DnsResolver {

    fn get_context(&self) -> Arc<ServerContext>;

    fn resolve(&mut self,
               qname: &String,
               qtype: QueryType,
               recursive: bool) -> Result<DnsPacket> {

        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        let context = self.get_context();

        if let Some(qr) = context.authority.query(qname, qtype.clone()) {
            return Ok(qr);
        }

        if !recursive || !context.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Ok(Some(qr)) = context.cache.lookup(qname, qtype.clone()) {
            return Ok(qr);
        }

        self.perform(qname, qtype)
    }

    fn perform(&mut self, qname: &String, qtype: QueryType) -> Result<DnsPacket>;
}

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
pub struct ForwardingDnsResolver {
    context: Arc<ServerContext>
}

impl ForwardingDnsResolver {
    pub fn new(context: Arc<ServerContext>) -> ForwardingDnsResolver {
        ForwardingDnsResolver {
            context: context
        }
    }
}

impl DnsResolver for ForwardingDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        return self.context.clone();
    }

    fn perform(&mut self,
               qname: &String,
               qtype: QueryType) -> Result<DnsPacket> {

        if let Some(ref server) = self.context.forward_server {
            let &(ref host, port) = server;
            let result = self.context.client.send_query(qname,
                                                        qtype.clone(),
                                                        (host.as_str(), port),
                                                        true);

            if let Ok(ref qr) = result {
                let _ = self.context.cache.update(&qr.answers);
            }

            return result;
        }

        Err(Error::new(ErrorKind::NotFound, "No DNS server found"))
    }
}

/// A Recursive DNS resolver
///
/// This resolver can answer any request using the root servers of the internet
pub struct RecursiveDnsResolver {
    context: Arc<ServerContext>
}

impl RecursiveDnsResolver {
    pub fn new(context: Arc<ServerContext>) -> RecursiveDnsResolver {
        RecursiveDnsResolver {
            context: context
        }
    }
}

impl DnsResolver for RecursiveDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        return self.context.clone();
    }

    fn perform(&mut self,
               qname: &String,
               qtype: QueryType) -> Result<DnsPacket> {

        // Find the closest name server by splitting the label and progessively
        // moving towards the root servers
        let mut tentative_ns = None;

        let labels = qname.split('.').collect::<Vec<&str>>();
        for lbl_idx in 0..labels.len()+1 {
            let domain = labels[lbl_idx..labels.len()].join(".");

            if let Ok(Some(qr)) = self.context.cache.lookup(&domain, QueryType::NS) {

                if let Some(new_ns) = qr.get_resolved_ns(&domain) {
                    tentative_ns = Some(new_ns.clone());
                    break;
                }
            }
        }

        let mut ns = match tentative_ns {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::NotFound, "No DNS server found"))
        };

        // Start querying name servers
        loop {
            //println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

            let ns_copy = ns.clone();

            let server = (ns_copy.as_str(), 53);
            let response = try!(self.context.client.send_query(qname,
                                                               qtype.clone(),
                                                               server,
                                                               false));

            // If we've got an actual answer, we're done!
            if response.answers.len() > 0 ||
               response.header.rescode == ResultCode::NXDOMAIN {

                let _ = self.context.cache.update(&response.answers);
                let _ = self.context.cache.update(&response.authorities);
                let _ = self.context.cache.update(&response.resources);
                return Ok(response.clone());
            }

            // Otherwise, try to find a new nameserver based on NS and a
            // corresponding A record in the additional section
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                // If there is such a record, we can retry the loop with that NS
                ns = new_ns.clone();
                let _ = self.context.cache.update(&response.answers);
                let _ = self.context.cache.update(&response.authorities);
                let _ = self.context.cache.update(&response.resources);

                continue;
            }

            // If not, we'll have to resolve the ip of a NS record
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => {
                    let mut packet = DnsPacket::new();
                    packet.header.rescode = ResultCode::NXDOMAIN;
                    return Ok(packet);
                }
            };

            // Recursively resolve the NS
            let recursive_response = try!(self.resolve(&new_ns_name,
                                                       QueryType::A,
                                                       true));

            // Pick a random IP and restart
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns.clone();
                continue;
            }

            // If there's no NS record at all, we're screwed
            return Ok(response.clone());
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;
    use std::net::Ipv4Addr;

    use dns::protocol::{DnsPacket, QueryType, ResourceRecord, ResultCode};

    use super::*;

    use dns::context::tests::create_test_context;

    #[test]
    fn test_forwarding_resolver() {
        let mut context = create_test_context(
            Box::new(|qname, _, _, _| {
                let mut packet = DnsPacket::new();

                if qname == "google.com" {
                    packet.answers.push(ResourceRecord::A {
                        domain: "google.com".to_string(),
                        addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                        ttl: 3600
                    });
                } else {
                    packet.header.rescode = ResultCode::NXDOMAIN;
                }

                Ok(packet)
            }));

        match Arc::get_mut(&mut context) {
            Some(mut ctx) => {
                ctx.forward_server = Some(("127.0.0.1".to_string(), 53));
            },
            None => panic!()
        }

        let mut resolver = context.create_resolver(context.clone());

        // First verify that we get a match back
        {
            let res = match resolver.resolve(&"google.com".to_string(),
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                ResourceRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                },
                _ => panic!()
            }
        };

        // Do the same lookup again, and verify that it's present in the cache
        // and that the counter has been updated
        {
            let res = match resolver.resolve(&"google.com".to_string(),
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            let list = match context.cache.list() {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, list.len());

            assert_eq!("google.com", list[0].domain);
            assert_eq!(1, list[0].records.len());
            assert_eq!(1, list[0].hits);

        };

        // Do a failed lookup
        {
            let res = match resolver.resolve(&"yahoo.com".to_string(),
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(0, res.answers.len());
            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
        };

    }

    #[test]
    fn test_recursive_resolver() {
        let context = create_test_context(
            Box::new(|qname, _, _, _| {
                let mut packet = DnsPacket::new();

                if qname == "google.com" {
                    packet.answers.push(ResourceRecord::A {
                        domain: "google.com".to_string(),
                        addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                        ttl: 3600
                    });
                } else {
                    packet.header.rescode = ResultCode::NXDOMAIN;
                }

                Ok(packet)
            }));

        let mut nameservers = Vec::new();
        nameservers.push(ResourceRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: 3600
        });
        nameservers.push(ResourceRecord::A {
            domain: "ns1.google.com".to_string(),
            addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
            ttl: 3600
        });

        let _ = context.cache.update(&nameservers);

        let mut resolver = context.create_resolver(context.clone());

        // Check that we can successfully resolve
        {
            let res = match resolver.resolve(&"google.com".to_string(),
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                ResourceRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                },
                _ => panic!()
            }
        };

        // Now check that the cache is used, and that the statistics is correct
        {
            let res = match resolver.resolve(&"google.com".to_string(),
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            let list = match context.cache.list() {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            assert_eq!(2, list.len());

            assert_eq!("google.com", list[0].domain);
            assert_eq!(2, list[0].records.len());
            assert_eq!(3, list[0].hits);

            assert_eq!("ns1.google.com", list[1].domain);
            assert_eq!(1, list[1].hits);
        };

        // Do a failed lookup
        {
            let res = match resolver.resolve(&"something.google.com".to_string(),
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(0, res.answers.len());
            assert_eq!(ResultCode::NXDOMAIN, res.header.rescode);
        };
    }
}

