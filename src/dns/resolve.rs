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
    fn resolve(&mut self,
               qname: &String,
               qtype: QueryType,
               recursive: bool) -> Result<DnsPacket>;
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
    fn resolve(&mut self,
               qname: &String,
               qtype: QueryType,
               recursive: bool) -> Result<DnsPacket> {

        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        if let Some(qr) = self.context.authority.query(qname, qtype.clone()) {
            return Ok(qr);
        }

        if !recursive || !self.context.allow_recursive {
            return Ok(DnsPacket::new());
        }

        if let Ok(Some(qr)) = self.context.cache.lookup(qname, qtype.clone()) {
            return Ok(qr);
        }

        if let Some(ref server) = self.context.forward_server {
            let &(ref host, port) = server;
            let result = self.context.udp_client.send_query(qname,
                                                            qtype.clone(),
                                                            (host.as_str(), port),
                                                            true);

            if let Ok(ref qr) = result {
                let _ = self.context.cache.update(&qr.answers);
            } else {
                return Ok(DnsPacket::new());
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
    fn resolve(&mut self,
               qname: &String,
               qtype: QueryType,
               recursive: bool) -> Result<DnsPacket> {

        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }

        if let Some(qr) = self.context.authority.query(qname, qtype.clone()) {
            return Ok(qr);
        }

        if !recursive || !self.context.allow_recursive {
            return Ok(DnsPacket::new());
        }

        if let Ok(Some(qr)) = self.context.cache.lookup(qname, qtype.clone()) {
            return Ok(qr);
        }

        // Set us up for failure
        let err = Error::new(ErrorKind::NotFound, "No DNS server found");
        let mut final_result: Result<DnsPacket> = Err(err);

        let mut tentative_ns = None;

        // Find the closest
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

        if let Some(ns_cand) = tentative_ns {

            let mut ns = ns_cand;

            // Start querying name servers
            loop {
                //println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

                let ns_copy = ns.clone();

                let server = (&*ns_copy, 53);
                let response = try!(self.context.udp_client.send_query(qname,
                                                                       qtype.clone(),
                                                                       server,
                                                                       false));

                // If we've got an actual answer, we're done!
                if response.answers.len() > 0 ||
                   response.header.rescode == ResultCode::NXDOMAIN {

                    final_result = Ok(response.clone());
                    let _ = self.context.cache.update(&response.answers);
                    let _ = self.context.cache.update(&response.authorities);
                    let _ = self.context.cache.update(&response.resources);
                    break;
                }

                // Otherwise, try to find a new nameserver based on NS and a
                // corresponding A record in the additional section
                if let Some(new_ns) = response.get_resolved_ns(qname) {
                    // If there is such a record, we can retry the loop with that NS
                    ns = new_ns.clone();
                    let _ = self.context.cache.update(&response.answers);
                    let _ = self.context.cache.update(&response.authorities);
                    let _ = self.context.cache.update(&response.resources);
                }
                else {
                    // If not, we'll have to resolve the ip of a NS record
                    if let Some(new_ns_name) = response.get_unresolved_ns(qname) {

                        // Recursively resolve the NS
                        let recursive_response = try!(self.resolve(&new_ns_name,
                                                                   QueryType::A,
                                                                   true));

                        // Pick a random IP and restart
                        if let Some(new_ns) = recursive_response.get_random_a() {
                            ns = new_ns.clone();
                            continue;
                        }
                    }

                    // If there's no NS record at all, we're screwed
                    final_result = Ok(response.clone());
                    break;
                }
            }
        }

        final_result
    }
}
