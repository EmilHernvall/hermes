use std::io::Result;
use std::vec::Vec;
use std::io::{Error, ErrorKind};
use rand::random;

use dns::protocol::{ResourceRecord, QueryType, QueryResult};
use dns::udp::DnsUdpClient;

pub struct DnsResolver<'a> {
    rootservers: Vec<&'a str>
}

impl<'a> DnsResolver<'a> {
    pub fn new() -> DnsResolver<'a> {
        DnsResolver {
            rootservers: vec![ "198.41.0.4",
                               "192.228.79.201",
                               "192.33.4.12",
                               "199.7.91.13",
                               "192.203.230.10",
                               "192.5.5.241",
                               "192.112.36.4",
                               "198.97.190.53",
                               "192.36.148.17",
                               "192.58.128.30",
                               "193.0.14.129",
                               "199.7.83.42",
                               "202.12.27.33" ]
        }
    }

    fn compile_authorities(&mut self,
                           qname: &String,
                           response: &QueryResult,
                           new_authorities: &mut Vec<ResourceRecord>) {

        for auth in &response.authorities {
            if let ResourceRecord::NS(ref suffix, ref host, _) = *auth {
                if suffix != qname {
                    continue;
                }

                for rsrc in &response.resources {
                    if let ResourceRecord::A(ref host2, ref ip, ref ttl) = *rsrc {
                        if host2 != host {
                            continue;
                        }

                        let rec = ResourceRecord::A(host.clone(), ip.clone(), *ttl);
                        new_authorities.push(rec);
                    }
                }
            }
        }
    }

    fn resolve_nameserver(&mut self, qname: &String) -> Result<QueryResult> {

        let err = Error::new(ErrorKind::NotFound, "No DNS server found");
        let mut final_result: Result<QueryResult> = Err(err);

        let mut part = qname.splitn(2, ".").last().unwrap();
        if part == qname {
            part = "";
        }

        let mut nswrap = None;

        // If we're at the top level, pick a random root server
        if part == "" {
            let idx = random::<usize>() % self.rootservers.len();
            nswrap = Some(self.rootservers[idx].to_string());
        }

        // Otherwise, call ourselves recursively and pick a random nameserver from
        // the result
        else {
            let nsresult = self.resolve_nameserver(&part.to_string());
            if let Ok(ref nsresponse) = nsresult {
                let auths = &nsresponse.authorities;

                let idx = random::<usize>() % auths.len();
                if let ResourceRecord::A(_, ip, _) = auths[idx] {
                    nswrap = Some(ip.to_string());
                }
            }

            final_result = nsresult;
        }

        // Perform lookup of the nameserver against the selected name server
        if let Some(ns) = nswrap {
            let mut resolver = DnsUdpClient::new(&ns);
            let result = resolver.send_query(qname, QueryType::NS);
            if let Ok(response) = result {
                let mut new_authorities = Vec::new();
                self.compile_authorities(qname, &response, &mut new_authorities);

                // Check if new authorities are available. If they are not,
                // fall through and return the previous result.
                if new_authorities.len() > 0 {
                    //println!("qname={} ns={}", qname, ns);
                    return Ok(QueryResult {
                        id: 0,
                        questions: Vec::new(),
                        answers: Vec::new(),
                        authorities: new_authorities,
                        resources: Vec::new()
                    });
                }
            }
            else {
                return result;
            }
        }

        //println!("qname={}", qname);
        final_result
    }

    pub fn resolve(&mut self, qname: &String) -> Result<QueryResult> {
        // Start out by recursively resolving the nameserver
        let res = self.resolve_nameserver(qname);
        if let Ok(ref response) = res {
            //println!("matched domain: {}", response.domain);

            // Pick a random name server
            let auths = &response.authorities;
            let idx = random::<usize>() % auths.len();
            if let ResourceRecord::A(_, ip, _) = auths[idx] {
                let ipstr = ip.to_string();

                // Perform a fresh query for an A record against that nameserver
                let mut resolver = DnsUdpClient::new(&ipstr);
                return resolver.send_query(qname, QueryType::A);
            }
        }

        res
        //Err(Error::new(ErrorKind::NotFound, "No DNS server found"))
    }
}

