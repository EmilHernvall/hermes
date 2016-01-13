mod dns;

extern crate rand;

use std::io::Result;
use std::env;
use std::vec::Vec;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use rand::random;

use dns::protocol::{ResourceRecord, QueryResult};
use dns::udp::DnsUdpProtocol;

struct Authority {
    suffix: String,
    entries: Vec<ResourceRecord>
}

impl Authority {
    fn new(suffix: String, entries: Vec<&str>) -> Authority {
        let mut entries_vector = Vec::new();

        for s in entries {
            entries_vector.push(ResourceRecord::NS(suffix.clone(), s.to_string(), 3600));
        }

        Authority {
            suffix: suffix,
            entries: entries_vector
        }
    }

    fn get_nameserver(&self) -> String {
        let servers = self.get_name_servers();
        return servers[random::<usize>() % servers.len()].clone();
    }

    fn get_name_servers(&self) -> Vec<String> {
        let mut nameservers = Vec::new();
        for entry in &self.entries {
            if let &ResourceRecord::NS(_, ref host, _) = entry {
                nameservers.push(host.clone());
            }
        }
        nameservers
    }
}

struct DnsResolver {
    cache: HashMap<String, Authority>
}

impl DnsResolver {
    fn new() -> DnsResolver {
        DnsResolver {
            cache: HashMap::new()
        }
    }

    fn compile_authorities(&self,
                           qname: &String,
                           response: &QueryResult,
                           new_authorities: &mut Vec<ResourceRecord>) {

        for auth in &response.authorities {
            println!("processing {:?}", auth);
            if let &ResourceRecord::NS(ref suffix, ref host, _) = auth {
                if suffix != qname {
                    continue;
                }

                for rsrc in &response.resources {
                    if let &ResourceRecord::A(ref host2, ref ip, ref ttl) = rsrc {
                        if host2 != host {
                            continue;
                        }

                        let rec = ResourceRecord::A(host.clone(), ip.clone(), *ttl);
                        new_authorities.push(rec);
                    }
                }
            }

            else if let &ResourceRecord::A(ref domain, ref ip, ttl) = auth {
                println!("cloning resolved authority");
                let rec = ResourceRecord::A(domain.clone(), ip.clone(), ttl);
                new_authorities.push(rec);
            }
        }
    }

    fn resolve_recursive(&self, qname: &String, original: &String) -> Result<QueryResult> {
        println!("{}", qname);

        let mut part = qname.splitn(2, ".").last().unwrap();
        if part == qname {
            part = "";
        }

        println!("part: {}", part);
        let mut nswrap = None;
        if let Some(entry) = self.cache.get(part) {
            nswrap = Some(entry.get_nameserver());
        }
        else {
            println!("");
            let nsresult = self.resolve_recursive(&part.to_string(), original);
            println!("");
            if let Ok(ref nsresponse) = nsresult {
                let auths = &nsresponse.authorities;
                println!("got {} authorities", auths.len());
                if let ResourceRecord::A(_, ip, _) = auths[random::<usize>() % auths.len()] {
                    nswrap = Some(ip.to_string());
                }
            }
        }

        if let Some(ns) = nswrap {
            println!("ns: {}", ns);
            println!("qname: {}", qname);

            let mut resolver = DnsUdpProtocol::new(&ns);
            let result = resolver.send_query(qname);
            if let Ok(ref response) = result {
                if qname != original {
                //if response.answers.len() == 0 {
                    let mut new_authorities = Vec::new();
                    self.compile_authorities(qname, response, &mut new_authorities);

                    println!("passing on {} authorities", new_authorities.len());

                    return Ok(QueryResult {
                        domain: qname.clone(),
                        answers: Vec::new(),
                        authorities: new_authorities,
                        resources: Vec::new()
                    });
                }
                else {
                    //let mut resolver = DnsUdpProtocol::new(&ns);
                    //let result = resolver.send_query(qname);
                }
            }

            return result;
        }
        else {
            println!("no nameserver");
        }

        Err(Error::new(ErrorKind::NotFound, "No DNS server found"))
    }

    fn resolve(&self, qname: &String) -> Result<QueryResult> {
        let result = self.resolve_recursive(qname, qname);
        if let Ok(ref response) = result {
            println!("success");
        }
        else {
            println!("fail");
        }

        result
    }
}

fn main() {

    if let Some(arg1) = env::args().nth(1) {

        /*let part_count = arg1.split(".").count();
        let mut parts = Vec::new();
        for i in 1..part_count+1 {
            let part = arg1.splitn(i, ".").last().unwrap();
            parts.push(part);
        }
        parts.push("");*/

        let mut resolver = DnsResolver::new();

        let rootservers = vec![ "198.41.0.4",
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
                                "202.12.27.33" ];

        resolver.cache.insert("".to_string(), Authority::new("".to_string(), rootservers));

        if let Ok(result) = resolver.resolve(&arg1) {
            println!("");
            println!("query domain: {0}", result.domain);

            println!("answers:");
            for x in result.answers {
                println!("\t{:?}", x);
            }

            println!("authorities:");
            for x in result.authorities {
                println!("\t{:?}", x);
            }

            println!("resources:");
            for x in result.resources {
                println!("\t{:?}", x);
            }

        }
    }
    else {
        println!("usage: ./resolve <domain>");
    }
}
