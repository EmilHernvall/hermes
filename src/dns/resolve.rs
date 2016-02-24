use std::io::Result;
use std::vec::Vec;
use std::io::{Error, ErrorKind};
use rand::random;

use dns::protocol::{QueryType, QueryResult};
use dns::udp::DnsUdpClient;
use dns::cache::SynchronizedCache;

pub struct DnsResolver<'a> {
    rootservers: Vec<&'a str>,
    cache: &'a SynchronizedCache
}

impl<'a> DnsResolver<'a> {
    pub fn new(cache: &'a SynchronizedCache) -> DnsResolver<'a> {
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
                               "202.12.27.33" ],
            cache: cache
        }
    }

    pub fn resolve(&mut self, qname: &String) -> Result<QueryResult> {

        if let Some(qr) = self.cache.lookup(qname.clone(), QueryType::A) {
            println!("got A cache hit for {}", qname);
            return Ok(qr);
        }

        // Set us up for failure
        let err = Error::new(ErrorKind::NotFound, "No DNS server found");
        let mut final_result: Result<QueryResult> = Err(err);

        // Pick a random root server to start out with
        let idx = random::<usize>() % self.rootservers.len();
        let mut ns = self.rootservers[idx].to_string();

        // Next, try to do better than hitting the root servers by finding a closer
        // NS in the cache
        let labels = qname.split('.').collect::<Vec<&str>>();
        for lbl_idx in 0..labels.len()+1 {
            let domain = labels[lbl_idx..labels.len()].join(".");

            //println!("label: {}", domain);

            if let Some(qr) = self.cache.lookup(domain.clone(), QueryType::NS) {
                println!("got ns cache hit for {}", domain);
                //qr.print();

                if let Some(new_ns) = qr.get_resolved_ns(&domain) {
                    ns = new_ns.clone();
                    break;
                }
            }
        }

        // Start querying name servers
        loop {
            println!("attempting lookup of {} with ns {}", qname, ns);

            let ns_copy = ns.clone();
            let mut resolver = DnsUdpClient::new(&ns_copy);
            println!("sending ns query for {} using {}", qname, ns);
            let response = try!(resolver.send_query(qname, QueryType::A));
            //response.print();

            // If we've got an actual answer, we're done!
            if response.answers.len() > 0 {
                final_result = Ok(response.clone());
                self.cache.update(response.answers);
                self.cache.update(response.authorities);
                self.cache.update(response.resources);
                break;
            }

            // Otherwise, try to find a new nameserver based on NS and a
            // corresponding A record in the additional section
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                // If there is such a record, we can retry the loop with that NS
                ns = new_ns.clone();
                self.cache.update(response.answers);
                self.cache.update(response.authorities);
                self.cache.update(response.resources);
            }
            else {
                // If not, we'll have to resolve the ip of a NS record
                if let Some(new_ns_name) = response.get_unresolved_ns(qname) {

                    // Recursively resolve the NS
                    let recursive_response = try!(self.resolve(&new_ns_name));

                    // Pick a random IP and restart
                    if let Some(new_ns) = recursive_response.get_random_a() {
                        ns = new_ns.clone();
                        continue;
                    }
                }

                // If there's no NS record at all, we're screwed
                break;
            }
        }

        final_result
    }
}
