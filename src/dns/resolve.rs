use std::io::Result;
use std::vec::Vec;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use rand::random;

use dns::protocol::{ResourceRecord, QueryType, QueryResult};
use dns::udp::DnsUdpClient;

pub struct RecordSet {
    pub records: Vec<ResourceRecord>
}

impl RecordSet {
    pub fn new() -> RecordSet {
        RecordSet {
            records: Vec::new()
        }
    }

    pub fn append_record(&mut self, rec: &ResourceRecord) {
        self.records.push(rec.clone());
    }

    /*pub fn to_query_result(&self) -> QueryResult {
        let mut qr = QueryResult {
            id: 0,
            authoritative: false,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        };

        qr.answers.extend(self.records.iter().cloned());

        qr
    }*/
}

pub struct DnsResolver<'a> {
    rootservers: Vec<&'a str>,
    cache: HashMap<String, RecordSet>
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
                               "202.12.27.33" ],
            cache: HashMap::new()
        }
    }

    fn fill_queryresult_from_cache(&self,
                                   qname: &String,
                                   qtype: QueryType,
                                   result_vec: &mut Vec<ResourceRecord>) {

        if let Some(ref rs) = self.cache.get(qname) {
            //println!("recordset {} has:", qname);
            for rec in &rs.records {
                //println!("entry: {:?}", rec);
                if rec.get_querytype() == qtype {
                    result_vec.push(rec.clone());
                }
            }
        }
    }

    pub fn cache_lookup(&self,
                        qname: &String,
                        qtype: QueryType) -> Option<QueryResult> {
        let mut result = None;

        let mut qr = QueryResult::new(0, false);
        self.fill_queryresult_from_cache(qname, qtype, &mut qr.answers);
        self.fill_queryresult_from_cache(qname, QueryType::NS, &mut qr.authorities);

        for authority in &qr.authorities {
            //println!("searching for {:?}", authority);
            if let ResourceRecord::NS(_, ref host, _) = *authority {
                self.fill_queryresult_from_cache(host, QueryType::A, &mut qr.resources);
            }
        }

        if qr.answers.len() > 0 || qr.authorities.len() > 0 {
            result = Some(qr);
        }

        result
    }

    pub fn update_cache(&mut self,
                        records: &Vec<ResourceRecord>)
    {
        for rec in records {
            if let Some(ref domain) = rec.get_domain() {
                println!("new record for {}: {:?}", domain, rec);
                if let Some(rs) = self.cache.get_mut(domain) {
                    rs.append_record(rec);
                    continue;
                }

                let mut rs = RecordSet::new();
                rs.append_record(rec);
                self.cache.insert(domain.clone(), rs);
            }
        }
    }

    pub fn resolve(&mut self, qname: &String) -> Result<QueryResult> {

        // Set us up for failure
        let err = Error::new(ErrorKind::NotFound, "No DNS server found");
        let mut final_result: Result<QueryResult> = Err(err);

        // Pick a random root server to start out with
        let idx = random::<usize>() % self.rootservers.len();
        let mut ns = self.rootservers[idx].to_string();

        //loop {
        let labels = qname.split('.').collect::<Vec<&str>>();
        for label in (0..labels.len()+1).rev() {
            let domain_idx = if label > 0 { label - 1 } else { 0 };
            let domain = (domain_idx..labels.len()).map(|x| labels[x]).collect::<Vec<&str>>().join(".");

            println!("label: {}", domain);

            let response;
            let mut cached_response = false;

            // Check for a response in cache
            if let Some(qr) = self.cache_lookup(&domain, QueryType::A) {
                response = qr;
                cached_response = true;
                println!("got cache hit for {}", qname);
                response.print();
            }
            // Otherwise, hit an actual nameserver
            else {
                let ns_copy = ns.clone();
                let mut resolver = DnsUdpClient::new(&ns_copy);
                println!("sending ns query for {} using {}", qname, ns);
                response = try!(resolver.send_query(qname, QueryType::A));
                //response.print();
            }

            // If we've got an actual answer, we're done!
            if response.answers.len() > 0 {
                final_result = Ok(response.clone());
                if !cached_response {
                    self.update_cache(&response.answers);
                    self.update_cache(&response.authorities);
                    self.update_cache(&response.resources);
                }
                break;
            }

            // Otherwise, try to find a new nameserver based on NS and a
            // corresponding A record in the additional section
            let resolved_ns = response.get_resolved_ns(qname);
            if let Some(new_ns) = resolved_ns {
                // If there is such a record, we can retry the loop with that NS
                ns = new_ns.clone();
                if !cached_response {
                    self.update_cache(&response.answers);
                    self.update_cache(&response.authorities);
                    self.update_cache(&response.resources);
                }
            }
            else {
                // If not, we'll have to resolve the ip of a NS record
                let unresolved_ns = response.get_unresolved_ns(qname);
                if let Some(new_ns_name) = unresolved_ns {

                    // Recursively resolve the NS
                    let recursive_response = try!(self.resolve(&new_ns_name));

                    // Pick a random IP and restart
                    if let Some(new_ns) = recursive_response.get_random_a(qname) {
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
