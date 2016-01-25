use std::io::Result;
use std::vec::Vec;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use rand::random;

use dns::protocol::{ResourceRecord, QueryType, QueryResult};
use dns::udp::DnsUdpClient;

pub struct RecordSet {
    pub records: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>
}

impl RecordSet {
    pub fn from_query_result(qr: &QueryResult) -> RecordSet {
        let mut rs = RecordSet {
            records: Vec::new(),
            authorities: Vec::new(),
            additional: Vec::new()
        };

        rs.records.extend(qr.answers.iter().cloned());
        rs.authorities.extend(qr.authorities.iter().cloned());
        rs.additional.extend(qr.resources.iter().cloned());

        rs
    }

    pub fn to_query_result(&self) -> QueryResult {
        let mut qr = QueryResult {
            id: 0,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        };

        qr.answers.extend(self.records.iter().cloned());
        qr.authorities.extend(self.authorities.iter().cloned());
        qr.resources.extend(self.additional.iter().cloned());

        qr
    }
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

    fn resolve_nameserver(&mut self, qname: &String) -> Result<QueryResult> {

        if let Some(rs) = self.cache.get(qname) {
            println!("cache hit for {}", qname);
            return Ok(rs.to_query_result());
        }

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
                nswrap = nsresponse.get_random_ns(qname);
                //let auths = &nsresponse.authorities;

                //let idx = random::<usize>() % auths.len();
                //if let ResourceRecord::A(_, ip, _) = auths[idx] {
                //    nswrap = Some(ip.to_string());
                //}
            }

            final_result = nsresult;
        }

        // Perform lookup of the nameserver against the selected name server
        if let Some(ns) = nswrap {
            let mut resolver = DnsUdpClient::new(&ns);

            let result = resolver.send_query(qname, QueryType::NS);
            if let Ok(response) = result {
                self.cache.insert(qname.to_string(), RecordSet::from_query_result(&response));

                //let mut new_authorities = Vec::new();
                //self.compile_authorities(qname, &response, &mut new_authorities);

                // Check if new authorities are available. If they are not,
                // fall through and return the previous result.
                if response.authorities.len() > 0 {
                    return Ok(response.clone());
                    //println!("qname={} ns={}", qname, ns);
                    //return Ok(QueryResult {
                    //    id: 0,
                    //    questions: Vec::new(),
                    //    answers: Vec::new(),
                    //    authorities: new_authorities,
                    //    resources: Vec::new()
                    //});
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
        //if let Ok(ref response) = res {
        //    //println!("matched domain: {}", response.domain);

        //    // Pick a random name server
        //    let auths = &response.authorities;
        //    let idx = random::<usize>() % auths.len();
        //    if let ResourceRecord::A(_, ip, _) = auths[idx] {
        //        let ipstr = ip.to_string();

        //        // Perform a fresh query for an A record against that nameserver
        //        let mut resolver = DnsUdpClient::new(&ipstr);
        //        return resolver.send_query(qname, QueryType::A);
        //    }
        //}

        res
        //Err(Error::new(ErrorKind::NotFound, "No DNS server found"))
    }
}
