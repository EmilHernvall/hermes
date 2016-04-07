//! a threadsafe cache for DNS information

use std::collections::{HashSet,BTreeMap};
use std::hash::{Hash,Hasher};
use std::sync::{Arc, RwLock};
use std::clone::Clone;
use std::io::{Write,Result,Error,ErrorKind};

use chrono::*;

use dns::protocol::{ResourceRecord, QueryType, DnsPacket};

#[derive(Clone,Eq)]
pub struct RecordEntry {
    pub record: ResourceRecord,
    pub timestamp: DateTime<Local>
}

impl PartialEq<RecordEntry> for RecordEntry {
    fn eq(&self, other: &RecordEntry) -> bool {
        self.record == other.record
    }
}

impl Hash for RecordEntry {
    fn hash<H>(&self, state: &mut H) where H: Hasher {
        self.record.hash(state);
    }
}

#[derive(Clone)]
pub struct RecordSet {
    pub domain: String,
    pub records: HashSet<RecordEntry>,
    pub hits: u32,
    pub updates: u32
}

impl RecordSet {
    pub fn new(domain: String) -> RecordSet {
        RecordSet {
            domain: domain,
            records: HashSet::new(),
            hits: 0,
            updates: 0
        }
    }

    pub fn append_record(&mut self, rec: &ResourceRecord) -> bool {
        self.updates += 1;

        let entry = RecordEntry {
                record: rec.clone(),
                timestamp: Local::now()
            };

        println!("cache entry update: {:?} ", rec);
        if self.records.contains(&entry) {
            self.records.remove(&entry);
        }

        self.records.insert(entry)
    }
}

pub struct Cache {
    records: BTreeMap<String, Arc<RecordSet>>
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            records: BTreeMap::new()
        }
    }

    fn fill_queryresult(&mut self,
                        qname: &String,
                        qtype: &QueryType,
                        result_vec: &mut Vec<ResourceRecord>,
                        increment_stats: bool) {

        if let Some(ref mut rs) = self.records.get_mut(qname).and_then(|x| Arc::get_mut(x)) {

            if increment_stats {
                rs.hits += 1;
            }

            let now = Local::now();
            //println!("recordset {} has:", qname);
            for entry in &rs.records {
                //println!("entry: {:?}", rec);
                let ttl_offset = Duration::seconds(entry.record.get_ttl() as i64);
                let expires = entry.timestamp + ttl_offset;
                if expires < now {
                    continue;
                }

                if entry.record.get_querytype() == *qtype {
                    result_vec.push(entry.record.clone());
                }
            }
        }
    }

    pub fn lookup(&mut self,
                  qname: &String,
                  qtype: QueryType) -> Option<DnsPacket> {

        let mut result = None;

        let mut qr = DnsPacket::new();
        self.fill_queryresult(qname, &qtype, &mut qr.answers, true);
        if qtype == QueryType::A {
            self.fill_queryresult(qname, &QueryType::CNAME, &mut qr.answers, false);
        }
        self.fill_queryresult(qname, &QueryType::NS, &mut qr.authorities, false);

        for authority in &qr.authorities {
            //println!("searching for {:?}", authority);
            if let ResourceRecord::NS { ref host, .. } = *authority {
                self.fill_queryresult(host, &QueryType::A, &mut qr.resources, false);
            }
        }

        if qtype == QueryType::NS {
            if qr.authorities.len() > 0 {
                result = Some(qr);
            }
        }
        else {
            if qr.answers.len() > 0 {
                result = Some(qr);
            }
        }

        result
    }

    pub fn update(&mut self, records: &Vec<ResourceRecord>) -> bool {

        for rec in records {
            let ref domain = match rec.get_domain() {
                Some(x) => x,
                None => continue
            };

            match self.records.get_mut(domain).and_then(|x| Arc::get_mut(x)) {
                Some(ref mut rs) => {
                    let _ = rs.append_record(rec);
                    continue;
                },
                None => {}
            }

            let mut rs = RecordSet::new(domain.clone());
            rs.append_record(rec);
            self.records.insert(domain.clone(), Arc::new(rs));
        }

        true
    }
}

pub struct SynchronizedCache {
    pub cache: RwLock<Cache>
}

impl SynchronizedCache {
    pub fn new() -> SynchronizedCache {
        SynchronizedCache {
            cache: RwLock::new(Cache::new())
        }
    }

    pub fn list(&self) -> Result<Vec<Arc<RecordSet>>> {
        let cache = match self.cache.read() {
            Ok(x) => x,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to acquire lock"))
        };

        let mut list = Vec::new();

        for (_, rs) in &cache.records {
            list.push(rs.clone());
        }

        Ok(list)
    }

    pub fn lookup(&self,
                  qname: &String,
                  qtype: QueryType) -> Result<Option<DnsPacket>> {

        let mut cache = match self.cache.write() {
            Ok(x) => x,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to acquire lock"))
        };

        Ok(cache.lookup(qname, qtype))
    }

    pub fn update(&self, records: &Vec<ResourceRecord>) -> Result<()> {
        let mut cache = match self.cache.write() {
            Ok(x) => x,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to acquire lock"))
        };

        cache.update(records);

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::net::Ipv4Addr;

    use dns::protocol::{ResourceRecord, QueryType};

    #[test]
    fn test_cache() {
        let mut cache = Cache::new();

        let mut records = Vec::new();
        records.push(ResourceRecord::A {
            domain: "www.google.com".to_string(),
            addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
            ttl: 3600
        });
        records.push(ResourceRecord::A {
            domain: "www.yahoo.com".to_string(),
            addr: "127.0.0.2".parse::<Ipv4Addr>().unwrap(),
            ttl: 0
        });
        records.push(ResourceRecord::CNAME {
            domain: "www.microsoft.com".to_string(),
            host: "www.somecdn.com".to_string(),
            ttl: 3600
        });

        cache.update(&records);

        // Test for successful lookup
        if let Some(packet) = cache.lookup(&"www.google.com".to_string(), QueryType::A) {
            assert_eq!(records[0], packet.answers[0]);
        } else {
            panic!();
        }

        // Test for failed lookup, since no CNAME's are known for this domain
        if cache.lookup(&"www.google.com".to_string(), QueryType::CNAME).is_some() {
            panic!();
        }

        // Check for successful CNAME lookup
        if let Some(packet) = cache.lookup(&"www.microsoft.com".to_string(), QueryType::CNAME) {
            assert_eq!(records[2], packet.answers[0]);
        } else {
            panic!();
        }

        // A lookups should also include CNAME records
        if let Some(packet) = cache.lookup(&"www.microsoft.com".to_string(), QueryType::A) {
            assert_eq!(records[2], packet.answers[0]);
        } else {
            panic!();
        }

        // This lookup should fail, since it has expired due to the 0 second TTL
        if cache.lookup(&"www.yahoo.com".to_string(), QueryType::A).is_some() {
            panic!();
        }

        let mut records2 = Vec::new();
        records2.push(ResourceRecord::A {
            domain: "www.yahoo.com".to_string(),
            addr: "127.0.0.2".parse::<Ipv4Addr>().unwrap(),
            ttl: 3600
        });

        cache.update(&records2);

        // And now it should succeed, since the record has been updated
        if !cache.lookup(&"www.yahoo.com".to_string(), QueryType::A).is_some() {
            panic!();
        }

        // Check stat counter behavior
        assert_eq!(3, cache.records.len());
        assert_eq!(2, cache.records.get(&"www.google.com".to_string()).unwrap().hits);
        assert_eq!(1, cache.records.get(&"www.google.com".to_string()).unwrap().updates);
        assert_eq!(2, cache.records.get(&"www.yahoo.com".to_string()).unwrap().hits);
        assert_eq!(2, cache.records.get(&"www.yahoo.com".to_string()).unwrap().updates);
        assert_eq!(1, cache.records.get(&"www.microsoft.com".to_string()).unwrap().updates);
        assert_eq!(2, cache.records.get(&"www.microsoft.com".to_string()).unwrap().hits);
    }
}
