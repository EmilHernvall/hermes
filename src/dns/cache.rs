use std::collections::{HashSet,HashMap};
use std::hash::{Hash,Hasher};
use std::sync::mpsc::{channel, Sender};
use std::thread::spawn;
use std::clone::Clone;

use chrono::*;

use dns::protocol::{ResourceRecord, QueryType, DnsPacket};

#[derive(Eq)]
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

pub struct RecordSet {
    pub records: HashSet<RecordEntry>
}

impl RecordSet {
    pub fn new() -> RecordSet {
        RecordSet {
            records: HashSet::new()
        }
    }

    pub fn append_record(&mut self, rec: &ResourceRecord) -> bool {
        let entry = RecordEntry {
                record: rec.clone(),
                timestamp: Local::now()
            };

        if self.records.contains(&entry) {
            self.records.remove(&entry);
        }

        self.records.insert(entry)
    }
}

pub struct Cache {
    records: HashMap<String, RecordSet>
}

impl Cache {
    pub fn new() -> Cache {
        Cache {
            records: HashMap::new()
        }
    }

    fn fill_queryresult(&self,
                        qname: &String,
                        qtype: &QueryType,
                        result_vec: &mut Vec<ResourceRecord>) {

        if let Some(ref rs) = self.records.get(qname) {
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

    pub fn lookup(&self,
                  qname: &String,
                  qtype: QueryType) -> Option<DnsPacket> {

        let mut result = None;

        let mut qr = DnsPacket::new();
        self.fill_queryresult(qname, &qtype, &mut qr.answers);
        if qtype == QueryType::A {
            self.fill_queryresult(qname, &QueryType::CNAME, &mut qr.answers);
        }
        self.fill_queryresult(qname, &QueryType::NS, &mut qr.authorities);

        for authority in &qr.authorities {
            //println!("searching for {:?}", authority);
            if let ResourceRecord::NS(_, ref host, _) = *authority {
                self.fill_queryresult(host, &QueryType::A, &mut qr.resources);
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
            if let Some(ref domain) = rec.get_domain() {
                if let Some(rs) = self.records.get_mut(domain) {
                    if rs.append_record(rec) {
                        //println!("updating record for {}: {:?}", domain, rec);
                    }
                    continue;
                }

                let mut rs = RecordSet::new();
                rs.append_record(rec);
                self.records.insert(domain.clone(), rs);

                //println!("new record for {}: {:?}", domain, rec);
            }
        }

        true
    }
}

enum CacheRequest {
    Update(Vec<ResourceRecord>),
    Query(String, QueryType)
}

enum CacheResponse {
    UpdateOk,
    QueryOk(Option<DnsPacket>)
}

pub type CacheMessage = (CacheRequest, Sender<CacheResponse>);

#[derive(Clone)]
pub struct SynchronizedCache {
    pub tx: Option<Sender<CacheMessage>>
}

impl SynchronizedCache {
    pub fn new() -> SynchronizedCache {
        SynchronizedCache {
            tx: None
        }
    }

    pub fn run(&mut self) {

        let (req_tx, req_rx) = channel();

        self.tx = Some(req_tx);
        //let (res_tx, res_rx) = channel();

        spawn(move || {
            let mut cache = Cache::new();
            for (req, res_tx) in req_rx {
                match req {
                    CacheRequest::Update(records) => {
                        cache.update(&records);
                        let _ = res_tx.send(CacheResponse::UpdateOk);
                    },
                    CacheRequest::Query(qname, qtype) => {
                        let res = cache.lookup(&qname, qtype);
                        let _ = res_tx.send(CacheResponse::QueryOk(res));
                    }
                }
            }
        });
    }

    pub fn lookup(&self,
                  qname: String,
                  qtype: QueryType) -> Option<DnsPacket> {

        if let Some(ref req_tx) = self.tx {
            let (res_tx, res_rx) = channel();
            let _ = req_tx.send((CacheRequest::Query(qname, qtype), res_tx));

            if let Ok(CacheResponse::QueryOk(res)) = res_rx.recv() {
                return res;
            }
        }

        None
    }

    pub fn update(&self, records: Vec<ResourceRecord>) -> bool {
        if let Some(ref req_tx) = self.tx {
            let (res_tx, res_rx) = channel();
            let _ = req_tx.send((CacheRequest::Update(records), res_tx));

            if let Ok(CacheResponse::UpdateOk) = res_rx.recv() {
                return true;
            }
        }

        false
    }
}
