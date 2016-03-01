use std::collections::{BTreeMap,BTreeSet};

use dns::protocol::ResourceRecord;

#[derive(Clone,Debug)]
pub struct Zone {
    pub domain: String,
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub records: BTreeSet<ResourceRecord>
}

impl Zone {
    pub fn new(domain: String, mname: String, rname: String) -> Zone {
        Zone {
            domain: domain,
            mname: mname,
            rname: rname,
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: 0,
            records: BTreeSet::new()
        }
    }

    pub fn add_record(&mut self, rec: &ResourceRecord) -> bool {
        self.records.insert(rec.clone())
    }
}

pub struct Authority {
    pub zones: BTreeMap<String, Zone>
}

impl Authority {
    pub fn new() -> Authority {
        Authority {
            zones: BTreeMap::new()
        }
    }

    pub fn add_zone(&mut self, zone: Zone)
    {
        self.zones.insert(zone.domain.clone(), zone);
    }
}
