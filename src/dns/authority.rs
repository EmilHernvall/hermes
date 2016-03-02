use std::collections::{BTreeMap,BTreeSet};
use std::sync::{RwLock, LockResult, RwLockReadGuard, RwLockWriteGuard};

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

pub struct Zones {
    zones: BTreeMap<String, Zone>
}

impl<'a> Zones {
    pub fn new() -> Zones {
        Zones {
            zones: BTreeMap::new()
        }
    }

    pub fn zones(&self) -> Vec<&Zone>
    {
        self.zones.values().map(|x| x).collect()
    }

    pub fn add_zone(&mut self, zone: Zone)
    {
        self.zones.insert(zone.domain.clone(), zone);
    }

    pub fn get_zone(&'a self, domain: &str) -> Option<&'a Zone>
    {
        self.zones.get(domain)
    }

    pub fn get_zone_mut(&'a mut self, domain: &str) -> Option<&'a mut Zone>
    {
        self.zones.get_mut(domain)
    }
}

pub struct Authority {
    zones: RwLock<Zones>
}

impl Authority {
    pub fn new() -> Authority {
        Authority {
            zones: RwLock::new(Zones::new())
        }
    }

    pub fn read(&self) -> LockResult<RwLockReadGuard<Zones>>
    {
        self.zones.read()
    }

    pub fn write(&self) -> LockResult<RwLockWriteGuard<Zones>>
    {
        self.zones.write()
    }
}

