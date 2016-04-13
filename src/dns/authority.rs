//! contains the data store for local zones

use std::collections::{BTreeMap,BTreeSet};
use std::sync::{RwLock, LockResult, RwLockReadGuard, RwLockWriteGuard};
use std::io::{Write,Result,Error,ErrorKind};
use std::fs::File;
use std::path::Path;

use dns::buffer::{VectorPacketBuffer, PacketBuffer, StreamPacketBuffer};
use dns::protocol::{DnsPacket,DnsRecord,QueryType,ResultCode};

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
    pub records: BTreeSet<DnsRecord>
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

    pub fn add_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.insert(rec.clone())
    }

    pub fn delete_record(&mut self, rec: &DnsRecord) -> bool {
        self.records.remove(rec)
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

    pub fn load(&mut self) -> Result<()> {
        let zones_dir = try!(Path::new("zones").read_dir());

        for wrapped_filename in zones_dir {
            let filename = match wrapped_filename {
                Ok(x) => x,
                Err(_) => continue
            };

            let mut zone_file = match File::open(filename.path()) {
                Ok(x) => x,
                Err(_) => continue
            };

            let mut buffer = StreamPacketBuffer::new(&mut zone_file);

            let mut zone = Zone::new(String::new(), String::new(), String::new());
            try!(buffer.read_qname(&mut zone.domain));
            try!(buffer.read_qname(&mut zone.mname));
            try!(buffer.read_qname(&mut zone.rname));
            zone.serial = try!(buffer.read_u32());
            zone.refresh = try!(buffer.read_u32());
            zone.retry = try!(buffer.read_u32());
            zone.expire = try!(buffer.read_u32());
            zone.minimum = try!(buffer.read_u32());

            let record_count = try!(buffer.read_u32());

            for _ in 0..record_count {
                let rr = try!(DnsRecord::read(&mut buffer));
                zone.add_record(&rr);
            }

            println!("Loaded zone {} with {} records", zone.domain, record_count);

            self.zones.insert(zone.domain.clone(), zone);
        }

        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        let zones_dir = Path::new("zones");
        for (_, zone) in &self.zones {
            let filename = zones_dir.join(Path::new(&zone.domain));
            let mut zone_file = match File::create(&filename) {
                Ok(x) => x,
                Err(_) => {
                    println!("Failed to save file {:?}", filename);
                    continue;
                }
            };

            let mut buffer = VectorPacketBuffer::new();
            let _ = buffer.write_qname(&zone.domain);
            let _ = buffer.write_qname(&zone.mname);
            let _ = buffer.write_qname(&zone.rname);
            let _ = buffer.write_u32(zone.serial);
            let _ = buffer.write_u32(zone.refresh);
            let _ = buffer.write_u32(zone.retry);
            let _ = buffer.write_u32(zone.expire);
            let _ = buffer.write_u32(zone.minimum);
            let _ = buffer.write_u32(zone.records.len() as u32);

            for rec in &zone.records {
                let _ = rec.write(&mut buffer);
            }

            let _ = zone_file.write(&buffer.buffer[0..buffer.pos]);
        }

        Ok(())
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

    pub fn load(&self) -> Result<()>
    {
        let mut zones = match self.zones.write() {
            Ok(x) => x,
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to acquire lock"))
        };

        try!(zones.load());

        Ok(())
    }

    pub fn query(&self, qname: &String, qtype: QueryType) -> Option<DnsPacket>
    {
        let zones = match self.zones.read().ok() {
            Some(x) => x,
            None => return None
        };

        let mut best_match = None;
        for zone in zones.zones() {
            if !qname.ends_with(&zone.domain) {
                continue;
            }

            if let Some((len, _)) = best_match {
                if len < zone.domain.len() {
                    best_match = Some((zone.domain.len(), zone));
                }
            }
            else {
                best_match = Some((zone.domain.len(), zone));
            }
        }

        let zone = match best_match {
            Some((_, zone)) => zone,
            None => return None
        };

        let mut packet = DnsPacket::new();
        packet.header.authoritative_answer = true;

        for rec in &zone.records {
            let domain = match rec.get_domain() {
                Some(x) => x,
                None => continue
            };

            if &domain != qname {
                continue;
            }

            let rtype = rec.get_querytype();
            if qtype == rtype || (qtype == QueryType::A &&
                                  rtype == QueryType::CNAME) {

                packet.answers.push(rec.clone());
            }

        }

        if packet.answers.len() == 0 {
            packet.header.rescode = ResultCode::NXDOMAIN;

            packet.authorities.push(DnsRecord::SOA {
                domain: zone.domain.clone(),
                mname: zone.mname.clone(),
                rname: zone.rname.clone(),
                serial: zone.serial,
                refresh: zone.refresh,
                retry: zone.retry,
                expire: zone.expire,
                minimum: zone.minimum,
                ttl: zone.minimum
            });
        }

        Some(packet)
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

