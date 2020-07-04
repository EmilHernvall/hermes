use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use serde_derive::{Deserialize, Serialize};
use serde_json::json;

use crate::dns::authority::Zone;
use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsRecord, TransientTtl};

use crate::web::cache::CacheRecordEntry;
use crate::web::util::FormDataDecodable;
use crate::web::{Result, WebError};

#[derive(Debug, Serialize, Deserialize)]
pub struct ZoneCreateRequest {
    pub domain: String,
    pub m_name: String,
    pub r_name: String,
    pub serial: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>,
    pub minimum: Option<u32>,
}

impl FormDataDecodable<ZoneCreateRequest> for ZoneCreateRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<ZoneCreateRequest> {
        let mut d: HashMap<_, _> = fields.into_iter().collect();

        let domain = d
            .remove("domain")
            .ok_or_else(|| WebError::MissingField("domain"))?;
        let m_name = d
            .remove("m_name")
            .ok_or_else(|| WebError::MissingField("m_name"))?;
        let r_name = d
            .remove("r_name")
            .ok_or_else(|| WebError::MissingField("r_name"))?;

        Ok(ZoneCreateRequest {
            domain,
            m_name,
            r_name,
            serial: d.get("serial").and_then(|x| x.parse::<u32>().ok()),
            refresh: d.get("refresh").and_then(|x| x.parse::<u32>().ok()),
            retry: d.get("retry").and_then(|x| x.parse::<u32>().ok()),
            expire: d.get("expire").and_then(|x| x.parse::<u32>().ok()),
            minimum: d.get("minimum").and_then(|x| x.parse::<u32>().ok()),
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordRequest {
    pub recordtype: String,
    pub domain: String,
    pub ttl: u32,
    pub host: Option<String>,
}

impl FormDataDecodable<RecordRequest> for RecordRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<RecordRequest> {
        let mut d: HashMap<_, _> = fields.into_iter().collect();

        let recordtype = d
            .remove("recordtype")
            .ok_or_else(|| WebError::MissingField("recordtype"))?;
        let domain = d
            .remove("domain")
            .ok_or_else(|| WebError::MissingField("domain"))?;

        let ttl = d
            .get("ttl")
            .and_then(|x| x.parse::<u32>().ok())
            .ok_or_else(|| WebError::MissingField("ttl"))?;

        Ok(RecordRequest {
            recordtype,
            domain,
            ttl: ttl,
            host: d.remove("host"),
        })
    }
}

impl RecordRequest {
    fn into_resourcerecord(self) -> Option<DnsRecord> {
        match self.recordtype.as_str() {
            "A" => {
                let addr = self.host.and_then(|x| x.parse::<Ipv4Addr>().ok())?;

                Some(DnsRecord::A {
                    domain: self.domain,
                    addr,
                    ttl: TransientTtl(self.ttl),
                })
            }
            "AAAA" => {
                let addr = self.host.and_then(|x| x.parse::<Ipv6Addr>().ok())?;

                Some(DnsRecord::AAAA {
                    domain: self.domain,
                    addr,
                    ttl: TransientTtl(self.ttl),
                })
            }
            "CNAME" => {
                let host = self.host?;

                Some(DnsRecord::CNAME {
                    domain: self.domain,
                    host: host,
                    ttl: TransientTtl(self.ttl),
                })
            }
            _ => None,
        }
    }
}

pub fn zone_list(context: &ServerContext) -> Result<serde_json::Value> {
    let zones = context.authority.read().map_err(|_| WebError::LockError)?;

    let mut zones_json = Vec::new();
    for zone in &zones.zones() {
        zones_json.push(json!({
            "domain": zone.domain,
            "m_name": zone.m_name,
            "r_name": zone.r_name,
            "serial": zone.serial,
            "refresh": zone.refresh,
            "retry": zone.retry,
            "expire": zone.expire,
            "minimum": zone.minimum,
        }));
    }

    Ok(json!({
        "ok": true,
        "zones": zones_json,
    }))
}

pub fn zone_create(context: &ServerContext, request: ZoneCreateRequest) -> Result<Zone> {
    let mut zones = context.authority.write().map_err(|_| WebError::LockError)?;

    let mut zone = Zone::new(request.domain, request.m_name, request.r_name);
    zone.serial = 0;
    zone.refresh = request.refresh.unwrap_or(3600);
    zone.retry = request.retry.unwrap_or(3600);
    zone.expire = request.expire.unwrap_or(3600);
    zone.minimum = request.minimum.unwrap_or(3600);
    zones.add_zone(zone.clone());

    zones.save()?;

    Ok(zone)
}

pub fn zone_view(context: &ServerContext, zone: &str) -> Result<serde_json::Value> {
    let zones = context.authority.read().map_err(|_| WebError::LockError)?;

    let zone = zones.get_zone(zone).ok_or_else(|| WebError::ZoneNotFound)?;

    let mut records = Vec::new();
    for (id, rr) in zone.records.iter().enumerate() {
        records.push(CacheRecordEntry {
            id: id as u32,
            record: rr.clone(),
        });
    }

    Ok(json!({
        "ok": true,
        "zone": zone.domain,
        "records": records,
    }))
}

pub fn record_create(context: &ServerContext, zone: &str, request: RecordRequest) -> Result<()> {
    let rr = request
        .into_resourcerecord()
        .ok_or_else(|| WebError::InvalidRequest)?;

    let mut zones = context.authority.write().map_err(|_| WebError::LockError)?;
    let zone = zones
        .get_zone_mut(zone)
        .ok_or_else(|| WebError::ZoneNotFound)?;
    zone.add_record(&rr);

    zones.save()?;

    Ok(())
}

pub fn record_delete(context: &ServerContext, zone: &str, request: RecordRequest) -> Result<()> {
    let rr = request
        .into_resourcerecord()
        .ok_or_else(|| WebError::InvalidRequest)?;

    let mut zones = context.authority.write().map_err(|_| WebError::LockError)?;
    let zone = zones
        .get_zone_mut(zone)
        .ok_or_else(|| WebError::ZoneNotFound)?;
    zone.delete_record(&rr);

    zones.save()?;

    Ok(())
}

