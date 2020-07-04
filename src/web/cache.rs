use serde_derive::{Deserialize, Serialize};

use crate::dns::cache::RecordSet;
use crate::dns::context::ServerContext;
use crate::dns::protocol::DnsRecord;
use crate::web::Result;

#[derive(Serialize, Deserialize)]
pub struct CacheRecordEntry {
    pub id: u32,
    pub record: DnsRecord,
}

#[derive(Serialize, Deserialize)]
pub struct CacheRecord {
    domain: String,
    hits: u32,
    updates: u32,
    entries: Vec<CacheRecordEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct CacheResponse {
    ok: bool,
    records: Vec<CacheRecord>,
}

pub fn cacheinfo(context: &ServerContext) -> Result<CacheResponse> {
    let cached_records = match context.cache.list() {
        Ok(x) => x,
        Err(_) => Vec::new(),
    };

    let mut cache_response = CacheResponse {
        ok: true,
        records: Vec::new(),
    };

    let mut id = 0;
    for rs in cached_records {
        let mut cache_record = CacheRecord {
            domain: rs.domain.clone(),
            hits: rs.hits,
            updates: rs.updates,
            entries: Vec::new(),
        };

        for entry in rs.record_types.values() {
            match *entry {
                RecordSet::NoRecords { .. } => {}
                RecordSet::Records { ref records, .. } => {
                    for entry in records {
                        cache_record.entries.push(CacheRecordEntry {
                            id,
                            record: entry.record.clone(),
                        });
                        id += 1;
                    }
                }
            }
        }

        cache_response.records.push(cache_record);
    }

    Ok(cache_response)
}
