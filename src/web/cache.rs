use std::io::Result;
use std::sync::Arc;

use regex::{Captures, Regex};
use tiny_http::{Header, Request, Response};
use serde_derive::{Serialize, Deserialize};

use crate::dns::protocol::DnsRecord;
use crate::dns::cache::RecordSet;
use crate::dns::context::ServerContext;

use crate::web::server::{Action, WebServer};

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

pub struct CacheAction {
    context: Arc<ServerContext>,
}

impl CacheAction {
    pub fn new(context: Arc<ServerContext>) -> CacheAction {
        CacheAction { context: context }
    }
}

impl Action for CacheAction {
    fn get_regex(&self) -> Regex {
        Regex::new(r"^/cache").unwrap()
    }

    fn initialize(&self, server: &mut WebServer) {
        let tpl_data = include_str!("templates/cache.html").to_string();
        if !server
            .handlebars
            .register_template_string("cache", tpl_data)
            .is_ok()
        {
            println!("Failed to register cache template");
            return;
        }
    }

    fn handle(
        &self,
        server: &WebServer,
        request: Request,
        _: &Captures<'_>,
        _: bool,
        json_output: bool,
    ) -> Result<()> {
        println!("Handling cache action");
        //let start_of_eq = Local::now();

        let cached_records = match self.context.cache.list() {
            Ok(x) => x,
            Err(_) => Vec::new(),
        };

        //let end_of_list = Local::now();

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

        //let end_of_object = Local::now();

        if json_output {
            let output = match serde_json::to_string(&cache_response) {
                Ok(x) => x,
                Err(e) => return server.error_response(request, &e.to_string()),
            };

            //let end_of_output = Local::now();
            //println!("list: {:?}", (end_of_list-start_of_eq).num_milliseconds());
            //println!("object: {:?}", (end_of_object-end_of_list).num_milliseconds());
            //println!("output: {:?}", (end_of_output-end_of_object).num_milliseconds());

            let mut response = Response::from_string(output);
            response.add_header(Header {
                field: "Content-Type".parse().unwrap(),
                value: "application/json".parse().unwrap(),
            });
            request.respond(response)
        } else {
            let html_data = match server.handlebars.render("cache", &cache_response) {
                Ok(x) => x,
                Err(e) => return server.error_response(request, &e.to_string()),
            };

            //let end_of_output = Local::now();
            //println!("list: {:?}", (end_of_list-start_of_eq).num_milliseconds());
            //println!("object: {:?}", (end_of_object-end_of_list).num_milliseconds());
            //println!("output: {:?}", (end_of_output-end_of_object).num_milliseconds());

            let mut response = Response::from_string(html_data);
            response.add_header(Header {
                field: "Content-Type".parse().unwrap(),
                value: "text/html".parse().unwrap(),
            });
            request.respond(response)
        }
    }
}
