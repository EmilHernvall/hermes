use std::io::Result;
use std::collections::BTreeMap;
use std::sync::Arc;

use regex::{Regex,Captures};
use tiny_http::{Response, Header, HeaderField, Request};
//use chrono::*;
use ascii::AsciiString;
use rustc_serialize::json::{self, ToJson, Json};

use dns::context::ServerContext;

use web::util::rr_to_json;
use web::server::{Action,WebServer};

#[derive(RustcEncodable)]
pub struct CacheRecord
{
    domain: String,
    hits: u32,
    updates: u32,
    entries: Vec<Json>
}

impl ToJson for CacheRecord {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("domain".to_string(), self.domain.to_json());
        d.insert("hits".to_string(), self.hits.to_json());
        d.insert("updates".to_string(), self.updates.to_json());
        d.insert("entries".to_string(), self.entries.to_json());
        Json::Object(d)
    }
}

#[derive(RustcEncodable)]
pub struct CacheResponse
{
    ok: bool,
    records: Vec<CacheRecord>
}

impl ToJson for CacheResponse {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("ok".to_string(), self.ok.to_json());
        d.insert("records".to_string(), self.records.to_json());
        Json::Object(d)
    }
}

pub struct CacheAction {
    context: Arc<ServerContext>
}

impl CacheAction {
    pub fn new(context: Arc<ServerContext>) -> CacheAction {
        CacheAction {
            context: context
        }
    }
}

impl Action for CacheAction {
    fn get_regex(&self) -> Regex {
        Regex::new(r"^/cache").unwrap()
    }

    fn initialize(&self, server: &mut WebServer) {
        let tpl_data = include_str!("templates/cache.html").to_string();
        if !server.handlebars.register_template_string("cache", tpl_data).is_ok() {
            println!("Failed to register cache template");
            return;
        }
    }

    fn handle(&self,
              server: &WebServer,
              request: Request,
              _: &Captures,
              _: bool,
              json_output: bool) -> Result<()> {

        //let start_of_eq = Local::now();

        let cached_records = match self.context.cache.list() {
            Ok(x) => x,
            Err(_) => Vec::new()
        };

        //let end_of_list = Local::now();

        let mut cache_response = CacheResponse {
            ok: true,
            records: Vec::new()
        };

        for rs in cached_records {
            let mut cache_record = CacheRecord {
                domain: rs.domain.clone(),
                hits: rs.hits,
                updates: rs.updates,
                entries: Vec::new()
            };

            for (id, entry) in rs.records.iter().enumerate() {
                cache_record.entries.push(rr_to_json(id as u32, &entry.record));
            }

            cache_response.records.push(cache_record);
        }

        //let end_of_object = Local::now();

        match json_output {
            true => {
                let output = match json::encode(&cache_response).ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to encode response")
                };

                //let end_of_output = Local::now();
                //println!("list: {:?}", (end_of_list-start_of_eq).num_milliseconds());
                //println!("object: {:?}", (end_of_object-end_of_list).num_milliseconds());
                //println!("output: {:?}", (end_of_output-end_of_object).num_milliseconds());

                let mut response = Response::from_string(output);
                response.add_header(Header{
                    field: "Content-Type".parse::<HeaderField>().unwrap(),
                    value: "application/json".parse::<AsciiString>().unwrap()
                });
                return request.respond(response);
            },
            false => {
                let html_data = match server.handlebars.render("cache", &cache_response).ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to encode response")
                };

                //let end_of_output = Local::now();
                //println!("list: {:?}", (end_of_list-start_of_eq).num_milliseconds());
                //println!("object: {:?}", (end_of_object-end_of_list).num_milliseconds());
                //println!("output: {:?}", (end_of_output-end_of_object).num_milliseconds());

                let mut response = Response::from_string(html_data);
                response.add_header(Header{
                    field: "Content-Type".parse::<HeaderField>().unwrap(),
                    value: "text/html".parse::<AsciiString>().unwrap()
                });
                return request.respond(response);
            }
        };
    }
}
