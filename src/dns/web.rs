use std::collections::BTreeMap;
use std::path::Path;
use std::fmt::Write;

use tiny_http::{Server, Response, StatusCode, Header, HeaderField};
use ascii::AsciiString;
use handlebars::Handlebars;
use rustc_serialize::json::{self, ToJson, Json};

use dns::cache::SynchronizedCache;
use dns::protocol::ResourceRecord;

fn rr_to_json(rr: &ResourceRecord) -> Json {
    let mut d = BTreeMap::new();

    let mut qtype = String::new();
    let _ = write!(&mut qtype, "{:?}", rr.get_querytype());
    d.insert("type".to_string(), qtype.to_json());

    match *rr {
        ResourceRecord::A(ref domain, ref host, ttl) => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_string().to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::AAAA(ref domain, ref host, ttl) => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_string().to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::NS(ref domain, ref host, ttl) => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::CNAME(ref domain, ref host, ttl) => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::SRV(ref domain, priority, weight, port, ref host, ttl) => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
            d.insert("priority".to_string(), priority.to_json());
            d.insert("weight".to_string(), weight.to_json());
            d.insert("port".to_string(), port.to_json());
        },
        ResourceRecord::MX(ref domain, _, ref host, ttl) => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::UNKNOWN(ref domain, qtype, data_len, ttl) => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
            d.insert("type".to_string(), qtype.to_json());
            d.insert("len".to_string(), data_len.to_json());
        },
        ResourceRecord::SOA => {
        },
        ResourceRecord::PTR => {
        },
        ResourceRecord::TXT => {
        }
    }

    Json::Object(d)
}

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

pub fn run_webserver(cache: &SynchronizedCache)
{
    let mut handlebars = Handlebars::new();
    let _ = handlebars.register_template_file("cache", Path::new("templates/cache.html"));

    let webserver = Server::http(("0.0.0.0", 5380)).unwrap();

    for request in webserver.incoming_requests() {
        println!("received request! method: {:?}, url: {:?}, headers: {:?}",
            request.method(),
            request.url(),
            request.headers()
        );

        if request.url().starts_with("/cache") {
            let cached_records = cache.list();

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

                for entry in rs.records {
                    cache_record.entries.push(rr_to_json(&entry.record));
                }

                cache_response.records.push(cache_record);
            }

            if let Ok(html_data) = handlebars.render("cache", &cache_response) {
                let mut response = Response::from_string(html_data);
                response.add_header(Header{
                    field: "Content-Type".parse::<HeaderField>().unwrap(),
                    value: "text/html".parse::<AsciiString>().unwrap()
                });
                let _ = request.respond(response);
            }

            /*if let Ok(output) = json::encode(&cache_response) {

                let mut response = Response::from_string(output);
                response.add_header(Header{
                    field: "Content-Type".parse::<HeaderField>().unwrap(),
                    value: "application/json".parse::<AsciiString>().unwrap()
                });
                let _ = request.respond(response);
            }
            else {
                let response = Response::empty(StatusCode(500));
                let _ = request.respond(response);
            }*/
        }
        else {
            let response = Response::empty(StatusCode(404));
            let _ = request.respond(response);
        }
    }
}
