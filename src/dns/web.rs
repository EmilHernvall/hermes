use std::collections::BTreeMap;
use std::path::Path;
use std::fmt::Write;

use tiny_http::{Server, Response, StatusCode, Header, HeaderField, Method, Request};
use ascii::AsciiString;
use handlebars::Handlebars;
use rustc_serialize::json::{self, ToJson, Json};

use dns::cache::SynchronizedCache;
use dns::protocol::ResourceRecord;
use dns::authority::{Authority, Zone};

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
        ResourceRecord::SOA(_, _, _, _, _, _, _, _, _) => {
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

#[derive(RustcDecodable)]
pub struct ZoneCreateRequest
{
    pub domain: String,
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
}

pub fn run_webserver(authority: &mut Authority,
                     cache: &SynchronizedCache)
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
        else if request.url().starts_with("/authority") {
            let _ = handle_authority(request, authority);
        }
        else {
            let response = Response::empty(StatusCode(404));
            let _ = request.respond(response);
        }
    }
}

pub fn handle_authority(mut request: Request,
                        authority: &mut Authority)
{
    match *request.method() {
        Method::Get => {
            let mut zones = Vec::new();
            for (_, zone) in &authority.zones {
                let mut d = BTreeMap::new();
                d.insert("domain".to_string(), zone.domain.to_json());
                d.insert("mname".to_string(), zone.mname.to_json());
                d.insert("rname".to_string(), zone.mname.to_json());
                d.insert("serial".to_string(), zone.serial.to_json());
                d.insert("refresh".to_string(), zone.refresh.to_json());
                d.insert("retry".to_string(), zone.retry.to_json());
                d.insert("expire".to_string(), zone.expire.to_json());
                d.insert("minimum".to_string(), zone.minimum.to_json());
                zones.push(Json::Object(d));
            }

            let zones_arr = Json::Array(zones);
            if let Ok(output) = json::encode(&zones_arr) {

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
            }
        },
        Method::Post => {
            if let Ok(create_zone_request) = Json::from_reader(request.as_reader()) {
                println!("{}", create_zone_request.pretty());

                loop {
                    if !create_zone_request.is_object() {
                        break;
                    }

                    let create_zone_object = create_zone_request.as_object().unwrap();

                    let domain_wrap = unpack_string(create_zone_object.get("domain"));
                    if !domain_wrap.is_some() {
                        println!("Missing domain");
                        break;
                    }

                    let mname_wrap = unpack_string(create_zone_object.get("mname"));
                    if !mname_wrap.is_some() {
                        println!("Missing mname");
                        break;
                    }

                    let rname_wrap = unpack_string(create_zone_object.get("rname"));
                    if !rname_wrap.is_some() {
                        println!("Missing rname");
                        break;
                    }

                    let domain = domain_wrap.unwrap();
                    let mname = mname_wrap.unwrap();
                    let rname = rname_wrap.unwrap();

                    println!("Adding zone {}", &domain);

                    authority.add_zone(Zone::new(domain, mname, rname));

                    break;
                }

                let response = Response::empty(StatusCode(200));
                let _ = request.respond(response);
            }
        },
        _ => {
            let response = Response::empty(StatusCode(404));
            let _ = request.respond(response);
        }
    }
}

pub fn unpack_string(opt: Option<&Json>) -> Option<String>
{
    match opt {
        Some(json) => json.as_string().map(|x| x.to_string()),
        None => None
    }
}
