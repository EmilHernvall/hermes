use std::collections::BTreeMap;
use std::path::Path;
use std::fmt::Write;
use std::net::{Ipv4Addr,Ipv6Addr};
use std::io::{Result, Error, ErrorKind};

use regex::Regex;
use tiny_http::{Server, Response, StatusCode, Header, HeaderField, Method, Request};
use ascii::AsciiString;
use handlebars::Handlebars;
use rustc_serialize::json::{self, ToJson, Json, DecodeResult, DecoderError};
use rustc_serialize::Decodable;

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

pub fn run_webserver(authority: &Authority,
                     cache: &SynchronizedCache)
{
    let mut handlebars = Handlebars::new();
    let _ = handlebars.register_template_file("cache", Path::new("templates/cache.html"));

    let webserver = match Server::http(("0.0.0.0", 5380)) {
        Ok(x) => x,
        Err(e) => {
            println!("Failed to start web server: {:?}", e);
            return;
        }
    };

    let cache_re = Regex::new(r"^/cache").unwrap();
    let authority_re = Regex::new(r"^/authority$").unwrap();
    let zone_re = Regex::new(r"^/authority/([A-Za-z0-9-.]+)$").unwrap();

    for request in webserver.incoming_requests() {
        println!("HTTP {:?} {:?}", request.method(), request.url());

        let accept_header = request.headers().iter()
            .filter(|x| x.field.as_str() == "Accept").map(|x| x.clone()).next();

        let json_output = match accept_header {
            Some(ah) => {
                let value : String = ah.value.into();
                value.contains("application/json")
            },
            None => false
        };

        if cache_re.is_match(request.url()) {
            match handle_cache(request,
                               &mut handlebars,
                               json_output,
                               cache) {
                Ok(_) => {},
                Err(e) => println!("HTTP request failed: {:?}", e)
            }

            continue;
        }
        else if authority_re.is_match(request.url()) {
            match handle_authority(request,
                                   &mut handlebars,
                                   json_output,
                                   authority) {
                Ok(_) => {},
                Err(e) => println!("HTTP request failed: {:?}", e)
            }

            continue;
        }
        else if let Some(caps) = zone_re.captures(&request.url().to_string()) {
            let zone = match caps.at(1) {
                Some(x) => x,
                None => {
                    let response = Response::empty(StatusCode(400));
                    let _ = request.respond(response);
                    continue;
                }
            };

            match handle_zone(request,
                              &mut handlebars,
                              &zone.to_string(),
                              json_output,
                              authority) {
                Ok(_) => {},
                Err(e) => println!("HTTP request failed: {:?}", e)
            }

            continue;
        }

        let response = Response::empty(StatusCode(404));
        let _ = request.respond(response);
    }
}

pub fn handle_cache(mut request: Request,
                    handlebars: &mut Handlebars,
                    json_output: bool,
                    cache: &SynchronizedCache) -> Result<()>
{
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

    match json_output {
        true => {
            let output = match json::encode(&cache_response).ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to encode response")
            };

            let mut response = Response::from_string(output);
            response.add_header(Header{
                field: "Content-Type".parse::<HeaderField>().unwrap(),
                value: "application/json".parse::<AsciiString>().unwrap()
            });
            return request.respond(response);
        },
        false => {
            let html_data = match handlebars.render("cache", &cache_response).ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to encode response")
            };

            let mut response = Response::from_string(html_data);
            response.add_header(Header{
                field: "Content-Type".parse::<HeaderField>().unwrap(),
                value: "text/html".parse::<AsciiString>().unwrap()
            });
            return request.respond(response);
        }
    };
}

#[derive(Debug,RustcDecodable)]
pub struct ZoneCreateRequest
{
    pub domain: String,
    pub mname: String,
    pub rname: String,
    pub serial: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>
}

fn handle_authority(mut request: Request,
                    handlebars: &mut Handlebars,
                    json_output: bool,
                    authority: &Authority) -> Result<()>
{
    match *request.method() {
        Method::Get => {
            let zones = match authority.read().ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to access authority")
            };

            let mut zones_json = Vec::new();
            for zone in &zones.zones() {
                let mut d = BTreeMap::new();
                d.insert("domain".to_string(), zone.domain.to_json());
                d.insert("mname".to_string(), zone.mname.to_json());
                d.insert("rname".to_string(), zone.mname.to_json());
                d.insert("serial".to_string(), zone.serial.to_json());
                d.insert("refresh".to_string(), zone.refresh.to_json());
                d.insert("retry".to_string(), zone.retry.to_json());
                d.insert("expire".to_string(), zone.expire.to_json());
                d.insert("minimum".to_string(), zone.minimum.to_json());
                zones_json.push(Json::Object(d));
            }

            let zones_arr = Json::Array(zones_json);
            let output = match json::encode(&zones_arr).ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to parse request")
            };

            let mut response = Response::from_string(output);
            response.add_header(Header{
                field: "Content-Type".parse::<HeaderField>().unwrap(),
                value: "application/json".parse::<AsciiString>().unwrap()
            });
            return request.respond(response);
        },
        Method::Post => {
            let create_data = match decode_json::<ZoneCreateRequest>(&mut request).ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to parse request")
            };

            println!("Adding zone {}", &create_data.domain);
            println!("{:?}", create_data);

            let mut zones = match authority.write().ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to access authority")
            };

            zones.add_zone(Zone::new(create_data.domain,
                                     create_data.mname,
                                     create_data.rname));

            let response = Response::empty(StatusCode(200));
            return request.respond(response);
        },
        _ => {
        }
    }

    error_response(request, "Invalid method")
}

#[derive(Debug,RustcDecodable)]
pub struct RecordCreateRequest
{
    pub recordtype: String,
    pub domain: String,
    pub ttl: u32,
    pub host: Option<String>
}

impl RecordCreateRequest {
    fn to_resourcerecord(self) -> Option<ResourceRecord> {
        match &*self.recordtype {
            "A" => {
                let host = match self.host.and_then(|x| x.parse::<Ipv4Addr>().ok()) {
                    Some(x) => x,
                    None => return None
                };

                Some(ResourceRecord::A(self.domain, host, self.ttl))
            },
            "AAAA" => {
                let host = match self.host.and_then(|x| x.parse::<Ipv6Addr>().ok()) {
                    Some(x) => x,
                    None => return None
                };

                Some(ResourceRecord::AAAA(self.domain, host, self.ttl))
            },
            "CNAME" => {
                let host = match self.host {
                    Some(x) => x,
                    None => return None
                };

                Some(ResourceRecord::CNAME(self.domain, host, self.ttl))
            },
            _ => None
        }
    }
}

fn handle_zone(mut request: Request,
               handlebars: &mut Handlebars,
               zone: &String,
               json_output: bool,
               authority: &Authority) -> Result<()>
{

    match *request.method() {
        Method::Get => {
            let zones = match authority.read().ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to access authority")
            };

            let zone = match zones.get_zone(zone) {
                Some(x) => x,
                None => return error_response(request, "Zone not found")
            };

            let mut records = Vec::new();
            for ref rr in &zone.records {
                records.push(rr_to_json(rr));
            }

            let records_arr = Json::Array(records);
            let output = match json::encode(&records_arr).ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to parse request")
            };

            let mut response = Response::from_string(output);
            response.add_header(Header{
                field: "Content-Type".parse::<HeaderField>().unwrap(),
                value: "application/json".parse::<AsciiString>().unwrap()
            });
            return request.respond(response);
        },
        Method::Post => {
            let create_data = match decode_json::<RecordCreateRequest>(&mut request).ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to parse request")
            };

            println!("{:?}", create_data);

            let rr = match create_data.to_resourcerecord() {
                Some(x) => x,
                None => return error_response(request, "Invalid record specification")
            };

            let mut zones = match authority.write().ok() {
                Some(x) => x,
                None => return error_response(request, "Failed to access authority")
            };

            let zone = match zones.get_zone_mut(zone) {
                Some(x) => x,
                None => return error_response(request, "Zone not found")
            };

            zone.add_record(&rr);

            let response = Response::empty(StatusCode(200));
            return request.respond(response);
        },
        _ => {}
    }

    error_response(request, "Invalid method")
}

fn error_response(request: Request, error: &str) -> Result<()>
{
    let response = Response::empty(StatusCode(400));
    let _ = request.respond(response);
    Err(Error::new(ErrorKind::InvalidInput, error))
}

fn decode_json<T: Decodable>(request: &mut Request) -> DecodeResult<T>
{
    let json = match Json::from_reader(request.as_reader()) {
        Ok(x) => x,
        Err(e) => return Err(DecoderError::ParseError(e))
    };

    let mut decoder = json::Decoder::new(json);
    Decodable::decode(&mut decoder)
}
