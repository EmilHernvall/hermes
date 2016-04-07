use std::path::Path;
use std::io::{Result, Error, ErrorKind, Read};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::error::Error as RealError;
use std::net::{Ipv4Addr,Ipv6Addr};

use regex::{Regex,Captures};
use tiny_http::{Response, Header, HeaderField, Request, Method, StatusCode};
use ascii::AsciiString;
use rustc_serialize::json::{self, ToJson, Json};

use dns::context::ServerContext;
use dns::authority::Zone;
use dns::protocol::ResourceRecord;

use web::util::{FormDataDecodable,rr_to_json,decode_json,parse_formdata};
use web::server::{Action,WebServer};

#[derive(Debug,RustcDecodable)]
pub struct ZoneCreateRequest
{
    pub domain: String,
    pub mname: String,
    pub rname: String,
    pub serial: Option<u32>,
    pub refresh: Option<u32>,
    pub retry: Option<u32>,
    pub expire: Option<u32>,
    pub minimum: Option<u32>
}

impl FormDataDecodable<ZoneCreateRequest> for ZoneCreateRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<ZoneCreateRequest> {
        let mut d = BTreeMap::new();
        for (k,v) in fields {
            d.insert(k, v);
        }

        let domain = match d.get("domain") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing domain"))
        };

        let mname = match d.get("mname") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing mname"))
        };

        let rname = match d.get("rname") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing rname"))
        };

        Ok(ZoneCreateRequest {
            domain: domain.clone(),
            mname: mname.clone(),
            rname: rname.clone(),
            serial: d.get("serial").and_then(|x| x.parse::<u32>().ok()),
            refresh: d.get("refresh").and_then(|x| x.parse::<u32>().ok()),
            retry: d.get("retry").and_then(|x| x.parse::<u32>().ok()),
            expire: d.get("expire").and_then(|x| x.parse::<u32>().ok()),
            minimum: d.get("minimum").and_then(|x| x.parse::<u32>().ok())
        })
    }
}

#[derive(Debug,RustcDecodable)]
pub struct RecordRequest
{
    pub delete_record: Option<bool>,
    pub recordtype: String,
    pub domain: String,
    pub ttl: u32,
    pub host: Option<String>
}

impl FormDataDecodable<RecordRequest> for RecordRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<RecordRequest> {
        let mut d = BTreeMap::new();
        for (k,v) in fields {
            d.insert(k, v);
        }

        let recordtype = match d.get("recordtype") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing recordtype"))
        };

        let domain = match d.get("domain") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing domain"))
        };

        let ttl = match d.get("ttl").and_then(|x| x.parse::<u32>().ok()) {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing ttl"))
        };

        let delete_record = d.get("delete_record").and_then(|x| x.parse::<bool>().ok());

        Ok(RecordRequest {
            delete_record: delete_record,
            recordtype: recordtype.clone(),
            domain: domain.clone(),
            ttl: ttl,
            host: d.get("host").map(|x| x.clone())
        })
    }
}

impl RecordRequest {
    fn to_resourcerecord(self) -> Option<ResourceRecord> {
        match self.recordtype.as_str() {
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

pub struct AuthorityAction {
    context: Arc<ServerContext>
}

impl AuthorityAction {
    pub fn new(context: Arc<ServerContext>) -> AuthorityAction {
        AuthorityAction {
            context: context
        }
    }
}

impl Action for AuthorityAction {
    fn get_regex(&self) -> Regex {
        Regex::new(r"^/authority$").unwrap()
    }

    fn initialize(&self, server: &mut WebServer) {
        if !server.handlebars.register_template_file("authority", Path::new("templates/authority.html")).is_ok() {
            println!("Failed to register authority template");
            return;
        }
    }

    fn handle(&self,
              server: &WebServer,
              mut request: Request,
              _: &Captures,
              json_input: bool,
              json_output: bool) -> Result<()> {

        match *request.method() {
            Method::Get => {
                let zones = match self.context.authority.read().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority")
                };

                let mut zones_json = Vec::new();
                for zone in &zones.zones() {
                    let mut d = BTreeMap::new();
                    d.insert("domain".to_string(), zone.domain.to_json());
                    d.insert("mname".to_string(), zone.mname.to_json());
                    d.insert("rname".to_string(), zone.rname.to_json());
                    d.insert("serial".to_string(), zone.serial.to_json());
                    d.insert("refresh".to_string(), zone.refresh.to_json());
                    d.insert("retry".to_string(), zone.retry.to_json());
                    d.insert("expire".to_string(), zone.expire.to_json());
                    d.insert("minimum".to_string(), zone.minimum.to_json());
                    zones_json.push(Json::Object(d));
                }

                let zones_arr = Json::Array(zones_json);

                let mut result_dict = BTreeMap::new();
                result_dict.insert("ok".to_string(), true.to_json());
                result_dict.insert("zones".to_string(), zones_arr);
                let result_obj = Json::Object(result_dict);

                match json_output {
                    true => {
                        let output = match json::encode(&result_obj).ok() {
                            Some(x) => x,
                            None => return server.error_response(request, "Failed to parse request")
                        };

                        let mut response = Response::from_string(output);
                        response.add_header(Header{
                            field: "Content-Type".parse::<HeaderField>().unwrap(),
                            value: "application/json".parse::<AsciiString>().unwrap()
                        });
                        return request.respond(response);
                    },
                    false => {
                        let html_data = match server.handlebars.render("authority", &result_obj) {
                            Ok(x) => x,
                            Err(e) => return server.error_response(request, &("Failed to encode response: ".to_string() + e.description()))
                        };

                        let mut response = Response::from_string(html_data);
                        response.add_header(Header{
                            field: "Content-Type".parse::<HeaderField>().unwrap(),
                            value: "text/html".parse::<AsciiString>().unwrap()
                        });
                        return request.respond(response);
                    }
                };
            },
            Method::Post => {
                let request_data = if json_input {
                    match decode_json::<ZoneCreateRequest>(&mut request).ok() {
                        Some(x) => x,
                        None => return server.error_response(request, "Failed to parse request")
                    }
                } else {
                    match parse_formdata(&mut request.as_reader()).and_then(|x| ZoneCreateRequest::from_formdata(x)) {
                        Ok(x) => x,
                        Err(e) => return server.error_response(request, e.description())
                    }
                };

                let mut zones = match self.context.authority.write().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority")
                };

                let mut zone = Zone::new(request_data.domain,
                                         request_data.mname,
                                         request_data.rname);
                zone.serial = 0;
                zone.refresh = request_data.refresh.unwrap_or(3600);
                zone.retry = request_data.retry.unwrap_or(3600);
                zone.expire = request_data.expire.unwrap_or(3600);
                zone.minimum = request_data.minimum.unwrap_or(3600);
                zones.add_zone(zone);

                match zones.save() {
                    Ok(_) => println!("Zones saved!"),
                    Err(e) =>  println!("Zone Saving failed: {:?}", e)
                }

                let mut response = Response::empty(StatusCode(201));
                response.add_header(Header{
                    field: "Refresh".parse::<HeaderField>().unwrap(),
                    value: "0; url=/authority".parse::<AsciiString>().unwrap()
                });
                return request.respond(response);
            },
            _ => {
            }
        }

        server.error_response(request, "Invalid method")
    }
}

pub struct ZoneAction {
    context: Arc<ServerContext>
}

impl ZoneAction {
    pub fn new(context: Arc<ServerContext>) -> ZoneAction {
        ZoneAction {
            context: context
        }
    }
}

impl Action for ZoneAction {
    fn get_regex(&self) -> Regex {
        Regex::new(r"^/authority/([A-Za-z0-9-.]+)$").unwrap()
    }

    fn initialize(&self, server: &mut WebServer) {
        if !server.handlebars.register_template_file("zone", Path::new("templates/zone.html")).is_ok() {
            println!("Failed to register zone template");
            return;
        }
    }

    fn handle(&self,
              server: &WebServer,
              mut request: Request,
              caps: &Captures,
              json_input: bool,
              json_output: bool) -> Result<()> {

        let zone = match caps.at(1) {
            Some(x) => x,
            None => return server.error_response(request, "Missing zone name")
        };

        match *request.method() {
            Method::Get => {
                let zones = match self.context.authority.read().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority")
                };

                let zone = match zones.get_zone(zone) {
                    Some(x) => x,
                    None => return server.error_response(request, "Zone not found")
                };

                let mut records = Vec::new();
                for (id, rr) in zone.records.iter().enumerate() {
                    records.push(rr_to_json(id as u32, rr));
                }

                let records_arr = Json::Array(records);

                let mut result_dict = BTreeMap::new();
                result_dict.insert("ok".to_string(), true.to_json());
                result_dict.insert("zone".to_string(), zone.domain.to_json());
                result_dict.insert("records".to_string(), records_arr);
                let result_obj = Json::Object(result_dict);

                match json_output {
                    true => {
                        let output = match json::encode(&result_obj).ok() {
                            Some(x) => x,
                            None => return server.error_response(request, "Failed to parse request")
                        };

                        let mut response = Response::from_string(output);
                        response.add_header(Header{
                            field: "Content-Type".parse::<HeaderField>().unwrap(),
                            value: "application/json".parse::<AsciiString>().unwrap()
                        });
                        return request.respond(response);
                    },
                    false => {
                        let html_data = match server.handlebars.render("zone", &result_obj).ok() {
                            Some(x) => x,
                            None => return server.error_response(request, "Failed to encode response")
                        };

                        let mut response = Response::from_string(html_data);
                        response.add_header(Header{
                            field: "Content-Type".parse::<HeaderField>().unwrap(),
                            value: "text/html".parse::<AsciiString>().unwrap()
                        });
                        return request.respond(response);
                    }
                };
            },
            Method::Post | Method::Delete => {
                let request_data = if json_input {
                    match decode_json::<RecordRequest>(&mut request) {
                        Ok(x) => x,
                        Err(e) => return server.error_response(request, e.description())
                    }
                } else {
                    match parse_formdata(&mut request.as_reader()).and_then(|x| RecordRequest::from_formdata(x)) {
                        Ok(x) => x,
                        Err(e) => return server.error_response(request, e.description())
                    }
                };

                let delete_record = if request.method() == &Method::Delete {
                    true
                } else {
                    request_data.delete_record.unwrap_or(false)
                };

                let rr = match request_data.to_resourcerecord() {
                    Some(x) => x,
                    None => return server.error_response(request, "Invalid record specification")
                };

                let mut zones = match self.context.authority.write().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority")
                };

                {
                    let zone = match zones.get_zone_mut(zone) {
                        Some(x) => x,
                        None => return server.error_response(request, "Zone not found")
                    };

                    if delete_record {
                        zone.delete_record(&rr);
                    } else {
                        zone.add_record(&rr);
                    }
                };

                match zones.save() {
                    Ok(_) => println!("Zones saved!"),
                    Err(e) =>  println!("Zone Saving failed: {:?}", e)
                }

                let mut response = Response::empty(StatusCode(201));
                response.add_header(Header{
                    field: "Refresh".parse::<HeaderField>().unwrap(),
                    value: ("0; url=/authority/".to_string() + zone).parse::<AsciiString>().unwrap()
                });
                return request.respond(response);
            },
            _ => {}
        }

        server.error_response(request, "Invalid method")
    }
}
