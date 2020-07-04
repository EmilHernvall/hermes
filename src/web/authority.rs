use std::collections::BTreeMap;
use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ascii::AsciiString;
use regex::{Captures, Regex};
use tiny_http::{Header, HeaderField, Method, Request, Response, StatusCode};
use serde_derive::{Serialize, Deserialize};
use serde_json::json;

use crate::dns::authority::Zone;
use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsRecord, TransientTtl};

use crate::web::server::{Action, WebServer};
use crate::web::cache::CacheRecordEntry;
use crate::web::util::{parse_formdata, FormDataDecodable};

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
        let mut d = BTreeMap::new();
        for (k, v) in fields {
            d.insert(k, v);
        }

        let domain = match d.get("domain") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing domain")),
        };

        let m_name = match d.get("m_name") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing m_name")),
        };

        let r_name = match d.get("r_name") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing r_name")),
        };

        Ok(ZoneCreateRequest {
            domain: domain.clone(),
            m_name: m_name.clone(),
            r_name: r_name.clone(),
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
    pub delete_record: Option<bool>,
    pub recordtype: String,
    pub domain: String,
    pub ttl: u32,
    pub host: Option<String>,
    pub addr: Option<String>,
}

impl FormDataDecodable<RecordRequest> for RecordRequest {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<RecordRequest> {
        let mut d : BTreeMap<_, _> = fields.into_iter().collect();

        let recordtype = match d.remove("recordtype") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing recordtype")),
        };

        let domain = match d.remove("domain") {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing domain")),
        };

        let ttl = match d.get("ttl").and_then(|x| x.parse::<u32>().ok()) {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::InvalidInput, "missing ttl")),
        };

        let delete_record = d.get("delete_record").and_then(|x| x.parse::<bool>().ok());

        Ok(RecordRequest {
            delete_record: delete_record,
            recordtype,
            domain,
            ttl: ttl,
            host: d.remove("host"),
            addr: d.remove("addr"),
        })
    }
}

impl RecordRequest {
    fn into_resourcerecord(self) -> Option<DnsRecord> {
        match self.recordtype.as_str() {
            "A" => {
                let host = match self.addr.and_then(|x| x.parse::<Ipv4Addr>().ok()) {
                    Some(x) => x,
                    None => return None,
                };

                Some(DnsRecord::A {
                    domain: self.domain,
                    addr: host,
                    ttl: TransientTtl(self.ttl),
                })
            }
            "AAAA" => {
                let host = match self.addr.and_then(|x| x.parse::<Ipv6Addr>().ok()) {
                    Some(x) => x,
                    None => return None,
                };

                Some(DnsRecord::AAAA {
                    domain: self.domain,
                    addr: host,
                    ttl: TransientTtl(self.ttl),
                })
            }
            "CNAME" => {
                let host = match self.host {
                    Some(x) => x,
                    None => return None,
                };

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

pub struct AuthorityAction {
    context: Arc<ServerContext>,
}

impl AuthorityAction {
    pub fn new(context: Arc<ServerContext>) -> AuthorityAction {
        AuthorityAction { context: context }
    }
}

impl Action for AuthorityAction {
    fn get_regex(&self) -> Regex {
        Regex::new(r"^/authority$").unwrap()
    }

    fn initialize(&self, server: &mut WebServer) {
        let tpl_data = include_str!("templates/authority.html").to_string();
        if !server
            .handlebars
            .register_template_string("authority", tpl_data)
            .is_ok()
        {
            println!("Failed to register authority template");
            return;
        }
    }

    fn handle(
        &self,
        server: &WebServer,
        mut request: Request,
        _: &Captures<'_>,
        json_input: bool,
        json_output: bool,
    ) -> Result<()> {
        match *request.method() {
            Method::Get => {
                let zones = match self.context.authority.read().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority"),
                };

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

                let result_obj = json!({
                    "ok": true,
                    "zones": zones_json,
                });

                if json_output {
                    let output = match serde_json::to_string(&result_obj).ok() {
                        Some(x) => x,
                        None => return server.error_response(request, "Failed to parse request"),
                    };

                    let mut response = Response::from_string(output);
                    response.add_header(Header {
                        field: "Content-Type".parse().unwrap(),
                        value: "application/json".parse().unwrap(),
                    });
                    return request.respond(response);
                } else {
                    let html_data = match server.handlebars.render("authority", &result_obj) {
                        Ok(x) => x,
                        Err(e) => {
                            return server.error_response(
                                request,
                                &format!("Failed to encode response: {}", e),
                            )
                        }
                    };

                    let mut response = Response::from_string(html_data);
                    response.add_header(Header {
                        field: "Content-Type".parse().unwrap(),
                        value: "text/html".parse().unwrap(),
                    });
                    return request.respond(response);
                }
            }
            Method::Post => {
                let request_data = if json_input {
                    match serde_json::from_reader::<_, ZoneCreateRequest>(request.as_reader()).ok() {
                        Some(x) => x,
                        None => return server.error_response(request, "Failed to parse request"),
                    }
                } else {
                    match parse_formdata(&mut request.as_reader())
                        .and_then(ZoneCreateRequest::from_formdata)
                    {
                        Ok(x) => x,
                        Err(e) => return server.error_response(request, &e.to_string()),
                    }
                };

                let mut zones = match self.context.authority.write().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority"),
                };

                let mut zone = Zone::new(
                    request_data.domain,
                    request_data.m_name,
                    request_data.r_name,
                );
                zone.serial = 0;
                zone.refresh = request_data.refresh.unwrap_or(3600);
                zone.retry = request_data.retry.unwrap_or(3600);
                zone.expire = request_data.expire.unwrap_or(3600);
                zone.minimum = request_data.minimum.unwrap_or(3600);
                zones.add_zone(zone);

                match zones.save() {
                    Ok(_) => println!("Zones saved!"),
                    Err(e) => println!("Zone Saving failed: {:?}", e),
                }

                let mut response = Response::empty(StatusCode(201));
                response.add_header(Header {
                    field: "Refresh".parse().unwrap(),
                    value: "0; url=/authority".parse().unwrap(),
                });
                return request.respond(response);
            }
            _ => {}
        }

        server.error_response(request, "Invalid method")
    }
}

pub struct ZoneAction {
    context: Arc<ServerContext>,
}

impl ZoneAction {
    pub fn new(context: Arc<ServerContext>) -> ZoneAction {
        ZoneAction { context: context }
    }
}

impl Action for ZoneAction {
    fn get_regex(&self) -> Regex {
        Regex::new(r"^/authority/([A-Za-z0-9-.]+)$").unwrap()
    }

    fn initialize(&self, server: &mut WebServer) {
        let tpl_data = include_str!("templates/zone.html").to_string();
        if !server
            .handlebars
            .register_template_string("zone", tpl_data)
            .is_ok()
        {
            println!("Failed to register zone template");
            return;
        }
    }

    fn handle(
        &self,
        server: &WebServer,
        mut request: Request,
        caps: &Captures<'_>,
        json_input: bool,
        json_output: bool,
    ) -> Result<()> {
        let zone = match caps.at(1) {
            Some(x) => x,
            None => return server.error_response(request, "Missing zone name"),
        };

        match *request.method() {
            Method::Get => {
                let zones = match self.context.authority.read().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority"),
                };

                let zone = match zones.get_zone(zone) {
                    Some(x) => x,
                    None => return server.error_response(request, "Zone not found"),
                };

                let mut records = Vec::new();
                for (id, rr) in zone.records.iter().enumerate() {
                    records.push(CacheRecordEntry {
                        id: id as u32,
                        record: rr.clone(),
                    });
                }

                let result_obj = json!({
                    "ok": true,
                    "zone": zone.domain,
                    "records": records,
                });

                eprintln!("result {:#?}", result_obj);

                if json_output {
                    let output = match serde_json::to_string(&result_obj).ok() {
                        Some(x) => x,
                        None => return server.error_response(request, "Failed to parse request"),
                    };

                    let mut response = Response::from_string(output);
                    response.add_header(Header {
                        field: "Content-Type".parse::<HeaderField>().unwrap(),
                        value: "application/json".parse::<AsciiString>().unwrap(),
                    });
                    return request.respond(response);
                } else {
                    let html_data = match server.handlebars.render("zone", &result_obj).ok() {
                        Some(x) => x,
                        None => return server.error_response(request, "Failed to encode response"),
                    };

                    let mut response = Response::from_string(html_data);
                    response.add_header(Header {
                        field: "Content-Type".parse::<HeaderField>().unwrap(),
                        value: "text/html".parse::<AsciiString>().unwrap(),
                    });
                    return request.respond(response);
                }
            }
            Method::Post | Method::Delete => {
                let request_data = if json_input {
                    match serde_json::from_reader::<_, RecordRequest>(request.as_reader()) {
                        Ok(x) => x,
                        Err(e) => return server.error_response(request, &e.to_string()),
                    }
                } else {
                    match parse_formdata(&mut request.as_reader())
                        .and_then(RecordRequest::from_formdata)
                    {
                        Ok(x) => x,
                        Err(e) => return server.error_response(request, &e.to_string()),
                    }
                };

                eprintln!("incoming request data: {:?}", request_data);

                let delete_record = if request.method() == &Method::Delete {
                    true
                } else {
                    request_data.delete_record.unwrap_or(false)
                };

                let rr = match request_data.into_resourcerecord() {
                    Some(x) => x,
                    None => return server.error_response(request, "Invalid record specification"),
                };

                let mut zones = match self.context.authority.write().ok() {
                    Some(x) => x,
                    None => return server.error_response(request, "Failed to access authority"),
                };

                {
                    let zone = match zones.get_zone_mut(zone) {
                        Some(x) => x,
                        None => return server.error_response(request, "Zone not found"),
                    };

                    if delete_record {
                        zone.delete_record(&rr);
                    } else {
                        zone.add_record(&rr);
                    }
                };

                match zones.save() {
                    Ok(_) => println!("Zones saved!"),
                    Err(e) => println!("Zone Saving failed: {:?}", e),
                }

                let mut response = Response::empty(StatusCode(201));
                response.add_header(Header {
                    field: "Refresh".parse::<HeaderField>().unwrap(),
                    value: ("0; url=/authority/".to_string() + zone)
                        .parse::<AsciiString>()
                        .unwrap(),
                });
                return request.respond(response);
            }
            _ => {}
        }

        server.error_response(request, "Invalid method")
    }
}
