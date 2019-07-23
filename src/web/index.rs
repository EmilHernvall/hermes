use std::collections::BTreeMap;
use std::io::Result;
use std::sync::Arc;

use regex::{Captures, Regex};
use rustc_serialize::json::{self, Json, ToJson};
use tiny_http::{Header, Request, Response};

use crate::dns::context::ServerContext;

use crate::web::server::{Action, WebServer};

#[derive(RustcEncodable)]
pub struct IndexResponse {
    ok: bool,
    client_sent_queries: usize,
    client_failed_queries: usize,
    server_tcp_queries: usize,
    server_udp_queries: usize,
}

impl ToJson for IndexResponse {
    fn to_json(&self) -> Json {
        let mut d = BTreeMap::new();
        d.insert("ok".to_string(), self.ok.to_json());
        d.insert(
            "client_sent_queries".to_string(),
            self.client_sent_queries.to_json(),
        );
        d.insert(
            "client_failed_queries".to_string(),
            self.client_failed_queries.to_json(),
        );
        d.insert(
            "server_tcp_queries".to_string(),
            self.server_tcp_queries.to_json(),
        );
        d.insert(
            "server_udp_queries".to_string(),
            self.server_udp_queries.to_json(),
        );
        Json::Object(d)
    }
}

pub struct IndexAction {
    context: Arc<ServerContext>,
}

impl IndexAction {
    pub fn new(context: Arc<ServerContext>) -> IndexAction {
        IndexAction { context: context }
    }
}

impl Action for IndexAction {
    fn get_regex(&self) -> Regex {
        Regex::new(r"^/$").unwrap()
    }

    fn initialize(&self, _: &mut WebServer) {
        //let tpl_data = include_str!("templates/cache.html").to_string();
        //if !server.handlebars.register_template_string("cache", tpl_data).is_ok() {
        //    println!("Failed to register cache template");
        //    return;
        //}
    }

    fn handle(
        &self,
        server: &WebServer,
        request: Request,
        _: &Captures<'_>,
        _: bool,
        json_output: bool,
    ) -> Result<()> {
        let index_response = IndexResponse {
            ok: true,
            client_sent_queries: self.context.client.get_sent_count(),
            client_failed_queries: self.context.client.get_failed_count(),
            server_tcp_queries: self.context.statistics.get_tcp_query_count(),
            server_udp_queries: self.context.statistics.get_udp_query_count(),
        };

        if json_output {
            let output = match json::encode(&index_response).ok() {
                Some(x) => x,
                None => return server.error_response(request, "Failed to encode response"),
            };

            let mut response = Response::from_string(output);
            response.add_header(Header {
                field: "Content-Type".parse().unwrap(),
                value: "application/json".parse().unwrap(),
            });
            request.respond(response)
        } else {
            server.error_response(request, "Not implemented")
            //let html_data = match server.handlebars.render("cache", &cache_response).ok() {
            //    Some(x) => x,
            //    None => return server.error_response(request, "Failed to encode response")
            //};

            //let mut response = Response::from_string(html_data);
            //response.add_header(Header{
            //    field: "Content-Type".parse().unwrap(),
            //    value: "text/html".parse().unwrap()
            //});
            //return request.respond(response);
        }
    }
}
