use std::io::{Result, Error, ErrorKind};
use std::sync::Arc;

use regex::{Regex,Captures};
use tiny_http::{Server, Response, StatusCode, Request};
use handlebars::Handlebars;

use dns::context::ServerContext;

pub trait Action {
    fn get_regex(&self) -> Regex;
    fn initialize(&self, server: &mut WebServer);
    fn handle(&self,
              server: &WebServer,
              mut request: Request,
              path_match: &Captures,
              json_input: bool,
              json_output: bool) -> Result<()>;
}

pub struct WebServer {
    pub context: Arc<ServerContext>,
    pub handlebars: Handlebars,
    pub actions: Vec<Box<Action>>
}

impl WebServer {

    pub fn new(context: Arc<ServerContext>) -> WebServer {
        let mut server = WebServer {
            context: context,
            handlebars: Handlebars::new(),
            actions: Vec::new()
        };

        let tpl_data = include_str!("templates/layout.html").to_string();
        if !server.handlebars.register_template_string("layout", tpl_data).is_ok() {
            println!("Failed to register layout template");
        }

        server
    }

    pub fn register_action(&mut self, action: Box<Action>) {
        action.initialize(self);
        self.actions.push(action);
    }

    pub fn run_webserver(self)
    {
        let webserver = match Server::http(("0.0.0.0", self.context.api_port)) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to start web server: {:?}", e);
                return;
            }
        };

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

            let content_type_header = request.headers().iter()
                .filter(|x| x.field.as_str() == "Content-Type").map(|x| x.clone()).next();

            let json_input = match content_type_header {
                Some(ah) => {
                    let value : String = ah.value.into();
                    value.contains("application/json")
                },
                None => false
            };

            let matching_actions : Vec<&Box<Action>> =
                self.actions.iter().filter(|x| x.get_regex().is_match(&request.url())).collect();

            if matching_actions.len() > 0 {
                let action = &matching_actions[0];
                if let Some(caps) = action.get_regex().captures(&request.url().to_string()) {
                    let _ = action.handle(&self, request, &caps, json_input, json_output);
                }
            } else {
                let response = Response::empty(StatusCode(404));
                let _ = request.respond(response);
            }
        }
    }

    pub fn error_response(&self, request: Request, error: &str) -> Result<()>
    {
        let response = Response::empty(StatusCode(400));
        let _ = request.respond(response);
        Err(Error::new(ErrorKind::InvalidInput, error))
    }
}

