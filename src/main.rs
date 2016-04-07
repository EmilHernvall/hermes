mod dns;
mod web;

extern crate rand;
extern crate chrono;
extern crate tiny_http;
extern crate rustc_serialize;
extern crate ascii;
extern crate handlebars;
extern crate regex;
extern crate getopts;

use std::env;
use std::sync::Arc;
use std::net::{Ipv4Addr, Ipv6Addr};

use getopts::Options;

use dns::server::DnsServer;
use dns::udp::DnsUdpServer;
use dns::tcp::DnsTcpServer;
use dns::protocol::ResourceRecord;
use dns::context::ServerContext;
use web::server::WebServer;
use web::cache::CacheAction;
use web::authority::{AuthorityAction,ZoneAction};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("a", "authority", "disable support for recursive lookups, and serve only local zones");
    opts.optopt("f", "forward", "forward replies to specified dns server", "SERVER");

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if opt_matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let mut context = Arc::new(ServerContext::new());

    if let Some(ctx) = Arc::get_mut(&mut context) {

        let mut index_rootservers = true;
        if opt_matches.opt_present("f") {
            match opt_matches.opt_str("f").and_then(|x| x.parse::<Ipv4Addr>().ok()) {
                Some(ip) => {
                    ctx.forward_server = Some((ip.to_string(), 53));
                    index_rootservers = false;
                    println!("Running as forwarder");
                },
                None => {
                    println!("Forward parameter must be a valid Ipv4 address");
                    return;
                }
            }
        }

        if opt_matches.opt_present("a") {
            ctx.allow_recursive = false;
        }

        match ctx.initialize() {
            Ok(_) => {},
            Err(e) => {
                println!("Server failed to initialize: {:?}", e);
                return;
            }
        }

        if index_rootservers {
            let _ = ctx.cache.update(&get_rootservers());
        }
    }


    let port = 53;

    println!("Listening on port {}", port);

    // Start DNS servers
    let udp_server = DnsUdpServer::new(context.clone());
    udp_server.run_server();

    let tcp_server = DnsTcpServer::new(context.clone());
    tcp_server.run_server();

    // Start web server
    let mut webserver = WebServer::new(context.clone());

    webserver.register_action(Box::new(CacheAction::new(context.clone())));
    webserver.register_action(Box::new(AuthorityAction::new(context.clone())));
    webserver.register_action(Box::new(ZoneAction::new(context.clone())));

    webserver.run_webserver();
}

fn get_rootservers() -> Vec<ResourceRecord>
{
    let mut rootservers = Vec::new();

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "a.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "a.root-servers.net".to_string(), addr: "198.41.0.4".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "a.root-servers.net".to_string(), addr: "2001:503:ba3e::2:30".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "b.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "b.root-servers.net".to_string(), addr: "192.228.79.201".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "b.root-servers.net".to_string(), addr: "2001:500:84::b".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "c.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "c.root-servers.net".to_string(), addr: "192.33.4.12".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "c.root-servers.net".to_string(), addr: "2001:500:2::c".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "d.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "d.root-servers.net".to_string(), addr: "199.7.91.13".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "d.root-servers.net".to_string(), addr: "2001:500:2d::d".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "e.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "e.root-servers.net".to_string(), addr: "192.203.230.10".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "f.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "f.root-servers.net".to_string(), addr: "192.5.5.241".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "f.root-servers.net".to_string(), addr: "2001:500:2f::f".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(),  host: "g.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "g.root-servers.net".to_string(), addr: "192.112.36.4".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "h.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "h.root-servers.net".to_string(), addr: "198.97.190.53".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "h.root-servers.net".to_string(), addr: "2001:500:1::53".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "i.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "i.root-servers.net".to_string(), addr: "192.36.148.17".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "i.root-servers.net".to_string(), addr: "2001:7fe::53".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "j.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "j.root-servers.net".to_string(), addr: "192.58.128.30".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "j.root-servers.net".to_string(), addr: "2001:503:c27::2:30".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "k.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "k.root-servers.net".to_string(), addr: "193.0.14.129".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "k.root-servers.net".to_string(), addr: "2001:7fd::1".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "l.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "l.root-servers.net".to_string(), addr: "199.7.83.42".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "l.root-servers.net".to_string(), addr: "2001:500:3::42".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers.push(ResourceRecord::NS { domain: "".to_string(), host: "m.root-servers.net".to_string(), ttl: 3600000 });
    rootservers.push(ResourceRecord::A{ domain: "m.root-servers.net".to_string(), addr: "202.12.27.33".parse::<Ipv4Addr>().unwrap(),ttl: 3600000 });
    rootservers.push(ResourceRecord::AAAA { domain: "m.root-servers.net".to_string(), addr: "2001:dc3::35".parse::<Ipv6Addr>().unwrap(), ttl: 3600000 });

    rootservers
}
