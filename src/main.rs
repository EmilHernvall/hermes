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
use web::server::run_webserver;

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

    let udp_server = DnsUdpServer::new(context.clone());
    udp_server.run_server();

    let tcp_server = DnsTcpServer::new(context.clone());
    tcp_server.run_server();

    run_webserver(context);
}

fn get_rootservers() -> Vec<ResourceRecord>
{
    let mut rootservers = Vec::new();

    rootservers.push(ResourceRecord::NS("".to_string(),"a.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("a.root-servers.net".to_string(),"198.41.0.4".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("a.root-servers.net".to_string(),"2001:503:ba3e::2:30".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"b.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("b.root-servers.net".to_string(),"192.228.79.201".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("b.root-servers.net".to_string(),"2001:500:84::b".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"c.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("c.root-servers.net".to_string(),"192.33.4.12".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("c.root-servers.net".to_string(),"2001:500:2::c".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"d.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("d.root-servers.net".to_string(),"199.7.91.13".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("d.root-servers.net".to_string(),"2001:500:2d::d".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"e.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("e.root-servers.net".to_string(),"192.203.230.10".parse::<Ipv4Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"f.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("f.root-servers.net".to_string(),"192.5.5.241".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("f.root-servers.net".to_string(),"2001:500:2f::f".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"g.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("g.root-servers.net".to_string(),"192.112.36.4".parse::<Ipv4Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"h.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("h.root-servers.net".to_string(),"198.97.190.53".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("h.root-servers.net".to_string(),"2001:500:1::53".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"i.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("i.root-servers.net".to_string(),"192.36.148.17".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("i.root-servers.net".to_string(),"2001:7fe::53".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"j.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("j.root-servers.net".to_string(),"192.58.128.30".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("j.root-servers.net".to_string(),"2001:503:c27::2:30".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"k.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("k.root-servers.net".to_string(),"193.0.14.129".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("k.root-servers.net".to_string(),"2001:7fd::1".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"l.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("l.root-servers.net".to_string(),"199.7.83.42".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("l.root-servers.net".to_string(),"2001:500:3::42".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers.push(ResourceRecord::NS("".to_string(),"m.root-servers.net".to_string(),3600000));
    rootservers.push(ResourceRecord::A("m.root-servers.net".to_string(),"202.12.27.33".parse::<Ipv4Addr>().unwrap(),3600000));
    rootservers.push(ResourceRecord::AAAA("m.root-servers.net".to_string(),"2001:dc3::35".parse::<Ipv6Addr>().unwrap(),3600000));

    rootservers
}
