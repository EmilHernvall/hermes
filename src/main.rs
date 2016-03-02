mod dns;

extern crate rand;
extern crate chrono;
extern crate tiny_http;
extern crate rustc_serialize;
extern crate ascii;
extern crate handlebars;
extern crate regex;

use std::env;
use std::sync::Arc;
use std::thread::spawn;
use std::net::{Ipv4Addr, Ipv6Addr};

use dns::server::DnsServer;
use dns::udp::DnsUdpServer;
use dns::udp::DnsUdpClient;
use dns::tcp::DnsTcpServer;
use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
use dns::protocol::{QueryType,ResourceRecord};
use dns::web::run_webserver;
use dns::authority::Authority;

fn main() {

    let client = Arc::new(DnsUdpClient::new());
    client.run().unwrap();

    let authority = Arc::new(Authority::new());

    let mut cache = SynchronizedCache::new();
    cache.run();
    cache.update(get_rootservers());

    if let Some(arg1) = env::args().nth(1) {

        let mut resolver = DnsResolver::new(&client, &cache);
        let res = resolver.resolve(&arg1, QueryType::A);
        if let Ok(result) = res {
            result.print();
        } else if let Err(err) = res {
            println!("error: {}", err);
        }
    }
    else {
        //println!("usage: ./resolve <domain>");

        let port = 53;

        println!("Listening on port {}", port);

        let udp_client_clone = client.clone();
        let udp_cache_clone = cache.clone();
        let udp_authority_clone = authority.clone();
        let _ = spawn(move|| {
            let mut server = DnsUdpServer::new(udp_client_clone,
                                               udp_authority_clone,
                                               &udp_cache_clone,
                                               port);
            server.run();
        });

        let tcp_client_clone = client.clone();
        let tcp_cache_clone = cache.clone();
        let tcp_authority_clone = authority.clone();
        let _ = spawn(move|| {
            let mut server = DnsTcpServer::new(tcp_client_clone,
                                               tcp_authority_clone,
                                               &tcp_cache_clone,
                                               port);
            server.run();
        });

        run_webserver(&*authority, &cache);
    }
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
