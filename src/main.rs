mod dns;

extern crate rand;
extern crate chrono;

use std::env;
use std::sync::Arc;
use std::thread::spawn;

use dns::network::DnsServer;
use dns::udp::DnsUdpServer;
use dns::udp::DnsUdpClient;
use dns::tcp::DnsTcpServer;
use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
use dns::protocol::QueryType;
//use std::net::Ipv4Addr;

fn main() {

    let client = Arc::new(DnsUdpClient::new());
    client.run().unwrap();

    let mut cache = SynchronizedCache::new();
    cache.run();

    //let mut local_records = Vec::new();
    //local_records.push(ResourceRecord::A("srv.dev.znaptag.com".to_string(), Ipv4Addr::new(192,16,1,21), 86400));
    //local_records.push(ResourceRecord::A("app.dev.znaptag.com".to_string(), Ipv4Addr::new(192,16,1,22), 86400));
    //local_records.push(ResourceRecord::CNAME("test.dev.znaptag.com".to_string(), "app.dev.znaptag.com".to_string(), 86400));
    //cache.update(local_records);

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

        let port = 1053;

        let udp_client_clone = client.clone();
        let udp_cache_clone = cache.clone();
        let udp_server = spawn(move|| {
            let mut server = DnsUdpServer::new(&udp_client_clone, &udp_cache_clone, port);
            server.run();
        });

        let tcp_client_clone = client.clone();
        let tcp_cache_clone = cache.clone();
        let _ = spawn(move|| {
            let mut server = DnsTcpServer::new(&tcp_client_clone, &tcp_cache_clone, port);
            server.run();
        });

        let _ = udp_server.join();
    }
}
