mod dns;

extern crate rand;
extern crate chrono;

use std::env;
use std::thread::spawn;

use dns::network::DnsServer;
use dns::udp::DnsUdpServer;
use dns::tcp::DnsTcpServer;
use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
//use dns::protocol::ResourceRecord;
//use std::net::Ipv4Addr;

fn main() {

    let mut cache = SynchronizedCache::new();
    cache.run();

    //let mut local_records = Vec::new();
    //local_records.push(ResourceRecord::A("srv.dev.znaptag.com".to_string(), Ipv4Addr::new(192,16,1,21), 86400));
    //local_records.push(ResourceRecord::A("app.dev.znaptag.com".to_string(), Ipv4Addr::new(192,16,1,22), 86400));
    //local_records.push(ResourceRecord::CNAME("test.dev.znaptag.com".to_string(), "app.dev.znaptag.com".to_string(), 86400));
    //cache.update(local_records);

    if let Some(arg1) = env::args().nth(1) {

        let mut resolver = DnsResolver::new(&cache);
        let res = resolver.resolve(&arg1);
        if let Ok(result) = res {
            //println!("query domain: {0}", result.domain);

            println!("answers:");
            for x in result.answers {
                println!("\t{:?}", x);
            }

            println!("authorities:");
            for x in result.authorities {
                println!("\t{:?}", x);
            }

            println!("resources:");
            for x in result.resources {
                println!("\t{:?}", x);
            }

        }
        else if let Err(err) = res {
            println!("error: {}", err);
        }
    }
    else {
        //println!("usage: ./resolve <domain>");

        let udp_cache_clone = cache.clone();
        let udp_server = spawn(move|| {
            let mut server = DnsUdpServer::new(&udp_cache_clone, 1053);
            server.run();
        });

        let tcp_cache_clone = cache.clone();
        let _ = spawn(move|| {
            let mut server = DnsTcpServer::new(&tcp_cache_clone, 1053);
            server.run();
        });

        let _ = udp_server.join();
    }
}
