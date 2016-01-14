mod dns;

extern crate rand;

use std::env;
use std::io::Result;
use std::net::UdpSocket;

use dns::resolve::DnsResolver;
use dns::protocol::{DnsPacket,
                    DnsHeader,
                    DnsQuestion,
                    ResourceRecord,
                    QueryType,
                    QueryResult,
                    querytype};

fn run_server() -> Result<()> {
    let socket = try!(UdpSocket::bind("0.0.0.0:1053"));

    loop {
        let mut packet = DnsPacket::new();
        let (_, src) = try!(socket.recv_from(&mut packet.buf));

        if let Ok(request) = packet.read() {

            let mut req_packet = DnsPacket::new();
            {

                let mut resolver = DnsResolver::new();
                let mut results = Vec::new();
                for question in &request.questions {
                    println!("{}", question);
                    if let Ok(result) = resolver.resolve(&question.name) {
                        results.push(result);
                    }
                }

                let mut answers = Vec::new();
                for result in results {
                    for answer in result.answers {
                        println!("{:?}", answer);
                        answers.push(answer);
                    }
                }

                let mut head = DnsHeader::new();
                head.id = request.id;
                head.recursion_available = true;
                head.questions = request.questions.len() as u16;
                head.answers = answers.len() as u16;
                head.response = true;

                try!(head.write(&mut req_packet));

                for question in request.questions {
                    try!(question.write(&mut req_packet));
                }

                for answer in answers {
                    answer.write(&mut req_packet);
                }

            };

            try!(socket.send_to(&req_packet.buf[0..req_packet.pos], src));
        }
    }

    //Ok(())
}

fn main() {

    if let Some(arg1) = env::args().nth(1) {

        let mut resolver = DnsResolver::new();
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

        let _ = run_server();
    }
}
