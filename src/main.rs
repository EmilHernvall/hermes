mod dns;

extern crate rand;

use std::env;
use std::io::Result;
use std::net::UdpSocket;
use std::io::BufWriter;

use dns::resolve::DnsResolver;
use dns::protocol::{DnsProtocol,
                    DnsHeader,
                    DnsQuestion,
                    QueryType,
                    querytype};

fn build_response(id: u16,
                  qname: &String,
                  qtype: QueryType,
                  answers: u16,
                  data: &mut Vec<u8>) -> Result<()> {

    let mut writer = BufWriter::new(data);

    let mut head = DnsHeader::new();
    head.id = id;
    head.recursion_available = true;
    head.questions = 1;
    head.answers = 1;

    try!(head.write(&mut writer));

    let question = DnsQuestion::new(qname, qtype);
    try!(question.write(&mut writer));

    Ok(())
}

fn run_server() -> Result<()> {
    let socket = try!(UdpSocket::bind("0.0.0.0:1053"));

    loop {
        let mut reqbuf = [0; 512];
        let (amt, src) = try!(socket.recv_from(&mut reqbuf));

        let mut protocol = DnsProtocol::new();
        protocol.buf = reqbuf;
        protocol.pos = 0;

        let mut header = DnsHeader::new();
        try!(header.read(&mut protocol));
        println!("{}", header);

        let mut qname = String::new();
        protocol.read_qname(&mut qname, false);

        let qtype = querytype(protocol.read_u16());
        let _ = protocol.read_u16();

        println!("qname: {}", qname);
        println!("qtype: {:?}", qtype);

        let mut resolver = DnsResolver::new();
        if let Ok(result) = resolver.resolve(&qname) {
            println!("answers:");
            for x in result.answers {
                println!("\t{:?}", x);
            }
        }

        //let mut resbuf = Vec::new();
        //try!(build_response(header.id, &qname, qtype, &mut resbuf));
        //try!(socket.send_to(&resbuf, src));
    }

    Ok(())
}

fn main() {

    if let Some(arg1) = env::args().nth(1) {

        let mut resolver = DnsResolver::new();
        if let Ok(result) = resolver.resolve(&arg1) {
            println!("query domain: {0}", result.domain);

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
    }
    else {
        //println!("usage: ./resolve <domain>");

        let _ = run_server();
    }
}
