use std::io::{Result, Error, ErrorKind};

use dns::resolve::DnsResolver;
use dns::protocol::{DnsPacket, QueryType, ResourceRecord, ResultCode};
use dns::buffer::{PacketBuffer, VectorPacketBuffer};

pub trait DnsServer {
    fn run_server(self) -> bool;
}

pub fn resolve_cnames(lookup_list: &Vec<ResourceRecord>,
                      results: &mut Vec<DnsPacket>,
                      resolver: &mut Box<DnsResolver>)
{
    for ref rec in lookup_list {
        match *rec {
            &ResourceRecord::CNAME(_, ref host, _) => {
                if let Ok(result2) = resolver.resolve(host,
                                                      QueryType::A) {

                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    resolve_cnames(&new_unmatched, results, resolver);
                }
            },
            &ResourceRecord::SRV(_, _, _, _, ref srv, _) => {
                if let Ok(result2) = resolver.resolve(srv,
                                                      QueryType::A) {

                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    resolve_cnames(&new_unmatched, results, resolver);
                }
            },
            _ => {}
        }
    }
}

pub fn build_response(request: &DnsPacket,
                      resolver: &mut Box<DnsResolver>,
                      res_buffer: &mut VectorPacketBuffer,
                      max_size: usize) -> Result<()>
{
    if request.questions.len() == 0 {
        return Err(Error::new(ErrorKind::InvalidInput, "Missing question"));
    }

    let mut packet = DnsPacket::new();

    let mut results = Vec::new();

    let question = &request.questions[0];
    packet.questions.push(question.clone());

    let rescode = match resolver.resolve(&question.name,
                                         question.qtype.clone()) {

        Ok(result) => {
            let rescode = result.header.rescode.clone();

            let unmatched = result.get_unresolved_cnames();
            results.push(result);

            resolve_cnames(&unmatched, &mut results, resolver);

            rescode
        },
        Err(err) => {
            println!("Got error: {:?}", err);
            ResultCode::NXDOMAIN
        }
    };

    print!("{:?} {}: ",
           request.questions[0].qtype,
           request.questions[0].name);
    for result in results {
        for rec in result.answers {
            print!("{:?} ", rec);
            packet.answers.push(rec);
        }
        for rec in result.authorities {
            print!("{:?} ", rec);
            packet.authorities.push(rec);
        }
        for rec in result.resources {
            print!("{:?} ", rec);
            packet.resources.push(rec);
        }
    }
    println!("");

    packet.header.id = request.header.id;
    packet.header.rescode = rescode;
    packet.header.recursion_available = true;
    packet.header.response = true;

    try!(packet.write(res_buffer, max_size));

    Ok(())
}
