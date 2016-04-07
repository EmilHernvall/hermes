use std::io::Result;
use std::sync::Arc;

use dns::resolve::DnsResolver;
use dns::protocol::{DnsPacket, QueryType, ResourceRecord, ResultCode};
use dns::buffer::{PacketBuffer, VectorPacketBuffer};
use dns::context::ServerContext;

pub trait DnsServer {
    fn run_server(self) -> bool;
}

pub fn resolve_cnames(lookup_list: &Vec<ResourceRecord>,
                      results: &mut Vec<DnsPacket>,
                      resolver: &mut Box<DnsResolver>)
{
    for ref rec in lookup_list {
        match *rec {
            &ResourceRecord::CNAME { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host,
                                                      QueryType::A,
                                                      true) {

                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    resolve_cnames(&new_unmatched, results, resolver);
                }
            },
            &ResourceRecord::SRV { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host,
                                                      QueryType::A,
                                                      true) {

                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    resolve_cnames(&new_unmatched, results, resolver);
                }
            },
            _ => {}
        }
    }
}

pub fn build_response(context: Arc<ServerContext>,
                      request: &DnsPacket,
                      resolver: &mut Box<DnsResolver>,
                      res_buffer: &mut VectorPacketBuffer,
                      max_size: usize) -> Result<()>
{
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_available = context.allow_recursive;
    packet.header.response = true;

    if request.header.recursion_desired && !context.allow_recursive {
        packet.header.rescode = ResultCode::REFUSED;
    }
    else if request.questions.len() == 0 {
        packet.header.rescode = ResultCode::FORMERR;
    }
    else {
        let mut results = Vec::new();

        let question = &request.questions[0];
        packet.questions.push(question.clone());

        let rescode = match resolver.resolve(&question.name,
                                             question.qtype.clone(),
                                             request.header.recursion_desired) {

            Ok(result) => {
                let rescode = result.header.rescode.clone();

                let unmatched = result.get_unresolved_cnames();
                results.push(result);

                resolve_cnames(&unmatched, &mut results, resolver);

                rescode
            },
            Err(err) => {
                println!("Got error: {:?}", err);
                ResultCode::SERVFAIL
            }
        };

        packet.header.rescode = rescode;

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
    }

    try!(packet.write(res_buffer, max_size));

    Ok(())
}
