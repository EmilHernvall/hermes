use std::io::Result;

use dns::resolve::DnsResolver;
use dns::protocol::{DnsPacket, QueryType, ResourceRecord};
use dns::buffer::{PacketBuffer, VectorPacketBuffer};

pub trait DnsServer {
    fn run(&mut self) -> bool;
}

pub fn resolve_cnames(lookup_list: &Vec<ResourceRecord>,
                      results: &mut Vec<DnsPacket>,
                      resolver: &mut DnsResolver)
{
    for ref rec in lookup_list {
        if let &ResourceRecord::CNAME(_, ref host, _) = *rec {
            if let Ok(result2) = resolver.resolve(host,
                                                  QueryType::A) {

                let new_unmatched = result2.get_unresolved_cnames();
                results.push(result2);

                resolve_cnames(&new_unmatched, results, resolver);
            }
        }
    }
}

pub fn build_response(request: &DnsPacket,
                      resolver: &mut DnsResolver,
                      res_buffer: &mut VectorPacketBuffer,
                      max_size: usize) -> Result<()>
{
    let mut packet = DnsPacket::new();

    let mut results = Vec::new();
    for question in &request.questions {

        packet.questions.push(question.clone());

        match resolver.resolve(&question.name,
                               question.qtype.clone()) {

            Ok(result) => {
                let unmatched = result.get_unresolved_cnames();
                results.push(result);

                resolve_cnames(&unmatched, &mut results, resolver);
            },
            Err(err) => {
                println!("Resolving {} failed: {:?}", question.name, err);
            }
        }
    }

    print!("{:?} {}: ",
           request.questions[0].qtype,
           request.questions[0].name);
    for result in results {
        for answer in result.answers {
            print!("{:?} ", answer);
            packet.answers.push(answer);
        }
    }
    println!("");

    packet.header.id = request.header.id;
    packet.header.recursion_available = true;
    packet.header.response = true;

    try!(packet.write(res_buffer, max_size));

    Ok(())
}
