use std::io::Result;

use dns::resolve::DnsResolver;
use dns::protocol::{DnsHeader, QueryResult, DnsPacket, QueryType, ResourceRecord};
use dns::buffer::{PacketBuffer, VectorPacketBuffer};

pub trait DnsServer {
    fn run(&mut self) -> bool;
}

pub fn resolve_cnames(lookup_list: &Vec<ResourceRecord>,
                      results: &mut Vec<QueryResult>,
                      resolver: &mut DnsResolver)
{
    for ref rec in lookup_list {
        if let &ResourceRecord::CNAME(_, ref host, _) = *rec {
            if let Ok(result2) = resolver.resolve(host,
                                                  QueryType::A) {

                let new_unmatched = result2.get_unresolved_cnames();
                resolve_cnames(&new_unmatched, results, resolver);
                results.push(result2);
            }
        }
    }
}

pub fn build_response(request: &QueryResult,
                      resolver: &mut DnsResolver,
                      res_buffer: &mut VectorPacketBuffer,
                      max_size: usize) -> Result<()>
{
    let mut res_packet = DnsPacket::new(res_buffer);

    let mut results = Vec::new();
    for question in &request.questions {
        println!("{}", question);
        if let Ok(result) = resolver.resolve(&question.name,
                                             question.qtype.clone()) {

            let unmatched = result.get_unresolved_cnames();
            resolve_cnames(&unmatched, &mut results, resolver);
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

    let mut size = head.binary_len();
    for ref question in &request.questions {
        size += question.binary_len(&res_packet);
    }

    let mut answer_count = answers.len();

    for (i, answer) in answers.iter().enumerate() {
        size += answer.binary_len(&res_packet);
        if size > max_size {
            answer_count = i;
            break;
        }
    }

    head.id = request.id;
    head.recursion_available = true;
    head.questions = request.questions.len() as u16;
    head.answers = answer_count as u16;
    head.response = true;
    head.truncated_message = answer_count < answers.len();

    try!(head.write(&mut res_packet));

    for question in &request.questions {
        try!(question.write(&mut res_packet));
    }

    for answer in answers.iter().take(answer_count) {
        try!(answer.write(&mut res_packet));
    }

    Ok(())
}
