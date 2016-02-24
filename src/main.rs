mod dns;

extern crate rand;
extern crate chrono;

use std::env;
use std::io::{Result, Read, Write};
use std::net::{UdpSocket, TcpListener};
use std::thread::spawn;

use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
use dns::protocol::{DnsPacket,
                    PacketBuffer,
                    BytePacketBuffer,
                    StreamPacketBuffer,
                    VectorPacketBuffer,
                    DnsHeader};

fn run_udp_server(cache: &SynchronizedCache) -> Result<()> {
    let socket = try!(UdpSocket::bind("0.0.0.0:1053"));

    let mut resolver = DnsResolver::new(&cache);

    loop {
        let mut req_buffer = BytePacketBuffer::new();
        let mut packet = DnsPacket::new(&mut req_buffer);
        let (_, src) = try!(socket.recv_from(&mut packet.buffer.buf));

        if let Ok(request) = packet.read() {

            let mut res_buffer = BytePacketBuffer::new();
            let mut res_packet = DnsPacket::new(&mut res_buffer);

            {
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

                let mut size = head.binary_len();
                for ref question in &request.questions {
                    size += question.binary_len(&packet);
                }

                let mut answer_count = answers.len();

                for (i, answer) in answers.iter().enumerate() {
                    size += answer.binary_len(&packet);
                    if size > 512 {
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

                for question in request.questions {
                    try!(question.write(&mut res_packet));
                }

                for answer in answers.iter().take(answer_count) {
                    try!(answer.write(&mut res_packet));
                }
            };

            try!(socket.send_to(&res_packet.buffer.buf[0..res_packet.buffer.pos], src));
        }
    }

    //Ok(())
}

fn run_tcp_server(cache: &SynchronizedCache) -> Result<()> {
    let listener = try!(TcpListener::bind("127.0.0.1:1053"));

    let mut resolver = DnsResolver::new(&cache);

    for wrap_stream in listener.incoming() {
        if let Ok(mut stream) = wrap_stream {

            let request = {
                let mut len_buffer = [0; 2];
                try!(stream.read(&mut len_buffer));
                let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
                let mut req_packet = DnsPacket::new(&mut stream_buffer);
                try!(req_packet.read())
            };

            let mut res_buffer = VectorPacketBuffer::new();

            {
                let mut res_packet = DnsPacket::new(&mut res_buffer);

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
                head.truncated_message = false;

                try!(head.write(&mut res_packet));

                for question in request.questions {
                    try!(question.write(&mut res_packet));
                }

                for answer in answers {
                    try!(answer.write(&mut res_packet));
                }
            };

            let len = res_buffer.pos();

            let mut len_buffer = [0; 2];
            len_buffer[0] = (len >> 8) as u8;
            len_buffer[1] = (len & 0xFF) as u8;

            try!(stream.write(&len_buffer));
            try!(stream.write(try!(res_buffer.get_range(0, len))));
        }
    }

    Ok(())
}

fn main() {

    let mut cache = SynchronizedCache::new();
    cache.run();

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
        let udp_server = spawn(move|| run_udp_server(&udp_cache_clone));

        let tcp_cache_clone = cache.clone();
        let _ = spawn(move|| run_tcp_server(&tcp_cache_clone));

        let _ = udp_server.join();
    }
}
