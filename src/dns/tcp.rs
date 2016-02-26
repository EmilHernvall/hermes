use std::io::{Result, Read, Write};
use std::net::{TcpListener, TcpStream};

use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
//use dns::network::{DnsClient, DnsServer};
use dns::network::DnsServer;
use dns::udp::DnsUdpClient;
use dns::protocol::{DnsHeader, DnsPacket};

use dns::buffer::{PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};

/*pub struct DnsTcpClient<'a> {
    server: &'a str
}

impl<'a> DnsTcpClient<'a> {
    pub fn new(server: &'a str) -> DnsTcpClient {
        DnsTcpClient {
            server: server
        }
    }
}*/

pub struct DnsTcpServer<'a> {
    client: &'a DnsUdpClient,
    cache: &'a SynchronizedCache,
    port: u16
}

impl<'a> DnsTcpServer<'a> {
    pub fn new(client: &'a DnsUdpClient,
               cache: &'a SynchronizedCache,
               port: u16) -> DnsTcpServer<'a> {
        DnsTcpServer {
            client: client,
            cache: cache,
            port: port
        }
    }

    pub fn handle_request(&mut self, mut stream: &TcpStream) -> Result<()> {
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
                let mut resolver = DnsResolver::new(self.client, self.cache);
                if let Ok(result) = resolver.resolve(&question.name,
                                                     question.qtype.clone()) {
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

        Ok(())
    }
}

impl<'a> DnsServer for DnsTcpServer<'a> {
    fn run(&mut self) -> bool {
        let socket_attempt = TcpListener::bind(("0.0.0.0", self.port));
        if !socket_attempt.is_ok() {
            return false;
        }

        let socket = socket_attempt.unwrap();
        for wrap_stream in socket.incoming() {
            if let Ok(stream) = wrap_stream {
                match self.handle_request(&stream) {
                    Ok(_) => {},
                    Err(err) => {
                        println!("TCP request failed: {:?}", err);
                    }
                }
            }
        }

        true
    }
}
