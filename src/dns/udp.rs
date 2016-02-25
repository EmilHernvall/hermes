use std::net::UdpSocket;
use std::io::Result;

use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
use dns::network::{DnsClient, DnsServer};
use dns::protocol::{DnsHeader,
                    QueryResult,
                    DnsQuestion,
                    DnsPacket,
                    QueryType};

use dns::buffer::{PacketBuffer, BytePacketBuffer};

pub struct DnsUdpClient<'a> {
    server: &'a str
}

impl<'a> DnsUdpClient<'a> {
    pub fn new(server: &'a str) -> DnsUdpClient {
        DnsUdpClient {
            server: server
        }
    }
}

impl<'a> DnsClient for DnsUdpClient<'a> {
    fn send_query(&mut self,
                  qname: &String,
                  qtype: QueryType) -> Result<QueryResult> {

        // Prepare request
        let mut req_buffer = BytePacketBuffer::new();
        let mut req_packet = DnsPacket::new(&mut req_buffer);

        let mut head = DnsHeader::new();
        head.questions = 1;
        try!(head.write(&mut req_packet));

        let question = DnsQuestion::new(qname, qtype);
        try!(question.write(&mut req_packet));

        // Set up socket and send data
        let socket = try!(UdpSocket::bind("0.0.0.0:34254"));
        try!(socket.send_to(&req_packet.buffer.buf[0..req_packet.buffer.pos], (self.server, 53)));

        // Retrieve response
        let mut res_buffer = BytePacketBuffer::new();
        {
            let _ = try!(socket.recv_from(&mut res_buffer.buf));
        };

        drop(socket);

        let mut response_packet = DnsPacket::new(&mut res_buffer);
        response_packet.read()
    }
}

pub struct DnsUdpServer<'a> {
    cache: &'a SynchronizedCache,
    port: u16
}

impl<'a> DnsUdpServer<'a> {
    pub fn new(cache: &SynchronizedCache, port: u16) -> DnsUdpServer {
        DnsUdpServer {
            cache: cache,
            port: port
        }
    }

    pub fn handle_request(&mut self, socket: &UdpSocket) -> Result<()> {
        let mut req_buffer = BytePacketBuffer::new();
        let mut packet = DnsPacket::new(&mut req_buffer);
        let (_, src) = try!(socket.recv_from(&mut packet.buffer.buf));

        let request = try!(packet.read());

        let mut res_buffer = BytePacketBuffer::new();
        let mut res_packet = DnsPacket::new(&mut res_buffer);

        {
            let mut results = Vec::new();
            for question in &request.questions {
                println!("{}", question);
                let mut resolver = DnsResolver::new(self.cache);
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
                size += question.binary_len(&res_packet);
            }

            let mut answer_count = answers.len();

            for (i, answer) in answers.iter().enumerate() {
                size += answer.binary_len(&res_packet);
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

            for question in &request.questions {
                try!(question.write(&mut res_packet));
            }

            for answer in answers.iter().take(answer_count) {
                try!(answer.write(&mut res_packet));
            }
        };

        try!(socket.send_to(&res_packet.buffer.buf[0..res_packet.buffer.pos], src));

        Ok(())
    }
}

impl<'a> DnsServer for DnsUdpServer<'a> {
    fn run(&mut self) -> bool {
        let socket_attempt = UdpSocket::bind(("0.0.0.0", self.port));
        if !socket_attempt.is_ok() {
            return false;
        }

        let socket = socket_attempt.unwrap();
        loop {
            match self.handle_request(&socket) {
                Ok(_) => {},
                Err(err) => {
                    println!("UDP request failed: {:?}", err);
                }
            }
        }
    }
}
