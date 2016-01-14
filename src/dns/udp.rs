use std::net::UdpSocket;
use std::io::Result;

use dns::protocol::{DnsHeader,
                    QueryResult,
                    DnsQuestion,
                    DnsPacket,
                    QueryType};

pub struct DnsUdpClient<'a> {
    server: &'a str,
    packet: DnsPacket
}

impl<'a> DnsUdpClient<'a> {
    pub fn new(server: &'a str) -> DnsUdpClient {
        DnsUdpClient {
            server: server,
            packet: DnsPacket::new()
        }
    }

    pub fn send_query(&mut self,
                      qname: &String,
                      qtype: QueryType) -> Result<QueryResult> {

        // Prepare request
        let mut req_packet = DnsPacket::new();

        let mut head = DnsHeader::new();
        head.questions = 1;
        try!(head.write(&mut req_packet));

        let question = DnsQuestion::new(qname, qtype);
        try!(question.write(&mut req_packet));

        // Set up socket and send data
        let socket = try!(UdpSocket::bind("0.0.0.0:34254"));
        try!(socket.send_to(&req_packet.buf[0..req_packet.pos], (self.server, 53)));

        // Retrieve response
        let _ = try!(socket.recv_from(&mut self.packet.buf));

        drop(socket);

        self.packet.read()
    }
}
