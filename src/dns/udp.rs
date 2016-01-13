use std::net::UdpSocket;
use std::io::BufWriter;
use std::io::Result;

use dns::protocol::{DnsHeader,
                    QueryResult,
                    DnsQuestion,
                    DnsProtocol,
                    QueryType};

pub struct DnsUdpClient<'a> {
    server: &'a str,
    protocol: DnsProtocol
}

impl<'a> DnsUdpClient<'a> {
    pub fn new(server: &'a str) -> DnsUdpClient {
        DnsUdpClient {
            server: server,
            protocol: DnsProtocol::new()
        }
    }

    fn build_query(&self,
                   qname: &String,
                   qtype: QueryType,
                   data: &mut Vec<u8>) -> Result<()> {

        let mut writer = BufWriter::new(data);

        let head = DnsHeader::new();
        try!(head.write(&mut writer));

        let question = DnsQuestion::new(qname, qtype);
        try!(question.write(&mut writer));

        Ok(())
    }

    pub fn send_query(&mut self,
                      qname: &String,
                      qtype: QueryType) -> Result<QueryResult> {

        // Prepare request
        let mut data = Vec::new();
        try!(self.build_query(qname, qtype, &mut data));

        // Set up socket and send data
        let socket = try!(UdpSocket::bind("0.0.0.0:34254"));
        try!(socket.send_to(&data, (self.server, 53)));

        // Retrieve response
        let _ = try!(socket.recv_from(&mut self.protocol.buf));

        drop(socket);

        // Process response
        let mut response = DnsHeader::new();
        self.protocol.pos += try!(response.read(&self.protocol.buf));

        //println!("{}", response);

        let mut domain = String::new();
        self.protocol.read_qname(&mut domain, false);
        let _ = self.protocol.read_u16(); // qtype
        let _ = self.protocol.read_u16(); // class

        let mut result = QueryResult { domain: domain,
                                       answers: Vec::new(),
                                       authorities: Vec::new(),
                                       resources: Vec::new() };

        self.protocol.read_records(response.answers, &mut result.answers);
        self.protocol.read_records(response.authorative_entries, &mut result.authorities);
        self.protocol.read_records(response.resource_entries, &mut result.resources);

        Ok(result)
    }
}
