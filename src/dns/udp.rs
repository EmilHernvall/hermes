use std::net::UdpSocket;
use std::net::{Ipv4Addr,Ipv6Addr};
use std::io::BufWriter;
use std::io::Result;

use dns::protocol::{ResourceRecord, DnsHeader, QueryResult, DnsQuestion, QueryType, querytype_number};

pub struct DnsUdpProtocol<'a> {
    server: &'a str,
    buf: [u8; 512],
    pos: usize
}

impl<'a> DnsUdpProtocol<'a> {
    pub fn new(server: &'a str) -> DnsUdpProtocol {
        DnsUdpProtocol {
            server: server,
            buf: [0; 512],
            pos: 0
        }
    }

    fn read_u16(&mut self) -> u16
    {
        let res = ((self.buf[self.pos] as u16) << 8) | (self.buf[self.pos+1] as u16);
        self.pos += 2;
        res
    }


    fn read_u32(&mut self) -> u32
    {
        let res = ((self.buf[self.pos+3] as u32) << 0) |
                  ((self.buf[self.pos+2] as u32) << 8) |
                  ((self.buf[self.pos+1] as u32) << 16) |
                  ((self.buf[self.pos+0] as u32) << 24);
        self.pos += 4;
        res
    }

    fn read_qname(&mut self, outstr: &mut String, nomove: bool)
    {
        let mut pos = self.pos;
        let mut jumped = false;

        let mut delim = "";
        loop {
            let len = self.buf[pos] as u8;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we only need to update the global position by two bytes.
            if (len & 0xC0) > 0 {
                let offset = (((len as u16) ^ 0xC0) << 8) | (self.buf[pos+1] as u16);
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            if len == 0 {
                break;
            }

            outstr.push_str(delim);
            outstr.push_str(&String::from_utf8_lossy(&self.buf[pos..pos+len as usize]));
            delim = ".";

            pos += len as usize;
        }

        if nomove {
            return;
        }

        if jumped {
            self.pos += 2;
        } else {
            self.pos = pos;
        }
    }

    fn read_records(&mut self, count: u16, result: &mut Vec<ResourceRecord>) {
        for _ in 0..count {
            let mut domain = String::new();
            self.read_qname(&mut domain, false);

            let qtype = self.read_u16();
            let _ = self.read_u16();
            let ttl = self.read_u32();
            let data_len = self.read_u16();

            if qtype == querytype_number(&QueryType::A) {
                let raw_addr = self.read_u32();
                let addr = Ipv4Addr::new(((raw_addr >> 24) & 0xFF) as u8,
                                         ((raw_addr >> 16) & 0xFF) as u8,
                                         ((raw_addr >> 8) & 0xFF) as u8,
                                         ((raw_addr >> 0) & 0xFF) as u8);
                result.push(ResourceRecord::A(domain, addr, ttl));
            }
            else if qtype == querytype_number(&QueryType::AAAA) {
                let raw_addr1 = self.read_u32();
                let raw_addr2 = self.read_u32();
                let raw_addr3 = self.read_u32();
                let raw_addr4 = self.read_u32();
                let addr = Ipv6Addr::new(((raw_addr1 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr1 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr2 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr2 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr3 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr3 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr4 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr4 >> 0) & 0xFFFF) as u16);

                result.push(ResourceRecord::AAAA(domain, addr, ttl));
            }
            else if qtype == querytype_number(&QueryType::NS) {
                let mut ns = String::new();
                self.read_qname(&mut ns, true);
                self.pos += data_len as usize;

                result.push(ResourceRecord::NS(domain, ns, ttl));
            }
            else if qtype == querytype_number(&QueryType::CNAME) {
                let mut cname = String::new();
                self.read_qname(&mut cname, true);
                self.pos += data_len as usize;

                result.push(ResourceRecord::CNAME(domain, cname, ttl));
            }
            else if qtype == querytype_number(&QueryType::SRV) {
                let priority = self.read_u16();
                let weight = self.read_u16();
                let port = self.read_u16();

                let mut srv = String::new();
                self.read_qname(&mut srv, true);
                self.pos += data_len as usize;

                result.push(ResourceRecord::SRV(domain, priority, weight, port, srv, ttl));
            }
            else if qtype == querytype_number(&QueryType::MX) {
                let newpos = self.pos + data_len as usize;
                let priority = self.read_u16();
                let mut mx = String::new();
                self.read_qname(&mut mx, false);
                self.pos = newpos;

                result.push(ResourceRecord::MX(domain, priority, mx, ttl));
            }
            else {
                self.pos += data_len as usize;

                result.push(ResourceRecord::UNKNOWN(domain, qtype, data_len, ttl));
            }
        }
    }

    fn build_query(&self, domain: &String, data: &mut Vec<u8>) -> Result<()> {
        let mut writer = BufWriter::new(data);

        let head = DnsHeader::new();
        try!(head.write(&mut writer));

        let question = DnsQuestion::new(domain, QueryType::A);
        try!(question.write(&mut writer));

        Ok(())
    }

    pub fn send_query(&mut self, qname: &String) -> Result<QueryResult> {

        // Prepare request
        let mut data = Vec::new();
        try!(self.build_query(qname, &mut data));

        // Set up socket and send data
        let socket = try!(UdpSocket::bind("0.0.0.0:34254"));
        try!(socket.send_to(&data, (self.server, 53)));

        // Retrieve response
        let _ = try!(socket.recv_from(&mut self.buf));

        drop(socket);

        // Process response
        let mut response = DnsHeader::new();
        self.pos += try!(response.read(&self.buf));

        //println!("{}", response);

        let mut domain = String::new();
        self.read_qname(&mut domain, false);
        let _ = self.read_u16(); // qtype
        let _ = self.read_u16(); // class

        let mut result = QueryResult { domain: domain,
                                       answers: Vec::new(),
                                       authorities: Vec::new(),
                                       resources: Vec::new() };

        self.read_records(response.answers, &mut result.answers);
        self.read_records(response.authorative_entries, &mut result.authorities);
        self.read_records(response.resource_entries, &mut result.resources);

        Ok(result)
    }
}
