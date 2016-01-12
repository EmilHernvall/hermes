use std::io::BufWriter;
use std::io::Write;
use std::io::Result;
//use std::io::stdout;
use std::net::UdpSocket;
use std::net::{Ipv4Addr,Ipv6Addr};
use std::fmt;
use std::env;
use std::vec::Vec;

#[derive(Debug)]
#[allow(dead_code)]
enum QueryType {
    UNKNOWN, // 0
    A, // 1
    NS, // 2
    CNAME, // 5
    SOA, // 6
    PTR, // 12
    MX, // 15
    TXT, // 16
    AAAA, // 28
    SRV // 33
}

fn querytype_number(qtype: &QueryType) -> u16 {
    match *qtype {
        QueryType::UNKNOWN => 0,
        QueryType::A => 1,
        QueryType::NS => 2,
        QueryType::CNAME => 5,
        QueryType::SOA => 6,
        QueryType::PTR => 12,
        QueryType::MX => 15,
        QueryType::TXT => 16,
        QueryType::AAAA => 28,
        QueryType::SRV => 33,
    }
}

/*fn querytype(num: u16) -> QueryType {
    match num {
        1 => QueryType::A,
        2 => QueryType::NS,
        5 => QueryType::CNAME,
        6 => QueryType::SOA,
        12 => QueryType::PTR,
        15 => QueryType::MX,
        16 => QueryType::TXT,
        28 => QueryType::AAAA,
        33 => QueryType::SRV,
        _ => QueryType::UNKNOWN
    }
}*/

#[derive(Debug)]
#[allow(dead_code)]
enum ResourceRecord {
    UNKNOWN(String, u16, u32), // 0
    A(String, Ipv4Addr, u32), // 1
    NS(String, String, u32), // 2
    CNAME(String, String, u32), // 5
    SOA, // 6
    PTR, // 12
    MX(String, u16, String, u32), // 15
    TXT, // 16
    AAAA(String, Ipv6Addr, u32), // 28
    SRV // 33
}

#[derive(Debug)]
struct DnsHeader {
    id: u16, // 16 bits

    recursion_desired: bool, // 1 bit
    truncated_message: bool, // 1 bit
    authorative_answer: bool, // 1 bit
    opcode: u8, // 4 bits
    response: bool, // 1 bit

    rescode: u8, // 4 bits
    checking_disabled: bool, // 1 bit
    authed_data: bool, // 1 bit
    z: bool, // 1 bit
    recursion_available: bool, // 1 bit

    questions: u16, // 16 bits
    answers: u16, // 16 bits
    authorative_entries: u16, // 16 bits
    resource_entries: u16 // 16 bits
}

impl DnsHeader {
    fn new() -> DnsHeader {
        DnsHeader { id: 0,

                    recursion_desired: true,
                    truncated_message: false,
                    authorative_answer: false,
                    opcode: 0,
                    response: false,

                    rescode: 0,
                    checking_disabled: false,
                    authed_data: false,
                    z: false,
                    recursion_available: false,

                    questions: 1,
                    answers: 0,
                    authorative_entries: 0,
                    resource_entries: 0 }
    }

    fn write<T : Write>(&self, writer: &mut BufWriter<T>) -> Result<()> {
        try!(writer.write(&[ (self.id >> 8) as u8,
                             (self.id & 0xFF) as u8 ]));

        try!(writer.write(&[ (((self.recursion_desired as u8)) |
                              ((self.truncated_message as u8) << 1) |
                              ((self.authorative_answer as u8) << 2) |
                              (self.opcode << 3) |
                              (self.response as u8) << 7) as u8 ]));

        try!(writer.write(&[ ((self.rescode) |
                              ((self.checking_disabled as u8) << 4) |
                              ((self.authed_data as u8) << 5) |
                              ((self.z as u8) << 6) |
                              (self.recursion_available as u8) << 7) as u8 ]));

        try!(writer.write(&[ (self.questions >> 8) as u8,
                             (self.questions & 0xFF) as u8 ]));
        try!(writer.write(&[ (self.answers >> 8) as u8,
                             (self.answers & 0xFF) as u8 ]));
        try!(writer.write(&[ (self.authorative_entries >> 8) as u8,
                             (self.authorative_entries & 0xFF) as u8 ]));
        try!(writer.write(&[ (self.resource_entries >> 8) as u8,
                             (self.resource_entries & 0xFF) as u8 ]));

        Ok(())
    }

    fn read(&mut self, res: &[u8]) -> Result<usize> {
        self.id = ((res[1] as u16) & 0xFF) | ((res[0] as u16) << 8);

        self.recursion_desired = (res[2] & (1 << 0)) > 0;
        self.truncated_message = (res[2] & (1 << 1)) > 0;
        self.authorative_answer = (res[2] & (1 << 2)) > 0;
        self.opcode = (res[2] >> 3) & 0x0F;
        self.response = (res[2] & (1 << 7)) > 0;

        self.rescode = res[3] & 0x0F;
        self.checking_disabled = (res[3] & (1 << 4)) > 0;
        self.authed_data = (res[3] & (1 << 5)) > 0;
        self.z = (res[3] & (1 << 6)) > 0;
        self.recursion_available = (res[3] & (1 << 7)) > 0;

        self.questions = ((res[5] as u16) & 0xFF) | ((res[4] as u16) << 8);
        self.answers = ((res[7] as u16) & 0xFF) | ((res[6] as u16) << 8);
        self.authorative_entries = ((res[9] as u16) & 0xFF) | ((res[8] as u16) << 8);
        self.resource_entries = ((res[11] as u16) & 0xFF) | ((res[10] as u16) << 8);

        // Return the constant header size
        Ok(12)
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "DnsHeader:\n"));
        try!(write!(f, "\tid: {0}\n", self.id));

        try!(write!(f, "\trecursion_desired: {0}\n", self.recursion_desired));
        try!(write!(f, "\ttruncated_message: {0}\n", self.truncated_message));
        try!(write!(f, "\tauthorative_answer: {0}\n", self.authorative_answer));
        try!(write!(f, "\topcode: {0}\n", self.opcode));
        try!(write!(f, "\tresponse: {0}\n", self.response));

        try!(write!(f, "\trescode: {0}\n", self.rescode));
        try!(write!(f, "\tchecking_disabled: {0}\n", self.checking_disabled));
        try!(write!(f, "\tauthed_data: {0}\n", self.authed_data));
        try!(write!(f, "\tz: {0}\n", self.z));
        try!(write!(f, "\trecursion_available: {0}\n", self.recursion_available));

        try!(write!(f, "\tquestions: {0}\n", self.questions));
        try!(write!(f, "\tanswers: {0}\n", self.answers));
        try!(write!(f, "\tauthorative_entries: {0}\n", self.authorative_entries));
        try!(write!(f, "\tresource_entries: {0}\n", self.resource_entries));

        Ok(())
    }
}

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    qtype: QueryType
}

impl DnsQuestion {
    fn new(name: &String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name: name.to_string(),
                      qtype: qtype }
    }

    fn write<T : Write>(&self, writer: &mut BufWriter<T>) -> Result<()> {

        for realstr in self.name.split(".").map(|x| x.to_string()) {
            try!(writer.write(&[ realstr.len() as u8 ]));
            try!(writer.write(realstr.as_bytes()));
        }
        try!(writer.write(&[ 0 ]));

        let typenum = querytype_number(&self.qtype);
        try!(writer.write(&[ (typenum >> 8) as u8,
                             (typenum & 0xFF) as u8 ]));
        try!(writer.write(&[ 0, 1 ]));

        Ok(())
    }
}

impl fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "DnsQuestion:\n"));
        try!(write!(f, "\tname: {0}\n", self.name));
        try!(write!(f, "\trecord type: {:?}\n", self.qtype));

        Ok(())
    }
}

struct QueryResult {
    domain: String,
    answers: Vec<ResourceRecord>,
    authorities: Vec<ResourceRecord>,
    resources: Vec<ResourceRecord>
}

struct DnsResolver<'a> {
    server: &'a str,
    buf: [u8; 512],
    pos: usize
}

impl<'a> DnsResolver<'a> {
    fn new(server: &'a str) -> DnsResolver {
        DnsResolver {
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
            else {
                self.pos += data_len as usize;

                result.push(ResourceRecord::UNKNOWN(domain, data_len, ttl));
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

    fn send_query(&mut self, qname: &String) -> Result<QueryResult> {

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

fn main() {
    if let Some(arg1) = env::args().nth(1) {
        let mut resolver = DnsResolver::new("192.168.1.1");
        if let Ok(result) = resolver.send_query(&arg1) {
            println!("query domain: {0}", result.domain);

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
    }
    else {
        println!("usage: ./resolve <domain>");
    }
}
