use std::fmt;
use std::net::{Ipv4Addr,Ipv6Addr};
use std::io::{Result, Read};
//use std::io::{Error, ErrorKind};
use rand::random;

use dns::buffer::PacketBuffer;

#[derive(PartialEq,Debug,Clone)]
pub enum QueryType {
    UNKNOWN = 0,
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33
}

impl QueryType {
    pub fn from_num(num: u16) -> QueryType {
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
    }
}

#[derive(Debug,Clone,PartialEq,Eq,Hash,PartialOrd,Ord)]
#[allow(dead_code)]
pub enum ResourceRecord {
    UNKNOWN(String, u16, u16, u32), // 0
    A(String, Ipv4Addr, u32), // 1
    NS(String, String, u32), // 2
    CNAME(String, String, u32), // 5
    SOA(String, String, String, u32, u32, u32, u32, u32, u32), // 6
    PTR, // 12
    MX(String, u16, String, u32), // 15
    TXT, // 16
    AAAA(String, Ipv6Addr, u32), // 28
    SRV(String, u16, u16, u16, String, u32) // 33
}

impl ResourceRecord {
    pub fn read<T: PacketBuffer>(buffer: &mut T) -> Result<ResourceRecord> {
        let mut domain = String::new();
        let _ = try!(buffer.read_qname(&mut domain));

        let qtype_num = try!(buffer.read_u16());
        let qtype = QueryType::from_num(qtype_num);
        let _ = try!(buffer.read_u16());
        let ttl = try!(buffer.read_u32());
        let data_len = try!(buffer.read_u16());

        match qtype {
            QueryType::A  => {
                let raw_addr = try!(buffer.read_u32());
                let addr = Ipv4Addr::new(((raw_addr >> 24) & 0xFF) as u8,
                                         ((raw_addr >> 16) & 0xFF) as u8,
                                         ((raw_addr >> 8) & 0xFF) as u8,
                                         ((raw_addr >> 0) & 0xFF) as u8);

                return Ok(ResourceRecord::A(domain, addr, ttl));
            },
            QueryType::AAAA => {
                let raw_addr1 = try!(buffer.read_u32());
                let raw_addr2 = try!(buffer.read_u32());
                let raw_addr3 = try!(buffer.read_u32());
                let raw_addr4 = try!(buffer.read_u32());
                let addr = Ipv6Addr::new(((raw_addr1 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr1 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr2 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr2 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr3 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr3 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr4 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr4 >> 0) & 0xFFFF) as u16);

                return Ok(ResourceRecord::AAAA(domain, addr, ttl));
            },
            QueryType::NS => {
                let mut ns = String::new();
                try!(buffer.read_qname(&mut ns));

                return Ok(ResourceRecord::NS(domain, ns, ttl));
            },
            QueryType::CNAME => {
                let mut cname = String::new();
                try!(buffer.read_qname(&mut cname));

                return Ok(ResourceRecord::CNAME(domain, cname, ttl));
            },
            QueryType::SRV => {
                let priority = try!(buffer.read_u16());
                let weight = try!(buffer.read_u16());
                let port = try!(buffer.read_u16());

                let mut srv = String::new();
                try!(buffer.read_qname(&mut srv));

                return Ok(ResourceRecord::SRV(domain,
                                           priority,
                                           weight,
                                           port,
                                           srv,
                                           ttl));
            },
            QueryType::MX => {
                let priority = try!(buffer.read_u16());
                let mut mx = String::new();
                try!(buffer.read_qname(&mut mx));

                return Ok(ResourceRecord::MX(domain, priority, mx, ttl));
            },
            QueryType::SOA => {
                let mut mname = String::new();
                try!(buffer.read_qname(&mut mname));

                let mut rname = String::new();
                try!(buffer.read_qname(&mut rname));

                let serial = try!(buffer.read_u32());
                let refresh = try!(buffer.read_u32());
                let retry = try!(buffer.read_u32());
                let expire = try!(buffer.read_u32());
                let minimum = try!(buffer.read_u32());

                return Ok(ResourceRecord::SOA(domain,
                                              mname,
                                              rname,
                                              serial,
                                              refresh,
                                              retry,
                                              expire,
                                              minimum,
                                              ttl));
            },
            _ => {
                try!(buffer.step(data_len as usize));

                return Ok(ResourceRecord::UNKNOWN(domain,
                                                  qtype as u16,
                                                  data_len,
                                                  ttl));
            }
        }
    }

    pub fn write<T: PacketBuffer>(&self,
                                  buffer: &mut T) -> Result<()> {

        match *self {
            ResourceRecord::A(ref host, ref addr, ttl) => {
                try!(buffer.write_qname(host));
                try!(buffer.write_u16(QueryType::A as u16));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(4));

                let octets = addr.octets();
                try!(buffer.write_u8(octets[0]));
                try!(buffer.write_u8(octets[1]));
                try!(buffer.write_u8(octets[2]));
                try!(buffer.write_u8(octets[3]));
            },
            ResourceRecord::AAAA(ref host, ref addr, ttl) => {
                try!(buffer.write_qname(host));
                try!(buffer.write_u16(QueryType::AAAA as u16));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(16));

                for octet in addr.segments().iter() {
                    try!(buffer.write_u16(*octet));
                }
            },
            ResourceRecord::NS(ref domain, ref host, ttl) => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::NS as u16));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(host.len() as u16 + 2));

                try!(buffer.write_qname(host));
            },
            ResourceRecord::CNAME(ref domain, ref addr, ttl) => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::CNAME as u16));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(addr.len() as u16 + 2));

                try!(buffer.write_qname(addr));
            },
            ResourceRecord::SRV(ref domain, priority, weight, port, ref srv, ttl) => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::SRV as u16));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(srv.len() as u16 + 8));

                try!(buffer.write_u16(priority));
                try!(buffer.write_u16(weight));
                try!(buffer.write_u16(port));
                try!(buffer.write_qname(srv));
            },
            ResourceRecord::MX(ref domain, priority, ref mx, ttl) => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::MX as u16));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(mx.len() as u16 + 4));

                try!(buffer.write_u16(priority));
                try!(buffer.write_qname(mx));
            },
            ResourceRecord::SOA(ref domain,
                                ref mname,
                                ref rname,
                                serial,
                                refresh,
                                retry,
                                expire,
                                minimum,
                                ttl) => {

                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::SOA as u16));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(mname.len() as u16 + 2 +
                                      rname.len() as u16 + 2 +
                                      5*4));

                try!(buffer.write_qname(mname));
                try!(buffer.write_qname(rname));
                try!(buffer.write_u32(serial));
                try!(buffer.write_u32(refresh));
                try!(buffer.write_u32(retry));
                try!(buffer.write_u32(expire));
                try!(buffer.write_u32(minimum));
            },
            _ => {
            }
        }

        Ok(())
    }

    pub fn binary_len<T: PacketBuffer>(&self,
                                       buffer: &T) -> usize {

        match *self {
            ResourceRecord::A(ref host, _, _) => {
                buffer.qname_len(host) + 2 + 2 + 4 + 2 + 4
            },
            //ResourceRecord::AAAA(ref host, ref addr, ttl) => {
            //},
            //ResourceRecord::NS(ref domain, ref addr, ttl) => {
            //},
            ResourceRecord::CNAME(ref domain, ref addr, _) => {
                buffer.qname_len(domain) + 2 + 2 + 4 + 2 + buffer.qname_len(addr)
            },
            //ResourceRecord::SRV(ref domain, priority, weight, port, ref srv, ttl) => {
            //},
            //ResourceRecord::MX(ref domain, priority, ref mx, ttl) => {
            //},
            _ => 0
        }
    }

    pub fn get_querytype(&self) -> QueryType {
        match *self {
            ResourceRecord::A(_, _, _) => QueryType::A,
            ResourceRecord::AAAA(_, _, _) => QueryType::AAAA,
            ResourceRecord::NS(_, _, _) => QueryType::NS,
            ResourceRecord::CNAME(_, _, _) => QueryType::CNAME,
            ResourceRecord::SRV(_, _, _, _, _, _) => QueryType::SRV,
            ResourceRecord::MX(_, _, _, _) => QueryType::MX,
            ResourceRecord::UNKNOWN(_, _, _, _) => QueryType::UNKNOWN,
            ResourceRecord::SOA(_, _, _, _, _, _, _, _, _) => QueryType::SOA,
            ResourceRecord::PTR => QueryType::PTR,
            ResourceRecord::TXT => QueryType::TXT
        }
    }

    pub fn get_domain(&self) -> Option<String> {
        match *self {
            ResourceRecord::A(ref domain, _, _) => Some(domain.clone()),
            ResourceRecord::AAAA(ref domain, _, _) => Some(domain.clone()),
            ResourceRecord::NS(ref domain, _, _) => Some(domain.clone()),
            ResourceRecord::CNAME(ref domain, _, _) => Some(domain.clone()),
            ResourceRecord::SRV(ref domain, _, _, _, _, _) => Some(domain.clone()),
            ResourceRecord::MX(ref domain, _, _, _) => Some(domain.clone()),
            ResourceRecord::UNKNOWN(ref domain, _, _, _) => Some(domain.clone()),
            ResourceRecord::SOA(_, _, _, _, _, _, _, _, _) => None,
            ResourceRecord::PTR => None,
            ResourceRecord::TXT => None
        }
    }

    pub fn get_ttl(&self) -> u32 {
        match *self {
            ResourceRecord::A(_, _, ttl) => ttl,
            ResourceRecord::AAAA(_, _, ttl) => ttl,
            ResourceRecord::NS(_, _, ttl) => ttl,
            ResourceRecord::CNAME(_, _, ttl) => ttl,
            ResourceRecord::SRV(_, _, _, _, _, ttl) => ttl,
            ResourceRecord::MX(_, _, _, ttl) => ttl,
            ResourceRecord::UNKNOWN(_, _, _, ttl) => ttl,
            ResourceRecord::SOA(_, _, _, _, _, _, _, _, _) => 0,
            ResourceRecord::PTR => 0,
            ResourceRecord::TXT => 0
        }
    }
}

#[derive(Clone,Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool, // 1 bit
    pub truncated_message: bool, // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8, // 4 bits
    pub response: bool, // 1 bit

    pub rescode: u8, // 4 bits
    pub checking_disabled: bool, // 1 bit
    pub authed_data: bool, // 1 bit
    pub z: bool, // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16, // 16 bits
    pub answers: u16, // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16 // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader { id: 0,

                    recursion_desired: false,
                    truncated_message: false,
                    authoritative_answer: false,
                    opcode: 0,
                    response: false,

                    rescode: 0,
                    checking_disabled: false,
                    authed_data: false,
                    z: false,
                    recursion_available: false,

                    questions: 0,
                    answers: 0,
                    authoritative_entries: 0,
                    resource_entries: 0 }
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        try!(buffer.write_u16(self.id));

        try!(buffer.write_u8( ((self.recursion_desired as u8)) |
                              ((self.truncated_message as u8) << 1) |
                              ((self.authoritative_answer as u8) << 2) |
                              (self.opcode << 3) |
                              ((self.response as u8) << 7) as u8) );

        try!(buffer.write_u8( (self.rescode) |
                              ((self.checking_disabled as u8) << 4) |
                              ((self.authed_data as u8) << 5) |
                              ((self.z as u8) << 6) |
                              ((self.recursion_available as u8) << 7) ));

        try!(buffer.write_u16(self.questions));
        try!(buffer.write_u16(self.answers));
        try!(buffer.write_u16(self.authoritative_entries));
        try!(buffer.write_u16(self.resource_entries));

        Ok(())
    }

    pub fn binary_len(&self) -> usize {
        12
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        self.id = try!(buffer.read_u16());

        let flags = try!(buffer.read_u16());
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = b & 0x0F;
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = try!(buffer.read_u16());
        self.answers = try!(buffer.read_u16());
        self.authoritative_entries = try!(buffer.read_u16());
        self.resource_entries = try!(buffer.read_u16());

        // Return the constant header size
        Ok(())
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "DnsHeader:\n"));
        try!(write!(f, "\tid: {0}\n", self.id));

        try!(write!(f, "\trecursion_desired: {0}\n", self.recursion_desired));
        try!(write!(f, "\ttruncated_message: {0}\n", self.truncated_message));
        try!(write!(f, "\tauthoritative_answer: {0}\n", self.authoritative_answer));
        try!(write!(f, "\topcode: {0}\n", self.opcode));
        try!(write!(f, "\tresponse: {0}\n", self.response));

        try!(write!(f, "\trescode: {0}\n", self.rescode));
        try!(write!(f, "\tchecking_disabled: {0}\n", self.checking_disabled));
        try!(write!(f, "\tauthed_data: {0}\n", self.authed_data));
        try!(write!(f, "\tz: {0}\n", self.z));
        try!(write!(f, "\trecursion_available: {0}\n", self.recursion_available));

        try!(write!(f, "\tquestions: {0}\n", self.questions));
        try!(write!(f, "\tanswers: {0}\n", self.answers));
        try!(write!(f, "\tauthoritative_entries: {0}\n", self.authoritative_entries));
        try!(write!(f, "\tresource_entries: {0}\n", self.resource_entries));

        Ok(())
    }
}

#[derive(Debug,Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
}

impl DnsQuestion {
    pub fn new(name: &String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name.to_string(),
            qtype: qtype
        }
    }

    pub fn binary_len<T: PacketBuffer>(&self, buffer: &T) -> usize {
        buffer.qname_len(&self.name) + 4
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {

        try!(buffer.write_qname(&self.name));

        let typenum = self.qtype.clone() as u16;
        try!(buffer.write_u16(typenum));
        try!(buffer.write_u16(1));

        Ok(())
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        let _ = buffer.read_qname(&mut self.name);
        self.qtype = QueryType::from_num(try!(buffer.read_u16())); // qtype
        let _ = buffer.read_u16(); // class

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

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub resources: Vec<ResourceRecord>
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        }
    }

    pub fn from_buffer<T: PacketBuffer>(buffer: &mut T) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        try!(result.header.read(buffer));

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(&"".to_string(),
                                                QueryType::UNKNOWN);
            try!(question.read(buffer));
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = try!(ResourceRecord::read(buffer));
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = try!(ResourceRecord::read(buffer));
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = try!(ResourceRecord::read(buffer));
            result.resources.push(rec);
        }

        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        //println!("query domain: {0}", self.domain);

        println!("answers:");
        for x in &self.answers {
            println!("\t{:?}", x);
        }

        println!("authorities:");
        for x in &self.authorities {
            println!("\t{:?}", x);
        }

        println!("resources:");
        for x in &self.resources {
            println!("\t{:?}", x);
        }
    }

    pub fn get_random_a(&self) -> Option<String> {
        if self.answers.len() > 0 {
            let idx = random::<usize>() % self.answers.len();
            let a_record = &self.answers[idx];
            if let &ResourceRecord::A(_, ref ip, _) = a_record {
                return Some(ip.to_string());
            }
        }

        None
    }

    pub fn get_unresolved_cnames(&self) -> Vec<ResourceRecord> {

        let mut unresolved = Vec::new();
        for answer in &self.answers {
            let mut matched = false;
            if let ResourceRecord::CNAME(_, ref host, _) = *answer {
                for answer2 in &self.answers {
                    if let ResourceRecord::A(ref host2, _, _) = *answer2 {
                        if host2 == host {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if !matched {
                unresolved.push(answer.clone());
            }
        }

        unresolved
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {

        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let ResourceRecord::NS(ref suffix, ref host, _) = *auth {
                if !qname.to_lowercase().ends_with(&suffix.to_lowercase()) {
                    continue;
                }

                for rsrc in &self.resources {
                    if let ResourceRecord::A(ref host2, ref ip, ref ttl) = *rsrc {
                        if host2 != host {
                            continue;
                        }

                        let rec = ResourceRecord::A(host.clone(), ip.clone(), *ttl);
                        new_authorities.push(rec);
                    }
                }
            }
        }

        if new_authorities.len() > 0 {
            let idx = random::<usize>() % new_authorities.len();
            if let ResourceRecord::A(_, ip, _) = new_authorities[idx] {
                return Some(ip.to_string());
            }
        }

        None
    }

    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {

        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let ResourceRecord::NS(ref suffix, ref host, _) = *auth {
                if !qname.to_lowercase().ends_with(&suffix.to_lowercase()) {
                    continue;
                }

                new_authorities.push(host);
            }
        }

        if new_authorities.len() > 0 {
            let idx = random::<usize>() % new_authorities.len();
            return Some(new_authorities[idx].clone());
        }

        None
    }

    pub fn write<T: PacketBuffer>(&mut self,
                                  buffer: &mut T,
                                  max_size: usize) -> Result<()>
    {
        let mut size = self.header.binary_len();
        for ref question in &self.questions {
            size += question.binary_len(buffer);
        }

        let mut answer_count = self.answers.len();

        for (i, answer) in self.answers.iter().enumerate() {
            size += answer.binary_len(buffer);
            if size > max_size {
                answer_count = i;
                break;
            }
        }

        self.header.questions = self.questions.len() as u16;
        self.header.answers = answer_count as u16;
        self.header.truncated_message = answer_count < self.answers.len();

        try!(self.header.write(buffer));

        for question in &self.questions {
            try!(question.write(buffer));
        }

        for answer in self.answers.iter().take(answer_count) {
            try!(answer.write(buffer));
        }

        Ok(())
    }

    /*pub fn has_soa(&self, qname: &str) -> bool {

        for auth in &self.authorities {
            if let ResourceRecord::SOA(ref domain, _, _, _, _, _, _, _, _) = *auth {
                if !qname.to_lowercase().ends_with(&domain.to_lowercase()) {
                    continue;
                }

                return true;
            }
        }

        false
    }*/
}

#[test]
fn test_dns_packet()
{
}
