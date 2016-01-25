use std::fmt;
use std::net::{Ipv4Addr,Ipv6Addr};
use std::io::Result;
use std::io::{Error, ErrorKind};
use rand::random;

#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
#[allow(dead_code)]
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

#[derive(Debug,Clone,PartialEq,Eq,Hash)]
#[allow(dead_code)]
pub enum ResourceRecord {
    UNKNOWN(String, u16, u16, u32), // 0
    A(String, Ipv4Addr, u32), // 1
    NS(String, String, u32), // 2
    CNAME(String, String, u32), // 5
    SOA, // 6
    PTR, // 12
    MX(String, u16, String, u32), // 15
    TXT, // 16
    AAAA(String, Ipv6Addr, u32), // 28
    SRV(String, u16, u16, u16, String, u32) // 33
}

impl ResourceRecord {
    pub fn read(packet: &mut DnsPacket) -> Result<ResourceRecord> {
        let mut domain = String::new();
        let _ = packet.read_qname(&mut domain, false);

        let qtype = QueryType::from_num(try!(packet.read_u16()));
        let _ = try!(packet.read_u16());
        let ttl = try!(packet.read_u32());
        let data_len = try!(packet.read_u16());

        if qtype == QueryType::A {
            let raw_addr = try!(packet.read_u32());
            let addr = Ipv4Addr::new(((raw_addr >> 24) & 0xFF) as u8,
                                     ((raw_addr >> 16) & 0xFF) as u8,
                                     ((raw_addr >> 8) & 0xFF) as u8,
                                     ((raw_addr >> 0) & 0xFF) as u8);

            return Ok(ResourceRecord::A(domain, addr, ttl));
        }
        else if qtype == QueryType::AAAA {
            let raw_addr1 = try!(packet.read_u32());
            let raw_addr2 = try!(packet.read_u32());
            let raw_addr3 = try!(packet.read_u32());
            let raw_addr4 = try!(packet.read_u32());
            let addr = Ipv6Addr::new(((raw_addr1 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr1 >> 0) & 0xFFFF) as u16,
                                     ((raw_addr2 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr2 >> 0) & 0xFFFF) as u16,
                                     ((raw_addr3 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr3 >> 0) & 0xFFFF) as u16,
                                     ((raw_addr4 >> 16) & 0xFFFF) as u16,
                                     ((raw_addr4 >> 0) & 0xFFFF) as u16);

            return Ok(ResourceRecord::AAAA(domain, addr, ttl));
        }
        else if qtype == QueryType::NS {
            let mut ns = String::new();
            try!(packet.read_qname(&mut ns, true));
            packet.pos += data_len as usize;

            return Ok(ResourceRecord::NS(domain, ns, ttl));
        }
        else if qtype == QueryType::CNAME {
            let mut cname = String::new();
            try!(packet.read_qname(&mut cname, true));
            packet.pos += data_len as usize;

            return Ok(ResourceRecord::CNAME(domain, cname, ttl));
        }
        else if qtype == QueryType::SRV {
            let priority = try!(packet.read_u16());
            let weight = try!(packet.read_u16());
            let port = try!(packet.read_u16());

            let mut srv = String::new();
            let _ = packet.read_qname(&mut srv, true);
            packet.pos += data_len as usize;

            return Ok(ResourceRecord::SRV(domain,
                                       priority,
                                       weight,
                                       port,
                                       srv,
                                       ttl));
        }
        else if qtype == QueryType::MX {
            let newpos = packet.pos + data_len as usize;
            let priority = try!(packet.read_u16());
            let mut mx = String::new();
            try!(packet.read_qname(&mut mx, false));
            packet.pos = newpos;

            return Ok(ResourceRecord::MX(domain, priority, mx, ttl));
        }
        else {
            packet.pos += data_len as usize;

            return Ok(ResourceRecord::UNKNOWN(domain,
                                              qtype as u16,
                                              data_len,
                                              ttl));
        }
    }

    pub fn write(&self,
                 packet: &mut DnsPacket) -> Result<()> {

        match *self {
            ResourceRecord::A(ref host, ref addr, ttl) => {
                try!(packet.write_qname(host));
                try!(packet.write_u16(QueryType::A as u16));
                try!(packet.write_u16(1));
                try!(packet.write_u32(ttl));
                try!(packet.write_u16(4));

                let octets = addr.octets();
                try!(packet.write_u8(octets[0]));
                try!(packet.write_u8(octets[1]));
                try!(packet.write_u8(octets[2]));
                try!(packet.write_u8(octets[3]));
            },
            //ResourceRecord::AAAA(ref host, ref addr, ttl) => {
            //},
            //ResourceRecord::NS(ref domain, ref addr, ttl) => {
            //},
            ResourceRecord::CNAME(ref domain, ref addr, ttl) => {
                try!(packet.write_qname(domain));
                try!(packet.write_u16(QueryType::CNAME as u16));
                try!(packet.write_u16(1));
                try!(packet.write_u32(ttl));
                try!(packet.write_u16(addr.len() as u16 + 2));

                try!(packet.write_qname(addr));
            },
            //ResourceRecord::SRV(ref domain, priority, weight, port, ref srv, ttl) => {
            //},
            //ResourceRecord::MX(ref domain, priority, ref mx, ttl) => {
            //},
            _ => {
            }
        }

        Ok(())
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
            ResourceRecord::SOA => QueryType::SOA,
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
            ResourceRecord::SOA => None,
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
            ResourceRecord::SOA => 0,
            ResourceRecord::PTR => 0,
            ResourceRecord::TXT => 0
        }
    }
}

#[derive(Debug)]
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

    pub fn write(&self, packet: &mut DnsPacket) -> Result<()> {
        try!(packet.write_u16(self.id));

        try!(packet.write_u8( ((self.recursion_desired as u8)) |
                              ((self.truncated_message as u8) << 1) |
                              ((self.authoritative_answer as u8) << 2) |
                              (self.opcode << 3) |
                              ((self.response as u8) << 7) as u8) );

        try!(packet.write_u8( (self.rescode) |
                              ((self.checking_disabled as u8) << 4) |
                          ((self.authed_data as u8) << 5) |
                          ((self.z as u8) << 6) |
                          ((self.recursion_available as u8) << 7) ));

    try!(packet.write_u16(self.questions));
    try!(packet.write_u16(self.answers));
    try!(packet.write_u16(self.authoritative_entries));
    try!(packet.write_u16(self.resource_entries));

    Ok(())
}

pub fn read(&mut self, packet: &mut DnsPacket) -> Result<()> {
    self.id = try!(packet.read_u16());

    let flags = try!(packet.read_u16());
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

    self.questions = try!(packet.read_u16());
    self.answers = try!(packet.read_u16());
    self.authoritative_entries = try!(packet.read_u16());
    self.resource_entries = try!(packet.read_u16());

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

#[derive(Debug)]
#[derive(Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
}

impl DnsQuestion {
pub fn new(name: &String, qtype: QueryType) -> DnsQuestion {
    DnsQuestion { name: name.to_string(),
                  qtype: qtype }
}

pub fn write(&self, packet: &mut DnsPacket) -> Result<()> {
//pub fn write<T : Write>(&self, writer: &mut BufWriter<T>) -> Result<()> {

    try!(packet.write_qname(&self.name));

    let typenum = self.qtype.clone() as u16;
    try!(packet.write_u16(typenum));
    try!(packet.write_u16(1));

    Ok(())
}

pub fn read(&mut self, packet: &mut DnsPacket) -> Result<()> {
    let _ = packet.read_qname(&mut self.name, false);
    self.qtype = QueryType::from_num(try!(packet.read_u16())); // qtype
    let _ = packet.read_u16(); // class

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
pub struct QueryResult {
    pub id: u16,
    pub authoritative: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub resources: Vec<ResourceRecord>
}

impl QueryResult {
    pub fn new(id: u16, authoritative: bool) -> QueryResult {
        QueryResult {
            id: id,
            authoritative: authoritative,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        }
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

    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {

        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let ResourceRecord::NS(ref suffix, ref host, _) = *auth {
                if !qname.ends_with(suffix) {
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
                if !qname.ends_with(suffix) {
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
}

pub struct DnsPacket {
    pub buf: [u8; 512],
    pub pos: usize
}

impl DnsPacket {
pub fn new() -> DnsPacket {
        DnsPacket {
            buf: [0; 512],
            pos: 0
        }
    }

    pub fn read_u16(&mut self) -> Result<u16>
    {
        if self.pos+1 >= self.buf.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }

        let res = ((self.buf[self.pos] as u16) << 8) |
                  (self.buf[self.pos+1] as u16);
        self.pos += 2;

        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32>
    {
        if self.pos+3 >= self.buf.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }

        let res = ((self.buf[self.pos+3] as u32) << 0) |
                  ((self.buf[self.pos+2] as u32) << 8) |
                  ((self.buf[self.pos+1] as u32) << 16) |
                  ((self.buf[self.pos+0] as u32) << 24);
        self.pos += 4;

        Ok(res)
    }

    pub fn read_qname(&mut self, outstr: &mut String, nomove: bool) -> Result<()>
    {
        let mut pos = self.pos;
        let mut jumped = false;

        let mut delim = "";
        loop {
            if pos >= self.buf.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }

            let len = self.buf[pos] as u8;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we only need to update the global position by two bytes.
            if (len & 0xC0) > 0 {
                let offset = (((len as u16) ^ 0xC0) << 8) |
                             (self.buf[pos+1] as u16);
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            if len == 0 {
                break;
            }

            if pos+len as usize >= self.buf.len() {
                return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
            }

            outstr.push_str(delim);
            outstr.push_str(&String::from_utf8_lossy(&self.buf[pos..pos+len as usize]));
            delim = ".";

            pos += len as usize;
        }

        if nomove {
            return Ok(());
        }

        if jumped {
            self.pos += 2;
        } else {
            self.pos = pos;
        }

        Ok(())
    }

    pub fn read_records(&mut self,
                        count: u16,
                        result: &mut Vec<ResourceRecord>) -> Result<()> {
        for _ in 0..count {
            let rec = try!(ResourceRecord::read(self));
            result.push(rec);
        }

        Ok(())
    }

    pub fn write_u8(&mut self, val: u8) -> Result<()> {
        self.buf[self.pos] = val;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<()> {
        self.buf[self.pos] = (val >> 8) as u8;
        self.buf[self.pos+1] = (val & 0xFF) as u8;
        self.pos += 2;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<()> {
        self.buf[self.pos+0] = ((val >> 24) & 0xFF) as u8;
        self.buf[self.pos+1] = ((val >> 16) & 0xFF) as u8;
        self.buf[self.pos+2] = ((val >> 8) & 0xFF) as u8;
        self.buf[self.pos+3] = ((val >> 0) & 0xFF) as u8;
        self.pos += 4;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &String) -> Result<()> {

        for label in qname.split(".") {
            let len = label.len();
            try!(self.write_u8(len as u8));
            for b in label.as_bytes() {
                try!(self.write_u8(*b));
            }
        }

        try!(self.write_u8(0));

        Ok(())
    }

    pub fn read(&mut self) -> Result<QueryResult> {
        let mut header = DnsHeader::new();
        try!(header.read(self));

        let mut result = QueryResult::new(header.id, header.authoritative_answer);

        for _ in 0..header.questions {
            let mut question = DnsQuestion::new(&"".to_string(),
                                                QueryType::UNKNOWN);
            try!(question.read(self));
            result.questions.push(question);
        }

        try!(self.read_records(header.answers, &mut result.answers));
        try!(self.read_records(header.authoritative_entries, &mut result.authorities));
        try!(self.read_records(header.resource_entries, &mut result.resources));

        Ok(result)
    }
}
