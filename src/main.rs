use std::io::BufWriter;
use std::io::Write;
use std::io::Result;
//use std::io::stdout;
use std::net::UdpSocket;
use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX
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
        DnsHeader { id: 777,

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

    fn to_binary<T : Write>(&self, writer: &mut BufWriter<T>) -> Result<()> {
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

    fn set_from_response(&mut self, res: &[u8]) -> Result<()> {
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

        Ok(())
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
    qtype: RecordType
}

impl DnsQuestion {
    fn new(name: &String, qtype: RecordType) -> DnsQuestion {
        DnsQuestion { name: name.to_string(),
                      qtype: qtype }
    }

    fn to_binary<T : Write>(&self, writer: &mut BufWriter<T>) -> Result<()> {

        for realstr in self.name.split(".").map(|x| x.to_string()) {
            try!(writer.write(&[ realstr.len() as u8 ]));
            try!(writer.write(realstr.as_bytes()));
        }
        try!(writer.write(&[ 0 ]));

        try!(writer.write(&[0, match self.qtype {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
        }]));
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

fn build_query(data: &mut Vec<u8>) -> Result<()> {
    let mut writer = BufWriter::new(data);

    let head = DnsHeader::new();
    println!("{}", head);

    try!(head.to_binary(&mut writer));

    let question = DnsQuestion::new(&"en.wikipedia.org".to_string(), RecordType::A);
    println!("{}", question);

    try!(question.to_binary(&mut writer));

    Ok(())
}

fn send_query() -> Result<()> {
    let mut data = Vec::new();

    try!(build_query(&mut data));

    println!("sending data of length {0}", data.len());
    let socket = try!(UdpSocket::bind("0.0.0.0:34254"));
    try!(socket.send_to(&data, ("8.8.8.8", 53)));

    println!("receiving data");
    let mut buf = [0; 512];
    let _ = try!(socket.recv_from(&mut buf));
    println!("got data\n");

    drop(socket);

    let mut response = DnsHeader::new();
    try!(response.set_from_response(&buf));

    println!("{}", response);

    let mut pos = 12;
    let mut domain = String::new();
    let mut delim = "";
    loop {
        let len = buf[pos] as u8;
        pos += 1;

        if len == 0 {
            break;
        }

        let part = String::from_utf8_lossy(&buf[pos..pos+len as usize]);
        pos += len as usize;

        domain.push_str(delim);
        domain.push_str(&part);

        delim = ".";
    }

    println!("domain: {0}", domain);

    pos += 6;

    let qtype = ((buf[pos] as u16) << 8) | (buf[pos+1] as u16);
    println!("qtype: {0}", qtype);
    pos += 2;

    let class = ((buf[pos] as u16) << 8) | (buf[pos+1] as u16);
    println!("class: {0}", class);
    pos += 2;

    /*let ttl = ((buf[pos+3] as u32) << 0) |
              ((buf[pos+2] as u32) << 8) |
              ((buf[pos+1] as u32) << 16) |
              ((buf[pos+0] as u32) << 24);
    println!("ttl: {0}", ttl);
    pos += 4;

    let data_len = ((buf[pos] as u16) << 8) | (buf[pos+1] as u16);
    println!("data_len: {0}", data_len);
    pos += 2;*/

    Ok(())
}

fn main() {
    let _ = send_query();
}
