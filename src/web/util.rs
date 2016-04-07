use std::collections::BTreeMap;
use std::io::{Result,Read};
use std::fmt::Write;

use rustc_serialize::json::{self,ToJson,Json,DecodeResult,DecoderError};
use rustc_serialize::Decodable;
use tiny_http::Request;

use dns::protocol::ResourceRecord;

pub trait FormDataDecodable<T> {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<T>;
}

fn hex_to_num(c: char) -> u8 {
    match c {
        '0'...'9' => (c as u8) - ('0' as u8),
        'a'...'f' => (c as u8) - ('a' as u8) + 0xA,
        'A'...'F' => (c as u8) - ('A' as u8) + 0xA,
        _ => 0
    }
}

pub fn url_decode(instr: &str) -> String {
    let src_buffer = instr.as_bytes();

    let mut pos = 0;
    let len = instr.len();
    let mut buffer = String::new();
    while pos < len {
        let cur = src_buffer[pos] as char;
        if cur == '%' {
            let a = hex_to_num(src_buffer[pos+1] as char);
            let b = hex_to_num(src_buffer[pos+2] as char);
            let new_char = ((a << 4) | b) as char;
            buffer.push(new_char);
            pos += 2;
        } else {
            buffer.push(cur);
        }

        pos += 1;
    }

    buffer
}

pub fn parse_formdata<R: Read>(reader: &mut R) -> Result<Vec<(String, String)>> {

    let mut data = String::new();
    try!(reader.read_to_string(&mut data));

    let res = data.split("&").filter_map(|x| {
        let s = x.split("=").collect::<Vec<&str>>();
        match s.len() {
            2 => Some((url_decode(s[0]), url_decode(s[1]))),
            _ => None
        }
    }).collect::<Vec<(String, String)>>();

    Ok(res)
}

pub fn rr_to_json(id: u32, rr: &ResourceRecord) -> Json {
    let mut d = BTreeMap::new();

    let mut qtype = String::new();
    let _ = write!(&mut qtype, "{:?}", rr.get_querytype());
    d.insert("id".to_string(), id.to_json());
    d.insert("type".to_string(), qtype.to_json());

    match *rr {
        ResourceRecord::A { ref domain, ref addr, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), addr.to_string().to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::AAAA { ref domain, ref addr, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), addr.to_string().to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::NS { ref domain, ref host, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::CNAME { ref domain, ref host, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::SRV { ref domain, priority, weight, port, ref host, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), host.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
            d.insert("priority".to_string(), priority.to_json());
            d.insert("weight".to_string(), weight.to_json());
            d.insert("port".to_string(), port.to_json());
        },
        ResourceRecord::MX { ref domain, priority, ref host, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("host".to_string(), (priority.to_string() + " " + host).to_json());
            d.insert("ttl".to_string(), ttl.to_json());
        },
        ResourceRecord::UNKNOWN { ref domain, qtype, data_len, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
            d.insert("type".to_string(), qtype.to_json());
            d.insert("len".to_string(), data_len.to_json());
        },
        ResourceRecord::SOA { .. } => {
        },
        ResourceRecord::TXT { ref domain, ref data, ttl } => {
            d.insert("domain".to_string(), domain.to_json());
            d.insert("ttl".to_string(), ttl.to_json());
            d.insert("txt".to_string(), data.to_json());
        }
        ResourceRecord::OPT { .. } => {
        }
    }

    Json::Object(d)
}

pub fn decode_json<T: Decodable>(request: &mut Request) -> DecodeResult<T>
{
    let json = match Json::from_reader(request.as_reader()) {
        Ok(x) => x,
        Err(e) => return Err(DecoderError::ParseError(e))
    };

    let mut decoder = json::Decoder::new(json);
    Decodable::decode(&mut decoder)
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::io::Cursor;

    #[test]
    fn test_url_decode() {
        assert_eq!("@foo barA", url_decode("%40foo%20bar%41"));
    }

    #[test]
    fn test_parse_formdata() {
        let data = "foo=bar&baz=quux";
        let result = parse_formdata(&mut Cursor::new(data.to_string())).unwrap();

        assert_eq!(2, result.len());
        assert_eq!(("foo".to_string(),"bar".to_string()), result[0]);
        assert_eq!(("baz".to_string(),"quux".to_string()), result[1]);

        let data2 = "foo=bar";
        let result2 = parse_formdata(&mut Cursor::new(data2.to_string())).unwrap();

        assert_eq!(1, result2.len());
        assert_eq!(("foo".to_string(),"bar".to_string()), result2[0]);

        let data3 = "foo=bar=baz";
        let result3 = parse_formdata(&mut Cursor::new(data3.to_string())).unwrap();

        assert_eq!(0, result3.len());

        let data4 = "foo=bar&&";
        let result4 = parse_formdata(&mut Cursor::new(data4.to_string())).unwrap();

        assert_eq!(1, result4.len());
        assert_eq!(("foo".to_string(),"bar".to_string()), result4[0]);
    }
}
