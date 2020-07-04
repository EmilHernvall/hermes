use std::io::{Read, Result};

pub trait FormDataDecodable<T> {
    fn from_formdata(fields: Vec<(String, String)>) -> Result<T>;
}

fn hex_to_num(c: char) -> u8 {
    match c {
        '0'..='9' => (c as u8) - (b'0' as u8),
        'a'..='f' => (c as u8) - (b'a' as u8) + 0xA,
        'A'..='F' => (c as u8) - (b'A' as u8) + 0xA,
        _ => 0,
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
            let a = hex_to_num(src_buffer[pos + 1] as char);
            let b = hex_to_num(src_buffer[pos + 2] as char);
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
    reader.read_to_string(&mut data)?;

    let res = data
        .split('&')
        .filter_map(|x| {
            let s = x.split('=').collect::<Vec<&str>>();
            match s.len() {
                2 => Some((url_decode(s[0]), url_decode(s[1]))),
                _ => None,
            }
        })
        .collect::<Vec<(String, String)>>();

    Ok(res)
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
        assert_eq!(("foo".to_string(), "bar".to_string()), result[0]);
        assert_eq!(("baz".to_string(), "quux".to_string()), result[1]);

        let data2 = "foo=bar";
        let result2 = parse_formdata(&mut Cursor::new(data2.to_string())).unwrap();

        assert_eq!(1, result2.len());
        assert_eq!(("foo".to_string(), "bar".to_string()), result2[0]);

        let data3 = "foo=bar=baz";
        let result3 = parse_formdata(&mut Cursor::new(data3.to_string())).unwrap();

        assert_eq!(0, result3.len());

        let data4 = "foo=bar&&";
        let result4 = parse_formdata(&mut Cursor::new(data4.to_string())).unwrap();

        assert_eq!(1, result4.len());
        assert_eq!(("foo".to_string(), "bar".to_string()), result4[0]);
    }
}
