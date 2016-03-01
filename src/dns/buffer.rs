use std::io::{Result, Read};
use std::io::{Error, ErrorKind};

pub trait PacketBuffer {
    fn read(&mut self) -> Result<u8>;
    fn get(&mut self, pos: usize) -> Result<u8>;
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;
    fn write(&mut self, val: u8) -> Result<()>;
    fn pos(&self) -> usize;
    fn seek(&mut self, pos: usize) -> Result<()>;
    fn step(&mut self, steps: usize) -> Result<()>;

    fn write_u8(&mut self, val: u8) -> Result<()> {
        try!(self.write(val));

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        try!(self.write((val >> 8) as u8));
        try!(self.write((val & 0xFF) as u8));

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        try!(self.write(((val >> 24) & 0xFF) as u8));
        try!(self.write(((val >> 16) & 0xFF) as u8));
        try!(self.write(((val >> 8) & 0xFF) as u8));
        try!(self.write(((val >> 0) & 0xFF) as u8));

        Ok(())
    }

    fn qname_len(&self, qname: &String) -> usize {
        qname.split(".").map(|x| x.len() + 1).fold(1, |x, y| x+y)
    }

    fn write_qname(&mut self, qname: &String) -> Result<()> {

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

    fn read_u16(&mut self) -> Result<u16>
    {
        let res = ((try!(self.read()) as u16) << 8) |
                  (try!(self.read()) as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32>
    {
        let res = ((try!(self.read()) as u32) << 24) |
                  ((try!(self.read()) as u32) << 16) |
                  ((try!(self.read()) as u32) << 8) |
                  ((try!(self.read()) as u32) << 0);

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()>
    {
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delim = "";
        loop {
            let len = try!(self.get(pos));

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) > 0 {

                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    try!(self.seek(pos+2));
                }

                let b2 = try!(self.get(pos+1)) as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);
            outstr.push_str(&String::from_utf8_lossy(try!(self.get_range(pos, len as usize))));
            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            try!(self.seek(pos));
        }

        Ok(())
    }

}

pub struct VectorPacketBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize
}

impl VectorPacketBuffer {
    pub fn new() -> VectorPacketBuffer {
        VectorPacketBuffer {
            buffer: Vec::new(),
            pos: 0
        }
    }
}

impl PacketBuffer for VectorPacketBuffer {
    fn read(&mut self) -> Result<u8> {
        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        Ok(&self.buffer[start..start+len as usize])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        self.buffer.push(val);
        self.pos += 1;

        Ok(())
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }
}

pub struct StreamPacketBuffer<'a, T> where T: Read + 'a {
    pub stream: &'a mut T,
    pub buffer: Vec<u8>,
    pub pos: usize
}

impl<'a, T> StreamPacketBuffer<'a, T> where T: Read + 'a {
    pub fn new(stream: &'a mut T) -> StreamPacketBuffer<T> {
        StreamPacketBuffer {
            stream: stream,
            buffer: Vec::new(),
            pos: 0
        }
    }
}

impl<'a, T> PacketBuffer for StreamPacketBuffer<'a, T> where T: Read + 'a {
    fn read(&mut self) -> Result<u8> {
        while self.pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            try!(self.stream.read(&mut local_buffer));
            self.buffer.push(local_buffer[0]);
        }

        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        while pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            try!(self.stream.read(&mut local_buffer));
            self.buffer.push(local_buffer[0]);
        }

        Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        while start+len >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            try!(self.stream.read(&mut local_buffer));
            self.buffer.push(local_buffer[0]);
        }

        Ok(&self.buffer[start..start+len as usize])
    }

    fn write(&mut self, _: u8) -> Result<()> {
        Ok(())
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }
}

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0
        }
    }
}

impl PacketBuffer for BytePacketBuffer {
    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        Ok(&self.buf[start..start+len as usize])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::InvalidInput, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;

        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;

        Ok(())
    }
}

