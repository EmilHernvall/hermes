use std::io::{Result, Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::thread::spawn;
use std::sync::Arc;

use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
use dns::server::{DnsServer, build_response};
use dns::udp::DnsUdpClient;
use dns::protocol::DnsPacket;
use dns::authority::Authority;

use dns::buffer::{PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};

pub struct DnsTcpServer<'a> {
    client: Arc<DnsUdpClient>,
    authority: Arc<Authority>,
    cache: &'a SynchronizedCache,
    port: u16
}

impl<'a> DnsTcpServer<'a> {
    pub fn new(client: Arc<DnsUdpClient>,
               authority: Arc<Authority>,
               cache: &'a SynchronizedCache,
               port: u16) -> DnsTcpServer<'a> {
        DnsTcpServer {
            client: client,
            authority: authority,
            cache: cache,
            port: port
        }
    }

    pub fn handle_request(mut stream: TcpStream,
                          client: &DnsUdpClient,
                          authority: &Authority,
                          cache: &SynchronizedCache) -> Result<()> {
        let request = {
            let mut len_buffer = [0; 2];
            try!(stream.read(&mut len_buffer));
            let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
            try!(DnsPacket::from_buffer(&mut stream_buffer))
        };

        let mut res_buffer = VectorPacketBuffer::new();

        let mut resolver = DnsResolver::new(client, authority, cache);
        try!(build_response(&request, &mut resolver, &mut res_buffer, 0xFFFF));

        let len = res_buffer.pos();

        let mut len_buffer = [0; 2];
        len_buffer[0] = (len >> 8) as u8;
        len_buffer[1] = (len & 0xFF) as u8;

        try!(stream.write(&len_buffer));
        try!(stream.write(try!(res_buffer.get_range(0, len))));

        try!(stream.shutdown(Shutdown::Both));

        Ok(())
    }
}

impl<'a> DnsServer for DnsTcpServer<'a> {
    fn run(&mut self) -> bool {
        let socket_attempt = TcpListener::bind(("0.0.0.0", self.port));
        if !socket_attempt.is_ok() {
            return false;
        }

        let socket = socket_attempt.unwrap();
        for wrap_stream in socket.incoming() {
            let stream = match wrap_stream {
                Ok(stream) => stream,
                Err(err) => {
                    println!("Failed to accept TCP connection: {:?}", err);
                    continue;
                }
            };

            let client = self.client.clone();
            let authority = self.authority.clone();
            let cache = self.cache.clone();
            spawn(move || {
                match DnsTcpServer::handle_request(stream,
                                                   &client,
                                                   &authority,
                                                   &cache) {
                    Ok(_) => {},
                    Err(err) => {
                        println!("TCP request failed: {:?}", err);
                    }
                }
            });
        }

        true
    }
}
