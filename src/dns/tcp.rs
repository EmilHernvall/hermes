use std::io::{Result, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::spawn;
use std::sync::Arc;

use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
use dns::server::{DnsServer, build_response};
use dns::udp::DnsUdpClient;
use dns::protocol::DnsPacket;

use dns::buffer::{PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};

pub struct DnsTcpServer<'a> {
    client: Arc<DnsUdpClient>,
    cache: &'a SynchronizedCache,
    port: u16
}

impl<'a> DnsTcpServer<'a> {
    pub fn new(client: Arc<DnsUdpClient>,
               cache: &'a SynchronizedCache,
               port: u16) -> DnsTcpServer<'a> {
        DnsTcpServer {
            client: client,
            cache: cache,
            port: port
        }
    }

    pub fn handle_request(mut stream: &TcpStream,
                          client: &DnsUdpClient,
                          cache: &SynchronizedCache) -> Result<()> {
        let request = {
            let mut len_buffer = [0; 2];
            try!(stream.read(&mut len_buffer));
            let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
            let mut req_packet = DnsPacket::new(&mut stream_buffer);
            try!(req_packet.read())
        };

        let mut res_buffer = VectorPacketBuffer::new();

        let mut resolver = DnsResolver::new(client, cache);
        try!(build_response(&request, &mut resolver, &mut res_buffer, 0xFFFF));

        let len = res_buffer.pos();

        let mut len_buffer = [0; 2];
        len_buffer[0] = (len >> 8) as u8;
        len_buffer[1] = (len & 0xFF) as u8;

        try!(stream.write(&len_buffer));
        try!(stream.write(try!(res_buffer.get_range(0, len))));

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
            if let Ok(stream) = wrap_stream {
                let client = self.client.clone();
                let cache = self.cache.clone();
                spawn(move || {
                    match DnsTcpServer::handle_request(&stream,
                                                       &client,
                                                       &cache) {
                        Ok(_) => {},
                        Err(err) => {
                            println!("TCP request failed: {:?}", err);
                        }
                    }
                });
            }
        }

        true
    }
}
