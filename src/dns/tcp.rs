use std::io::{Result, Read, Write};
use std::net::{TcpListener, TcpStream, Shutdown};
use std::thread::spawn;
use std::sync::Arc;

use dns::server::{DnsServer, build_response};
use dns::protocol::DnsPacket;
use dns::context::ServerContext;

use dns::buffer::{PacketBuffer, StreamPacketBuffer, VectorPacketBuffer};

pub struct DnsTcpServer {
    context: Arc<ServerContext>
}

impl DnsTcpServer {
    pub fn new(context: Arc<ServerContext>) -> DnsTcpServer {
        DnsTcpServer {
            context: context
        }
    }

    pub fn handle_request(mut stream: TcpStream,
                          context: Arc<ServerContext>) -> Result<()> {
        let request = {
            let mut len_buffer = [0; 2];
            try!(stream.read(&mut len_buffer));
            let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
            try!(DnsPacket::from_buffer(&mut stream_buffer))
        };

        let mut res_buffer = VectorPacketBuffer::new();

        let mut resolver = context.create_resolver(context.clone());
        try!(build_response(context,
                            &request,
                            &mut resolver,
                            &mut res_buffer,
                            0xFFFF));

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

impl DnsServer for DnsTcpServer {
    fn run_server(self) -> bool {
        let socket_attempt = TcpListener::bind(("0.0.0.0", self.context.listen_port));
        if !socket_attempt.is_ok() {
            return false;
        }

        spawn(move || {
            let socket = socket_attempt.unwrap();
            for wrap_stream in socket.incoming() {
                let stream = match wrap_stream {
                    Ok(stream) => stream,
                    Err(err) => {
                        println!("Failed to accept TCP connection: {:?}", err);
                        continue;
                    }
                };

                let context = self.context.clone();
                spawn(move || {
                    match DnsTcpServer::handle_request(stream,
                                                       context) {
                        Ok(_) => {},
                        Err(err) => {
                            println!("TCP request failed: {:?}", err);
                        }
                    }
                });
            }
        });

        true
    }
}
