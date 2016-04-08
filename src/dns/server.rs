//! UDP and TCP server implementations for DNS

use std::io::{Result, Write};
use std::net::{UdpSocket, TcpListener, TcpStream, Shutdown};
use std::sync::Arc;
use std::thread::spawn;

use dns::resolve::DnsResolver;
use dns::protocol::{DnsPacket, QueryType, ResourceRecord, ResultCode};
use dns::buffer::{PacketBuffer, BytePacketBuffer, VectorPacketBuffer, StreamPacketBuffer};
use dns::context::ServerContext;

macro_rules! return_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(res) => res,
            Err(_) => {
                println!($message);
                return;
            }
        }
    }
}

macro_rules! ignore_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(_) => {},
            Err(_) => {
                println!($message);
                return;
            }
        };
    }
}

/// Common trait for DNS servers
pub trait DnsServer {

    /// Initialize the server and start listenening
    ///
    /// This method should _NOT_ block. Rather, servers are expected to spawn a new
    /// thread to handle requests and return immediately.
    fn run_server(self) -> bool;
}

/// Utility function for resolving domains referenced in for example CNAME or SRV
/// records. This usually spares the client from having to perform additional
/// lookups.
fn resolve_cnames(lookup_list: &Vec<ResourceRecord>,
                  results: &mut Vec<DnsPacket>,
                  resolver: &mut Box<DnsResolver>)
{
    for ref rec in lookup_list {
        match *rec {
            &ResourceRecord::CNAME { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host,
                                                      QueryType::A,
                                                      true) {

                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    resolve_cnames(&new_unmatched, results, resolver);
                }
            },
            &ResourceRecord::SRV { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host,
                                                      QueryType::A,
                                                      true) {

                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    resolve_cnames(&new_unmatched, results, resolver);
                }
            },
            _ => {}
        }
    }
}

/// Perform the actual work for a query
///
/// Incoming requests are validated to make sure they are well formed and adhere
/// to the server configuration. If so, the request will be passed on to the
/// active resolver and a query will be performed. It will also resolve some
/// possible references within the query, such as CNAME hosts.
///
/// This function will always return a valid packet, even if the request could not
/// be performed, since we still want to send something back to the client.
fn execute_query(context: Arc<ServerContext>, request: &DnsPacket) -> DnsPacket
{
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_available = context.allow_recursive;
    packet.header.response = true;

    if request.header.recursion_desired && !context.allow_recursive {
        packet.header.rescode = ResultCode::REFUSED;
    }
    else if request.questions.len() == 0 {
        packet.header.rescode = ResultCode::FORMERR;
    }
    else {
        let mut results = Vec::new();

        let question = &request.questions[0];
        packet.questions.push(question.clone());

        let mut resolver = context.create_resolver(context.clone());
        let rescode = match resolver.resolve(&question.name,
                                             question.qtype.clone(),
                                             request.header.recursion_desired) {

            Ok(result) => {
                let rescode = result.header.rescode.clone();

                let unmatched = result.get_unresolved_cnames();
                results.push(result);

                resolve_cnames(&unmatched, &mut results, &mut resolver);

                rescode
            },
            Err(err) => {
                println!("Failed to resolve {:?} {}: {:?}", question.qtype, question.name, err);
                ResultCode::SERVFAIL
            }
        };

        packet.header.rescode = rescode;

        for result in results {
            for rec in result.answers {
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                packet.resources.push(rec);
            }
        }
    }

    packet
}

/// The UDP server
///
/// Accepts DNS queries through UDP, and uses the ServerContext to determine
/// how to service the request. Packets are read on a single thread, after which
/// a new thread is spawned to service the request asynchronously.
pub struct DnsUdpServer {
    context: Arc<ServerContext>
}

impl DnsUdpServer {
    pub fn new(context: Arc<ServerContext>) -> DnsUdpServer {
        DnsUdpServer {
            context: context
        }
    }

    /// Handle a request asynchronously by reading it on the query thread but
    /// servicing the response on a new thread
    fn handle_request(&self, socket: &UdpSocket) -> Result<()> {

        // Read a query packet
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = try!(socket.recv_from(&mut req_buffer.buf));
        let request = try!(DnsPacket::from_buffer(&mut req_buffer));

        // Clone the socket and context so they can be safely moved to the new
        // thread
        let socket_clone = match socket.try_clone() {
            Ok(x) => x,
            Err(e) => return Err(e)
        };

        let context = self.context.clone();

        // Spawn the response thread
        spawn(move || {

            let mut size_limit = 512;

            // Check for EDNS
            if request.resources.len() == 1 {
                if let &ResourceRecord::OPT { packet_len, .. } = &request.resources[0] {
                    size_limit = packet_len as usize;
                }
            }

            // Create a response buffer, and ask the context for an appropriate
            // resolver
            let mut res_buffer = VectorPacketBuffer::new();

            let mut packet = execute_query(context, &request);
            let _ = packet.write(&mut res_buffer, size_limit);

            // Fire off the response
            let len = res_buffer.pos();
            let data = return_or_report!(res_buffer.get_range(0, len), "Failed to get buffer data");
            ignore_or_report!(socket_clone.send_to(data, src), "Failed to send response packet");
        });

        Ok(())
    }
}

impl DnsServer for DnsUdpServer {

    /// Launch the server
    ///
    /// This method takes ownership of the server, preventing the method from
    /// being called multiple times.
    fn run_server(self) -> bool {

        // Bind the socket
        let socket = match UdpSocket::bind(("0.0.0.0", self.context.dns_port)) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to start UDP DNS server: {:?}", e);
                return false;
            }
        };

        // Start servicing requests
        spawn(move || {
            loop {
                match self.handle_request(&socket) {
                    Ok(_) => {},
                    Err(err) => {
                        println!("UDP request failed: {:?}", err);
                    }
                }
            }
        });

        true
    }
}

/// TCP DNS server
pub struct DnsTcpServer {
    context: Arc<ServerContext>
}

impl DnsTcpServer {
    pub fn new(context: Arc<ServerContext>) -> DnsTcpServer {
        DnsTcpServer {
            context: context
        }
    }

    fn handle_request(&self, mut stream: TcpStream) {

        let context = self.context.clone();

        spawn(move || {
            let request = {
                let mut stream_buffer = StreamPacketBuffer::new(&mut stream);

                // When DNS packets are sent over TCP, they're prefixed with a two byte
                // length. We don't really need to know the length in advance, so we
                // just move past it and continue reading as usual
                ignore_or_report!(stream_buffer.read_u16(), "Failed to read query packet length");

                return_or_report!(DnsPacket::from_buffer(&mut stream_buffer), "Failed to read query packet")
            };

            let mut res_buffer = VectorPacketBuffer::new();

            let mut packet = execute_query(context, &request);
            ignore_or_report!(packet.write(&mut res_buffer, 0xFFFF), "Failed to write packet to buffer");

            // As is the case for incoming queries, we need to send a 2 byte length
            // value before handing of the actual packet.
            let len = res_buffer.pos();

            let mut len_buffer = [0; 2];
            len_buffer[0] = (len >> 8) as u8;
            len_buffer[1] = (len & 0xFF) as u8;

            ignore_or_report!(stream.write(&len_buffer), "Failed to write packet size");

            // Now we can go ahead and write the actual packet
            let data = return_or_report!(res_buffer.get_range(0, len), "Failed to get packet data");

            ignore_or_report!(stream.write(data), "Failed to write response packet");

            ignore_or_report!(stream.shutdown(Shutdown::Both), "Failed to shutdown socket");
        });
    }
}

impl DnsServer for DnsTcpServer {
    fn run_server(self) -> bool {
        let socket_attempt = TcpListener::bind(("0.0.0.0", self.context.dns_port));
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

                self.handle_request(stream);
            }
        });

        true
    }
}
