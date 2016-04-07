use std::net::UdpSocket;
use std::io::Result;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread::spawn;
use std::io::{Error, ErrorKind};
use std::marker::{Send, Sync};
use std::cell::Cell;

use dns::client::DnsClient;
use dns::server::{DnsServer, build_response};
use dns::protocol::{DnsPacket, DnsQuestion, QueryType, ResourceRecord};
use dns::buffer::{PacketBuffer, BytePacketBuffer, VectorPacketBuffer};
use dns::context::ServerContext;

/// The UDP client
///
/// This includes a fair bit of synchronization due to the stateless nature of UDP.
/// When many queries are sent in parallell, the response packets can come back
/// in any order. For that reason, we fire off replies on the sending thread, but
/// handle replies on a single thread. A channel is created for every response,
/// and the caller will block on the channel until the a response is received.
pub struct DnsUdpClient {

    /// Counter for assigning packet ids
    pub seq: Mutex<Cell<u16>>,

    /// The listener socket
    pub socket: UdpSocket,

    /// Queries in progress
    pub pending_queries: Arc<Mutex<Vec<PendingQuery>>>
}

/// A query in progress. This struct holds the `id` if the request, and a channel
/// endpoint for returning a response back to the thread from which the query
/// was posed.
pub struct PendingQuery {
    seq: u16,
    tx: Sender<DnsPacket>
}

// The UDP client has been designed for thread safety and can be moved across
// thread boundaries as well as used from different threads in parallell.
unsafe impl Send for DnsUdpClient {}
unsafe impl Sync for DnsUdpClient {}

impl DnsUdpClient {
    pub fn new() -> DnsUdpClient {
        DnsUdpClient {
            seq: Mutex::new(Cell::new(0)),
            socket: UdpSocket::bind(("0.0.0.0", 34255)).unwrap(),
            pending_queries: Arc::new(Mutex::new(Vec::new()))
        }
    }

    /// The run method launches a worker thread. Unless this thread is running, no
    /// responses will ever be generated, and clients will just block indefinitely.
    ///
    /// This method is safe to invoke multiple times, since each invocation will
    /// just start a new worker thread.
    pub fn run(&self) -> Result<()> {

        let socket_copy = try!(self.socket.try_clone());
        let pending_queries_lock = self.pending_queries.clone();

        spawn(move || {
            loop {
                // Read data into a buffer
                let mut res_buffer = BytePacketBuffer::new();
                match socket_copy.recv_from(&mut res_buffer.buf) {
                    Ok(_) => {},
                    Err(_) => {
                        continue;
                    }
                }

                // Construct a DnsPacket from buffer, skipping the packet if parsing
                // failed
                let packet = match DnsPacket::from_buffer(&mut res_buffer) {
                    Ok(packet) => packet,
                    Err(err) => {
                        println!("Got error {}", err);
                        continue;
                    }
                };

                // Acquire a lock on the pending_queries list, and search for a
                // matching PendingQuery to which to deliver the response.
                if let Ok(mut pending_queries) = pending_queries_lock.lock() {

                    let mut matched_query = None;
                    for (i, pending_query) in pending_queries.iter().enumerate() {

                        if pending_query.seq == packet.header.id {

                            // Matching query found, send the response
                            let _ = pending_query.tx.send(packet.clone());

                            // Mark this index for removal from list
                            matched_query = Some(i);

                            break;
                        }
                    }

                    // Remove the `PendingQuery` for the list
                    if let Some(idx) = matched_query {
                        pending_queries.remove(idx);
                    }
                }
            }
        });

        Ok(())
    }
}

impl DnsClient for DnsUdpClient {

    /// Send a DNS query
    ///
    /// This will construct a query packet, and fire it off to the specified server.
    /// The query is sent from the callee thread, but responses are read on a
    /// worker thread, and returned to this thread through a channel. Thus this
    /// method is thread safe, and can be used from any number of threads in
    /// parallell.
    fn send_query(&self,
                  qname: &String,
                  qtype: QueryType,
                  server: (&str, u16),
                  recursive: bool) -> Result<DnsPacket> {

        // Prepare request
        let mut packet = DnsPacket::new();

        if let Ok(seq_cell) = self.seq.lock() {
            packet.header.id = seq_cell.get();
            seq_cell.set(packet.header.id+1);
        }
        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;

        packet.questions.push(DnsQuestion::new(&qname, qtype));

        // Create a return channel, and add a `PendingQuery` to the list of lookups
        // in progress
        let (tx, rx) = channel();
        match self.pending_queries.lock() {
            Ok(mut pending_queries) => {
                pending_queries.push(PendingQuery {
                    seq: packet.header.id,
                    tx: tx
                });
            },
            Err(_) => return Err(Error::new(ErrorKind::Other, "Failed to acquire lock"))
        }

        // Send query
        let mut req_buffer = BytePacketBuffer::new();
        try!(packet.write(&mut req_buffer, 512));
        try!(self.socket.send_to(&req_buffer.buf[0..req_buffer.pos], server));

        // Wait for response
        if let Ok(qr) = rx.recv() {
            return Ok(qr);
        }

        // Otherwise, fail
        Err(Error::new(ErrorKind::InvalidInput, "Lookup failed"))
    }
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
    pub fn handle_request(&self, socket: &UdpSocket) -> Result<()> {

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
            let mut resolver = context.create_resolver(context.clone());

            // Build the response, using the dns::server::build_response function
            match build_response(context,
                                 &request,
                                 &mut resolver,
                                 &mut res_buffer,
                                 size_limit) {

                Ok(_) => {},
                Err(err) => {
                    println!("UDP request failed: {:?}", err);
                    return;
                }
            }

            // Fire off the response
            let len = res_buffer.pos();
            if let Ok(data) = res_buffer.get_range(0, len) {
                if let Err(err) = socket_clone.send_to(data, src) {
                    println!("UDP send failed: {:?}", err);
                }
            }
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
        let socket = match UdpSocket::bind(("0.0.0.0", self.context.listen_port)) {
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
