//! client for sending DNS queries to other servers

use std::cell::Cell;
use std::io::Result;
use std::io::{Error, ErrorKind};
use std::marker::{Send, Sync};
use std::net::UdpSocket;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::spawn;

use dns::buffer::{PacketBuffer, BytePacketBuffer};
use dns::protocol::{DnsPacket, DnsQuestion, QueryType};

pub trait DnsClient {
    fn run(&self) -> Result<()>;
    fn send_query(&self,
                  qname: &String,
                  qtype: QueryType,
                  server: (&str, u16),
                  recursive: bool) -> Result<DnsPacket>;
}

/// The UDP client
///
/// This includes a fair bit of synchronization due to the stateless nature of UDP.
/// When many queries are sent in parallell, the response packets can come back
/// in any order. For that reason, we fire off replies on the sending thread, but
/// handle replies on a single thread. A channel is created for every response,
/// and the caller will block on the channel until the a response is received.
pub struct DnsUdpClient {

    /// Counter for assigning packet ids
    seq: Mutex<Cell<u16>>,

    /// The listener socket
    socket: UdpSocket,

    /// Queries in progress
    pending_queries: Arc<Mutex<Vec<PendingQuery>>>
}

/// A query in progress. This struct holds the `id` if the request, and a channel
/// endpoint for returning a response back to the thread from which the query
/// was posed.
struct PendingQuery {
    seq: u16,
    tx: Sender<DnsPacket>
}

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

}

impl DnsClient for DnsUdpClient {

    /// The run method launches a worker thread. Unless this thread is running, no
    /// responses will ever be generated, and clients will just block indefinitely.
    ///
    /// This method is safe to invoke multiple times, since each invocation will
    /// just start a new worker thread.
    fn run(&self) -> Result<()> {

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

#[cfg(test)]
pub mod tests {

    use std::io::Result;

    use dns::protocol::{DnsPacket,QueryType};
    use super::*;

    pub type StubCallback = Fn(&String, QueryType, (&str, u16), bool) -> Result<DnsPacket>;

    pub struct DnsStubClient {
        callback: Box<StubCallback>
    }

    impl<'a> DnsStubClient {
        pub fn new(callback: Box<StubCallback>) -> DnsStubClient {
            DnsStubClient {
                callback: callback
            }
        }
    }

    unsafe impl Send for DnsStubClient {}
    unsafe impl Sync for DnsStubClient {}

    impl DnsClient for DnsStubClient {

        fn run(&self) -> Result<()> {
            Ok(())
        }

        fn send_query(&self,
                      qname: &String,
                      qtype: QueryType,
                      server: (&str, u16),
                      recursive: bool) -> Result<DnsPacket> {

            (self.callback)(qname, qtype, server, recursive)
        }
    }
}
