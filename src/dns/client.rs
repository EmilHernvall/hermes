//! client for sending DNS queries to other servers

use std::io::Result;
use std::io::{Error, ErrorKind};
use std::marker::{Send, Sync};
use std::net::UdpSocket;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{spawn,sleep};
use std::time::Duration as SleepDuration;
use std::sync::atomic::{AtomicUsize,Ordering};

use chrono::*;

use dns::buffer::{PacketBuffer, BytePacketBuffer};
use dns::protocol::{DnsPacket, DnsQuestion, QueryType};

pub trait DnsClient {
    fn get_sent_count(&self) -> usize;
    fn get_failed_count(&self) -> usize;

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

    total_sent: AtomicUsize,
    total_failed: AtomicUsize,

    /// Counter for assigning packet ids
    seq: AtomicUsize,

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
    timestamp: DateTime<Local>,
    tx: Sender<Option<DnsPacket>>
}

unsafe impl Send for DnsUdpClient {}
unsafe impl Sync for DnsUdpClient {}

impl DnsUdpClient {
    pub fn new(port: u16) -> DnsUdpClient {
        DnsUdpClient {
            total_sent: AtomicUsize::new(0),
            total_failed: AtomicUsize::new(0),
            seq: AtomicUsize::new(0),
            socket: UdpSocket::bind(("0.0.0.0", port)).unwrap(),
            pending_queries: Arc::new(Mutex::new(Vec::new()))
        }
    }
}

impl DnsClient for DnsUdpClient {

    fn get_sent_count(&self) -> usize {
        self.total_sent.load(Ordering::Acquire)
    }

    fn get_failed_count(&self) -> usize {
        self.total_failed.load(Ordering::Acquire)
    }

    /// The run method launches a worker thread. Unless this thread is running, no
    /// responses will ever be generated, and clients will just block indefinitely.
    fn run(&self) -> Result<()> {

        // Start the thread for handling incoming responses
        {
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
                            println!("DnsUdpClient failed to parse packet with error: {}", err);
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
                                let _ = pending_query.tx.send(Some(packet.clone()));

                                // Mark this index for removal from list
                                matched_query = Some(i);

                                break;
                            }
                        }

                        if let Some(idx) = matched_query {
                            pending_queries.remove(idx);
                        } else {
                            println!("Discarding response for: {:?}", packet.questions[0]);
                        }
                    }
                }
            });
        };

        // Start the thread for timing out requests
        {
            let pending_queries_lock = self.pending_queries.clone();
            spawn(move || {
                let timeout = Duration::seconds(1);
                loop {
                    if let Ok(mut pending_queries) = pending_queries_lock.lock() {

                        let mut finished_queries = Vec::new();
                        for (i, pending_query) in pending_queries.iter().enumerate() {

                            let expires = pending_query.timestamp + timeout;
                            if expires < Local::now() {
                                let _ = pending_query.tx.send(None);
                                finished_queries.push(i);
                            }
                        }

                        // Remove `PendingQuery` objects from the list, in reverse order
                        for idx in finished_queries.iter().rev() {
                            pending_queries.remove(*idx);
                        }

                    }

                    sleep(SleepDuration::from_millis(100));
                }
            });
        };

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

        let _ = self.total_sent.fetch_add(1, Ordering::Release);

        // Prepare request
        let mut packet = DnsPacket::new();

        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        if packet.header.id + 1 == 0xFFFF {
            self.seq.compare_and_swap(0xFFFF, 0, Ordering::SeqCst);
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
                    timestamp: Local::now(),
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
        if let Ok(res) = rx.recv() {
            match res {
                Some(qr) => return Ok(qr),
                None => {
                    let _ = self.total_failed.fetch_add(1, Ordering::Release);
                    return Err(Error::new(ErrorKind::TimedOut, "Request timed out"))
                }
            }
        }

        // Otherwise, fail
        let _ = self.total_failed.fetch_add(1, Ordering::Release);
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

        fn get_sent_count(&self) -> usize {
            0
        }

        fn get_failed_count(&self) -> usize {
            0
        }

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
