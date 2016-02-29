use std::net::UdpSocket;
use std::io::Result;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::thread::spawn;
use std::io::{Error, ErrorKind};
use std::marker::{Send, Sync};
use std::cell::Cell;

use dns::resolve::DnsResolver;
use dns::cache::SynchronizedCache;
use dns::network::{DnsClient, DnsServer};
use dns::protocol::{DnsHeader,
                    QueryResult,
                    DnsQuestion,
                    DnsPacket,
                    QueryType};

use dns::buffer::{PacketBuffer, BytePacketBuffer, VectorPacketBuffer};

/*pub struct DnsUdpClient<'a> {
    server: &'a str
}

impl<'a> DnsUdpClient<'a> {
    pub fn new(server: &'a str) -> DnsUdpClient {
        DnsUdpClient {
            server: server
        }
    }
}

impl<'a> DnsClient for DnsUdpClient<'a> {
    fn send_query(&mut self,
                  qname: &String,
                  qtype: QueryType) -> Result<QueryResult> {

        // Prepare request
        let mut req_buffer = BytePacketBuffer::new();
        let mut req_packet = DnsPacket::new(&mut req_buffer);

        let mut head = DnsHeader::new();
        head.id = 0;
        head.questions = 1;
        try!(head.write(&mut req_packet));

        let question = DnsQuestion::new(qname, qtype);
        try!(question.write(&mut req_packet));

        // Set up socket and send data
        let socket = try!(UdpSocket::bind("0.0.0.0:34254"));
        try!(socket.send_to(&req_packet.buffer.buf[0..req_packet.buffer.pos], (self.server, 53)));

        // Retrieve response
        let mut res_buffer = BytePacketBuffer::new();
        {
            let _ = try!(socket.recv_from(&mut res_buffer.buf));
        };

        drop(socket);

        let mut response_packet = DnsPacket::new(&mut res_buffer);
        response_packet.read()
    }
}*/

pub struct PendingQuery {
    seq: u16,
    tx: Sender<QueryResult>
}

pub struct DnsUdpClient {
    pub seq: Mutex<Cell<u16>>,
    pub socket: UdpSocket,
    pub pending_queries: Arc<Mutex<Vec<PendingQuery>>>
}

#[allow(dead_code)]
impl DnsUdpClient {
    pub fn new() -> DnsUdpClient {
        println!("New DnsUdpClient");
        DnsUdpClient {
            seq: Mutex::new(Cell::new(0)),
            socket: UdpSocket::bind(("0.0.0.0", 34254)).unwrap(),
            pending_queries: Arc::new(Mutex::new(Vec::new()))
        }
    }

    pub fn run(&self) -> Result<()> {

        let socket_copy = try!(self.socket.try_clone());
        let pending_queries_lock = self.pending_queries.clone();

        spawn(move || {
            loop {
                let mut res_buffer = BytePacketBuffer::new();
                {
                    match socket_copy.recv_from(&mut res_buffer.buf) {
                        Ok(_) => {
                            //println!("received {:?} bytes", bytes);
                        },
                        Err(_) => {
                            //println!("receive error");
                            continue;
                        }
                    }
                };

                let mut response_packet = DnsPacket::new(&mut res_buffer);
                match response_packet.read() {
                    Ok(query_result) => {

                        if let Ok(mut pending_queries) = pending_queries_lock.lock() {
                            let mut matched_query = None;
                            for (i, pending_query) in pending_queries.iter().enumerate() {
                                if pending_query.seq == query_result.id {
                                    let _ = pending_query.tx.send(query_result.clone());
                                    matched_query = Some(i);
                                }
                            }

                            if let Some(idx) = matched_query {
                                pending_queries.remove(idx);
                            }
                        }
                    },
                    Err(err) => {
                        println!("Got error {}", err);
                    }
                }
            }
        });

        Ok(())
    }
}

unsafe impl Send for DnsUdpClient {}
unsafe impl Sync for DnsUdpClient {}

impl DnsClient for DnsUdpClient {
    fn send_query(&self,
                  qname: &String,
                  qtype: QueryType,
                  server: (&str, u16)) -> Result<QueryResult> {

        // Prepare request
        let mut req_buffer = BytePacketBuffer::new();
        let mut req_packet = DnsPacket::new(&mut req_buffer);

        let mut head = DnsHeader::new();
        if let Ok(seq_cell) = self.seq.lock() {
            head.id = seq_cell.get();
            seq_cell.set(head.id+1);
        }
        head.questions = 1;
        try!(head.write(&mut req_packet));

        let question = DnsQuestion::new(&qname, qtype);
        try!(question.write(&mut req_packet));

        let (tx, rx) = channel();
        if let Ok(mut pending_queries) = self.pending_queries.lock() {
            pending_queries.push(PendingQuery {
                seq: head.id,
                tx: tx
            });

            // Send query
            try!(self.socket.send_to(&req_packet.buffer.buf[0..req_packet.buffer.pos], server));
        }

        if let Ok(qr) = rx.recv() {
            return Ok(qr);
        }

        Err(Error::new(ErrorKind::InvalidInput, "Lookup failed"))
    }
}

pub struct DnsUdpServer<'a> {
    client: Arc<DnsUdpClient>,
    cache: &'a SynchronizedCache,
    port: u16
}

impl<'a> DnsUdpServer<'a> {
    pub fn new(client: Arc<DnsUdpClient>,
               cache: &'a SynchronizedCache,
               port: u16) -> DnsUdpServer<'a> {
        DnsUdpServer {
            client: client,
            cache: cache,
            port: port
        }
    }

    pub fn handle_request(socket: &UdpSocket,
                          client: &DnsUdpClient,
                          cache: &SynchronizedCache) -> Result<()> {
        let mut req_buffer = BytePacketBuffer::new();
        let mut packet = DnsPacket::new(&mut req_buffer);
        let (_, src) = try!(socket.recv_from(&mut packet.buffer.buf));

        let request = try!(packet.read());

        let mut res_buffer = VectorPacketBuffer::new();

        {
            let mut res_packet = DnsPacket::new(&mut res_buffer);

            let mut results = Vec::new();
            for question in &request.questions {
                println!("{}", question);
                let mut resolver = DnsResolver::new(client, cache);
                if let Ok(result) = resolver.resolve(&question.name,
                                                     question.qtype.clone()) {
                    results.push(result);
                }
            }

            let mut answers = Vec::new();
            for result in results {
                for answer in result.answers {
                    println!("{:?}", answer);
                    answers.push(answer);
                }
            }

            let mut head = DnsHeader::new();

            let mut size = head.binary_len();
            for ref question in &request.questions {
                size += question.binary_len(&res_packet);
            }

            let mut answer_count = answers.len();

            for (i, answer) in answers.iter().enumerate() {
                size += answer.binary_len(&res_packet);
                if size > 512 {
                    answer_count = i;
                    break;
                }
            }

            head.id = request.id;
            head.recursion_available = true;
            head.questions = request.questions.len() as u16;
            head.answers = answer_count as u16;
            head.response = true;
            head.truncated_message = answer_count < answers.len();

            try!(head.write(&mut res_packet));

            for question in &request.questions {
                try!(question.write(&mut res_packet));
            }

            for answer in answers.iter().take(answer_count) {
                try!(answer.write(&mut res_packet));
            }
        };

        let len = res_buffer.pos();

        try!(socket.send_to(try!(res_buffer.get_range(0, len)), src));

        Ok(())
    }
}

impl<'a> DnsServer for DnsUdpServer<'a> {
    fn run(&mut self) -> bool {
        let socket_attempt = UdpSocket::bind(("0.0.0.0", self.port));
        if !socket_attempt.is_ok() {
            return false;
        }

        let socket = socket_attempt.unwrap();
        loop {
            if let Ok(socket_clone) = socket.try_clone() {
                let client = self.client.clone();
                let cache = self.cache.clone();
                spawn(move || {
                    match DnsUdpServer::handle_request(&socket_clone, &client, &cache) {
                        Ok(_) => {},
                        Err(err) => {
                            println!("UDP request failed: {:?}", err);
                        }
                    }
                });
            }
        }
    }
}
