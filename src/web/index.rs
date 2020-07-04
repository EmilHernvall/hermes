use serde_derive::{Deserialize, Serialize};

use crate::dns::context::ServerContext;
use crate::web::Result;

#[derive(Serialize, Deserialize)]
pub struct IndexResponse {
    ok: bool,
    client_sent_queries: usize,
    client_failed_queries: usize,
    server_tcp_queries: usize,
    server_udp_queries: usize,
}

pub fn index(context: &ServerContext) -> Result<IndexResponse> {
    Ok(IndexResponse {
        ok: true,
        client_sent_queries: context.client.get_sent_count(),
        client_failed_queries: context.client.get_failed_count(),
        server_tcp_queries: context.statistics.get_tcp_query_count(),
        server_udp_queries: context.statistics.get_udp_query_count(),
    })
}
