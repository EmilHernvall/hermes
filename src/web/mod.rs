use derive_more::{Display, From};

pub mod authority;
pub mod cache;
pub mod index;
pub mod server;
pub mod util;

#[derive(Debug, Display, From)]
pub enum WebError {
    Authority(crate::dns::authority::AuthorityError),
    Io(std::io::Error),
    MissingField(&'static str),
    Serialization(serde_json::Error),
    Template(handlebars::RenderError),
    ZoneNotFound,
    LockError,
    InvalidRequest,
}

impl std::error::Error for WebError {}

pub type Result<T> = std::result::Result<T, WebError>;
