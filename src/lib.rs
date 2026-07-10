pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod coalesce;
pub mod config;
pub mod constants;
pub mod env_matcher;
pub mod hash;
pub mod json;
pub mod label_matcher;
pub mod logger;
pub mod proc;
pub mod procfs;
pub(crate) mod quote;
pub mod rotate;
pub mod sockaddr;
pub mod types;
pub mod userdb;

#[cfg(test)]
mod test;
