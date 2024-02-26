pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod coalesce;
pub mod config;
pub mod constants;
pub mod json;
pub mod label_matcher;
pub mod logger;
pub mod parser;
pub mod proc;
#[cfg(all(feature = "procfs", target_os = "linux"))]
pub mod procfs;
pub(crate) mod quote;
pub mod rotate;
#[cfg(target_os = "linux")]
pub mod sockaddr;
pub mod types;
pub mod userdb;
