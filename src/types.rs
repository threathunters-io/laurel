use std::fmt::Debug;

use indexmap::IndexMap;

use serde::{Serialize, Serializer};

use linux_audit_parser::*;

use crate::proc::ProcessKey;

/// Collect records in [`EventBody`] context as single or multiple
/// instances.
///
/// Examples for single instances are `SYSCALL`,`EXECVE` (even if the
/// latter can be split across multiple lines). An example for
/// multiple instances is `PATH`.
///
/// "Multi" records are serialized as list-of-maps (`[ { "key":
/// "value", … }, { "key": "value", … } … ]`)
#[derive(Debug, Clone, Serialize)]
pub enum EventValues<'a> {
    // e.g SYSCALL, EXECVE
    Single(Body<'a>),
    // e.g. PATH
    Multi(Vec<Body<'a>>),
}

fn serialize_node<S: Serializer>(value: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    Bytes(value.as_ref().unwrap()).serialize(s)
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct Event<'a> {
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_node"
    )]
    pub node: Option<Vec<u8>>,
    pub id: EventID,
    #[serde(flatten)]
    pub body: IndexMap<MessageType, EventValues<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_info: Option<Body<'a>>,
    #[serde(skip)]
    pub is_filtered: bool,
    #[serde(skip)]
    pub(crate) is_exec: bool,
    #[serde(skip)]
    pub(crate) process_key: Option<ProcessKey>,
}

impl Event<'_> {
    pub fn new(node: Option<Vec<u8>>, id: EventID) -> Self {
        Event {
            node,
            id,
            body: IndexMap::with_capacity(5),
            container_info: None,
            is_filtered: false,
            is_exec: false,
            process_key: None,
        }
    }
}

pub(crate) type NVec = tinyvec::TinyVec<[u8; 14]>;

/// Helper type to enforce that serialize_bytes() is used in serialization.
pub(crate) struct Bytes<'a>(pub &'a [u8]);

impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}
