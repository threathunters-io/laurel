use std::fmt::Debug;

use indexmap::IndexMap;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use linux_audit_parser::*;

/// Collect records in [`EventBody`] context as single or multiple
/// instances.
///
/// Examples for single instances are `SYSCALL`,`EXECVE` (even if the
/// latter can be split across multiple lines). An example for
/// multiple instances is `PATH`.
///
/// "Multi" records are serialized as list-of-maps (`[ { "key":
/// "value", … }, { "key": "value", … } … ]`)
#[derive(Debug, Clone)]
pub enum EventValues<'a> {
    // e.g SYSCALL, EXECVE
    Single(Body<'a>),
    // e.g. PATH
    Multi(Vec<Body<'a>>),
}

impl Serialize for EventValues<'_> {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            EventValues::Single(rv) => rv.serialize(s),
            EventValues::Multi(rvs) => s.collect_seq(rvs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event<'a> {
    pub node: Option<Vec<u8>>,
    pub id: EventID,
    pub body: IndexMap<MessageType, EventValues<'a>>,
    pub container_info: Option<Body<'a>>,
    pub filter: bool,
}

impl Event<'_> {
    pub fn new(node: Option<Vec<u8>>, id: EventID) -> Self {
        Event {
            node,
            id,
            body: IndexMap::with_capacity(5),
            container_info: None,
            filter: false,
        }
    }
}

impl Serialize for Event<'_> {
    #[inline(always)]
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let length = 1
            + self.body.len()
            + usize::from(self.node.is_some())
            + usize::from(self.container_info.is_some());
        let mut map = s.serialize_map(Some(length))?;
        map.serialize_key("ID")?;
        map.serialize_value(&self.id)?;
        if let Some(node) = &self.node {
            // FIXME
            map.serialize_key("NODE")?;
            map.serialize_value(&Bytes(node))?;
        }
        for (k, v) in &self.body {
            map.serialize_entry(&k, &v)?;
        }
        if let Some(value) = &self.container_info {
            map.serialize_key("CONTAINER_INFO")?;
            map.serialize_value(&value)?;
        }
        map.end()
    }
}

pub(crate) type NVec = tinyvec::TinyVec<[u8; 14]>;

/// Helper type to enforce that serialize_bytes() is used in serialization.
pub(crate) struct Bytes<'a>(pub &'a [u8]);

impl<'a> Serialize for Bytes<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(self.0)
    }
}
