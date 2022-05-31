use std::error::Error;
use std::fmt;

use regex::bytes::RegexSet;

use serde::{Serialize,Deserialize};
use serde::ser::{Serializer,SerializeMap};
use serde::de::{self,Deserializer,Visitor,MapAccess};

#[derive(Debug)]
pub struct LabelMatcher {
    set: RegexSet,
    tags: Vec<Vec<u8>>,
}

impl LabelMatcher {
    pub fn new(exprs: &[(&str,&str)]) -> Result<Self,Box<dyn Error>> {
        let mut regexes = Vec::with_capacity(exprs.len());
        let mut tags = Vec::with_capacity(exprs.len());
        for (r,t) in exprs {
            regexes.push(r);
            tags.push(Vec::from(t.as_bytes()));
        }
        let set = RegexSet::new(regexes)?;
        Ok(Self{ set, tags })
    }
    // Return the list of tags that are supposed to describe text
    pub fn matches(&self, text: &[u8]) -> Vec<&[u8]> {
        self.set.matches(&text).iter().map(|i|self.tags[i].as_ref()).collect()
    }
}

impl Serialize for LabelMatcher {
    // This is a lossy serializer that is intended to be used for debugging only.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok,S::Error> {
        let mut map = s.serialize_map(None)?;
        let mut keys = self.set.patterns().iter();
        let mut values = self.tags.iter();
        while let (Some(k), Some(v)) = (keys.next(), values.next()) {
            map.serialize_entry(k,&String::from_utf8_lossy(v))?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for LabelMatcher {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(LabelMatcherVisitor{})
    }
}

struct LabelMatcherVisitor {}

impl<'de> Visitor<'de> for LabelMatcherVisitor {
    type Value = LabelMatcher;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a non-empty regexp=>label map")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value,A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut kvs: Vec<(String,String)> = Vec::new();
        while let Some((k,v)) = access.next_entry()? {
            kvs.push((k,v));
        }
        if kvs.len() == 0 {
            Err(de::Error::custom("empty hash"))
        } else {
            let kvs = kvs.iter().map( |(k,v)| (k.as_ref(),v.as_ref()) ).collect::<Vec<_>>();
            Ok(LabelMatcher::new(&kvs).map_err(de::Error::custom)?)
        }
    }
}
