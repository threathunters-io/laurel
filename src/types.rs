use std::fmt::{self,Debug,Display};
use std::string::*;
use std::ops::Range;
use std::iter::Iterator;
use std::error::Error as StdError;
use std::convert::{TryFrom,TryInto};
use std::str;

use serde::{Serialize,Serializer};
use serde::ser::{SerializeSeq,SerializeMap,Error};

use crate::constants::*;
use crate::quoted_string::ToQuotedString;

/// The identifier of an audit event, corresponding to the
/// `msg=audit(…)` part of every _auditd(8)_ log line.
///
/// It consists of a mullisecond-precision timestamp and a sequence
/// number, thus guaranteeing per-host uniqueness.
#[derive(Debug,PartialEq,Eq,Hash,Clone,Copy,Default)]
pub struct EventID {
    pub timestamp: u64,
    pub sequence: u32,
}

impl Display for EventID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{:03}:{}", self.timestamp/1000, self.timestamp%1000, self.sequence)
    }
}

impl Serialize for EventID {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok,S::Error> {
        s.serialize_str(&format!("{}", self))
    }
}

/// The type of an audit message, corresponding to the `type=…` part
/// of every _auditd(8)_ log line.
///
/// The implementation uses the same 32bit unsigned integer that is
/// used by the Linux Audit API.
///
/// The mappings between numeric and symbolic values is generated
/// using CSV retrieved from the [`Linux Audit Project`]'s
/// documentation.
///
/// [`Linux Audit Project`]: https://github.com/linux-audit/audit-documentation
#[derive(PartialEq,Eq,Hash,Default,Clone,Copy)]
pub struct MessageType(pub u32);

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match EVENT_NAMES.get(&(self.0)) {
            Some(name) => write!(f, "{}", name.to_string()),
            None => write!(f, "UNKNOWN[{}]", self.0),
        }
    }
}

impl Debug for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageType({})",
               match EVENT_NAMES.get(&(self.0)) {
                   Some(name) => name.to_string(),
                   None => format!("{}", self.0),
               })
    }
}

impl Serialize for MessageType {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match EVENT_NAMES.get(&(self.0)) {
            Some(name) => s.serialize_str(&name),
            None => s.serialize_str(&format!("UNKNOWN[{}]", self.0)),
        }
    }
}

/// Representation of the key part of key/value pairs in [`Record`]
#[derive(Debug,PartialEq,Clone)]
pub enum Key {
    Name(Range<usize>),
    /// `a0`, `a1`, `a2[0]`, `a2[1]`…
    Arg(u16, Option<u16>),
    /// `a0_len` …
    ArgLen(u16),
    Literal(&'static str),
}

/// Quotes in [`Value`] strings
#[derive(PartialEq,Clone)]
pub enum Quote { None, Single, Double, Braces }

#[derive(Clone)]
pub enum Number {
    Hex(u64),
    Dec(u64),
    Oct(u64),
}

impl Debug for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Num:<")?;
        match self {
            Number::Hex(n) => write!(f, "0x{:x}>", n),
            Number::Dec(n) => write!(f, "{}>", n),
            Number::Oct(n) => write!(f, "0o{:o}>", n),
        }
    }
}

/// Representation of the value part of key/value pairs in [`Record`]
#[derive(Clone)]
pub enum Value {
    Empty,
    /// HexStr is transformed in parse(), to a bare Str by the time
    /// any external code sees the Value.
    HexStr(Range<usize>),
    Str(Range<usize>, Quote),
    /// Segments are generated in Coalesce::normalize() from `EXECVE`
    /// / `aX[Y]` fragments.
    Segments(Vec<Range<usize>>),
    /// Lists are generated in Coalesce::normalize() e.g.: `EXECVE` /
    /// `a0`, `a1`, `a2` … -> `ARGV`
    List(Vec<Value>),
    StringifiedList(Vec<Value>),
    /// Values generated in parse() from unquoted Str values
    ///
    /// For example, `SYSCALL` / `a0` etc are interpreted as
    /// hexadecimal numbers.
    Number(Number),
}

/// List of [`Key`]/[`Value`] pairs, that are, for the most part,
/// stored offsets into the raw log line.
#[derive(Clone)]
pub struct Record {
    pub elems: Vec<(Key, Value)>,
    pub raw: Vec<u8>,
}

impl Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut seq = f.debug_struct("Record");
        for (k,v) in self {
            seq.field( &*k.to_string(), &v);
        }
        seq.finish()
    }
}

impl Serialize for Record {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok,S::Error> {
        let mut map = s.serialize_map(Some(self.elems.len()))?;
        for (k,v) in self {
            map.serialize_key(&k.to_string())?;
            map.serialize_value(&v)?;
        }
        map.end()
    }
}

impl<'a> Record {
    /// Merges two Records into one
    pub fn extend(&mut self, other: Self) {
        let rawlen = self.raw.len();
        self.raw.extend(other.raw);
        self.elems.extend(other.elems.into_iter().map(|(k,v)| (
            match k {
                Key::Name(r) => Key::Name(r.offset(rawlen)),
                _ => k,
            },
            match v {
                Value::HexStr(r) => Value::HexStr(r.offset(rawlen)),
                Value::Str(r,q) => Value::Str(r.offset(rawlen),q),
                Value::Empty => Value::Empty,
                Value::Number(n) => Value::Number(n),
                Value::Segments(_) | Value::List(_) | Value::StringifiedList(_) =>
                    panic!("extend after normalize?"),
            }
        )).collect::<Vec<_>>())
    }

    /// Retrieves the first value found for a given key
    pub fn get(&self, key: &[u8]) -> Option<RValue> {
        for (k,v) in self {
            if format!("{}", k).as_bytes() == key {
                return Some(v)
            }
        }
        None
    }

    /// Add a byte string to a record.
    pub fn put(&mut self, s: &[u8]) -> Range<usize> {
        let b = self.raw.len();
        self.raw.extend(s);
        b .. b+s.len()
    }
}

impl<'a> IntoIterator for &'a Record {
    type Item = (RKey<'a>, RValue<'a>);
    type IntoIter = RecordIterator<'a>;
    fn into_iter(self) -> Self::IntoIter {
        return RecordIterator {
            count: 0, r: &self,
        }
    }
}

pub struct RecordIterator<'a> {
    r: &'a Record,
    count: usize,
}

impl<'a> Iterator for RecordIterator<'a> {
    type Item = (RKey<'a>, RValue<'a>);
    fn next(&mut self) -> Option<Self::Item> {
        self.count += 1;
        self.r.elems.get(self.count-1).
            map( |(key,value)| (RKey{key, raw: &self.r.raw}, RValue{value, raw: &self.r.raw}))
    }
}

/// RKey is borrowed from Record.
#[derive(PartialEq)]
pub struct RKey<'a> { pub key: &'a Key, pub raw: &'a[u8] }
/// RValue is borrowed from Record.
#[derive(Clone,Copy)]
pub struct RValue<'a> { pub value: &'a Value, pub raw: &'a[u8] }

impl<'a> Debug for RKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl<'a> Display for RKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.key {
            Key::Arg(x, Some(y)) => write!(f, "a{}[{}]", x, y),
            Key::Arg(x, None) => write!(f, "a{}", x),
            Key::ArgLen(x) => write!(f, "a{}_len", x),
            Key::Name(r) => {
                // safety: The peg parser guarantees an ASCII-only key.
                let s = unsafe { str::from_utf8_unchecked(&self.raw[r.clone()]) };
                f.write_str(s)
            },
            Key::Literal(s) => f.write_str(s),
        }
    }
}

impl<'a> PartialEq<str> for RKey<'a> {
    fn eq(&self, other: &str) -> bool {
        self.to_string() == *other
    }
}

impl<'a> TryFrom<RValue<'a>> for Vec<u8> {
    type Error = Box<dyn StdError>;
    fn try_from(v: RValue<'a>) -> Result<Self, Self::Error> {
        match v.value {
            Value::HexStr(_) => Err("HexStr occurred after parse".into()),
            Value::Str(r,Quote::Braces) => {
                let mut s = Vec::with_capacity(r.len() + 2);
                s.push(b'{');
                s.extend(Vec::from(&v.raw[r.clone()]));
                s.push(b'}');
                Ok(s)
            },
            Value::Str(r,_) => Ok(Vec::from(&v.raw[r.clone()]).into()),
            Value::Empty => Ok("".into()),
            Value::Segments(ranges) => {
                let mut sb = Vec::new();
                for r in ranges {
                    sb.extend(Vec::from(&v.raw[r.clone()]));
                }
                Ok(sb)
            }
            Value::Number(_) => Err("Won't convert number to string".into()),
            Value::List(_) | Value::StringifiedList(_) => Err("Can't convert list to scalarr".into()),
        }
    }
}

impl<'a> TryFrom<RValue<'a>> for Vec<Vec<u8>> {
    type Error = Box<dyn StdError>;
    fn try_from(value: RValue<'a>) -> Result<Self, Self::Error> {
        if let Value::List(values) = value.value {
            let mut rv = Vec::new();
            for v in values {
                let s = Vec::try_from(RValue{value: &v, raw: &value.raw})?;
                rv.push(s);
            }
            Ok(rv)
        } else {
            Err("not a list".into())
        }
    }
}

impl<'a> Debug for RValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            Value::HexStr(r) => write!(f, "HexStr:<{}>", &String::from_utf8_lossy(&self.raw[r.clone()])),
            Value::Str(r,_q) => write!(f, "Str:<{}>", &String::from_utf8_lossy(&self.raw[r.clone()])),
            Value::Empty     => write!(f, "Empty"),
            Value::Segments(segs) => {
                write!(f, "Segments<")?;
                for (n, r) in segs.iter().enumerate() {
                    if n > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", String::from_utf8_lossy(&self.raw[r.clone()]))?;
                }
                write!(f, ">")
            },
            Value::List(vs) => {
                write!(f, "List:<")?;
                for (n, v) in vs.iter().enumerate() {
                    if n > 0 {
                        write!(f, ", ")?;
                    }
                    match v {
                        Value::Str(r, _) => {
                            write!(f, "{}", String::from_utf8_lossy(&self.raw[r.clone()]))?;
                        }
                        Value::Segments(rs) => {
                            for r in rs {
                                write!(f, "{}", String::from_utf8_lossy(&self.raw[r.clone()]))?;
                            }
                        }
                        Value::Number(Number::Hex(n)) => write!(f, "{:?}", Number::Hex(*n))?,
                        Value::Empty     => panic!("list can't contain empty value"),
                        Value::HexStr(_) => panic!("list can't contain hex string"),
                        Value::List(_) | Value::StringifiedList(_) => panic!("list can't contain list"),
                        Value::Number(_) => panic!("List can't contain number"),
                    }
                }
                write!(f, ">")
            }
            Value::StringifiedList(vs) => {
                write!(f, "StringifiedList:<")?;
                for (n, v) in vs.iter().enumerate() {
                    if n > 0 {
                        write!(f, " ")?;
                    }
                    match v {
                        Value::Str(r, _) => {
                            write!(f, "{}", String::from_utf8_lossy(&self.raw[r.clone()]))?;
                        }
                        Value::Segments(rs) => {
                            for r in rs {
                                write!(f, "{}", String::from_utf8_lossy(&self.raw[r.clone()]))?;
                            }
                        }
                        Value::Number(Number::Hex(n)) => write!(f, "{:?}", Number::Hex(*n))?,
                        Value::Empty     => panic!("list can't contain empty value"),
                        Value::HexStr(_) => panic!("list can't contain hex string"),
                        Value::List(_) | Value::StringifiedList(_) => panic!("list can't contain list"),
                        Value::Number(_) => panic!("List can't contain number"),
                    }
                }
                write!(f, ">")
            }
            Value::Number(n) => {
                write!(f, "{:?}", n)
            }
        }
    }
}


impl<'a> Serialize for RValue<'a> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok,S::Error> {
        match self.value {
            Value::Empty => s.serialize_none(),
            Value::Str(r,q) => {
                let mut sb = String::with_capacity(r.len());
                if let Quote::Braces = q { sb.push('{') };
                sb.push_str(&self.raw[r.clone()].to_quoted_string());
                if let Quote::Braces = q { sb.push('}') };
                s.serialize_str(&sb)
            },
            Value::Segments(segs) => {
                let mut sb = String::new();
                for seg in segs {
                    sb.push_str(&self.raw[seg.clone()].to_quoted_string());
                }
                s.serialize_str(&sb)
            },
            Value::List(vs) => {
                let mut seq = s.serialize_seq(Some(vs.len()))?;
                for v in vs {
                    seq.serialize_element(&RValue{raw: &self.raw, value: &v})?;
                }
                seq.end()
            },
            Value::StringifiedList(vs) => {
                let mut buf: Vec<u8> = Vec::new();
                let mut first = true;
                for v in vs {
                    if first {
                        first = false;
                    } else {
                        buf.push(b' ');
                    }
                    buf.extend(RValue{raw: &self.raw, value: &v}
                               .try_into().
                               unwrap_or_else(|_| vec!(b'x')));
                }
                s.serialize_str(&buf.to_quoted_string())
            },
            Value::Number(n) => {
                match n {
                    Number::Dec(n) => s.serialize_u64(*n),
                    Number::Hex(n) => s.serialize_str(&format!("0x{:x}", n)),
                    Number::Oct(n) => s.serialize_str(&format!("0o{:o}", n)),
                }
            }
            Value::HexStr(_r) => {
                Err(S::Error::custom("can't serialize untreated hex string"))
            }
        }
    }
}

/// The Offset trait provides an implementation for adding offset to Range.
trait Offset { fn offset(&self, offset: usize) -> Self; }

impl Offset for Range<usize> {
    fn offset(&self, offset: usize) -> Self {
        Range{start: self.start + offset, end: self.end + offset }
    }
}

