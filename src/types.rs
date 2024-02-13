use std::convert::{Into, TryFrom};
use std::fmt::{self, Debug, Display};
use std::iter::Iterator;
use std::ops::Range;
use std::str;
use std::string::*;

use indexmap::IndexMap;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::constants::*;
use crate::quoted_string::ToQuotedString;

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
    Single(Record<'a>),
    // e.g. PATH
    Multi(Vec<Record<'a>>),
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
    pub filter: bool,
}

impl Event<'_> {
    pub fn new(node: Option<Vec<u8>>, id: EventID) -> Self {
        Event {
            node,
            id,
            body: IndexMap::with_capacity(5),
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
        let length = self.body.len() + if self.node.is_some() { 2 } else { 1 };
        let mut map = s.serialize_map(Some(length))?;
        map.serialize_key("ID")?;
        map.serialize_value(&self.id)?;
        if let Some(node) = &self.node {
            map.serialize_key("NODE")?;
            map.serialize_value(&node.as_slice().to_quoted_string())?;
        }
        for (k, v) in &self.body {
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

/// The identifier of an audit event, corresponding to the
/// `msg=audit(…)` part of every _auditd(8)_ log line.
///
/// It consists of a mullisecond-precision timestamp and a sequence
/// number, thus guaranteeing per-host uniqueness.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy, Default)]
pub struct EventID {
    pub timestamp: u64,
    pub sequence: u32,
}

impl Display for EventID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{:03}:{}",
            self.timestamp / 1000,
            self.timestamp % 1000,
            self.sequence
        )
    }
}

impl Serialize for EventID {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self)
    }
}

impl PartialEq<str> for EventID {
    fn eq(&self, other: &str) -> bool {
        format!("{self}") == other
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
#[derive(PartialEq, Eq, Hash, Default, Clone, Copy)]
pub struct MessageType(pub u32);

impl Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match EVENT_NAMES.get(&(self.0)) {
            Some(name) => write!(f, "{}", name),
            None => write!(f, "UNKNOWN[{}]", self.0),
        }
    }
}

impl Debug for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MessageType({})",
            match EVENT_NAMES.get(&(self.0)) {
                Some(name) => name.to_string(),
                None => format!("{}", self.0),
            }
        )
    }
}

impl Serialize for MessageType {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match EVENT_NAMES.get(&(self.0)) {
            Some(name) => s.collect_str(name),
            None => s.collect_str(&format_args!("UNKNOWN[{}]", self.0)),
        }
    }
}

impl MessageType {
    /// True for messages that are part of multi-part events from
    /// kernel-space.
    ///
    /// This mimics auparse logic as of version 3.0.6
    pub fn is_multipart(&self) -> bool {
        (1300..2100).contains(&self.0) || self == &msg_type::LOGIN
    }
}

/// Common values found in SYSCALL records
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
#[repr(usize)]
pub enum Common {
    Arch,
    Argc,
    CapFe,
    CapFi,
    CapFp,
    CapFver,
    Comm,
    Cwd,
    Dev,
    Exe,
    Exit,
    Inode,
    Item,
    Items,
    Key,
    Mode,
    Name,
    Nametype,
    Pid,
    PPid,
    Ses,
    Subj,
    Success,
    Syscall,
    Tty,
}

const COMMON: &[(&str, Common)] = &[
    ("arch", Common::Arch),
    ("argc", Common::Argc),
    ("cap_fe", Common::CapFe),
    ("cap_fi", Common::CapFi),
    ("cap_fp", Common::CapFp),
    ("cap_fver", Common::CapFver),
    ("comm", Common::Comm),
    ("cwd", Common::Cwd),
    ("dev", Common::Dev),
    ("exe", Common::Exe),
    ("exit", Common::Exit),
    ("inode", Common::Inode),
    ("item", Common::Item),
    ("items", Common::Items),
    ("key", Common::Key),
    ("mode", Common::Mode),
    ("name", Common::Name),
    ("nametype", Common::Nametype),
    ("pid", Common::Pid),
    ("ppid", Common::PPid),
    ("ses", Common::Ses),
    ("subj", Common::Subj),
    ("success", Common::Success),
    ("syscall", Common::Syscall),
    ("tty", Common::Tty),
];

impl TryFrom<&[u8]> for Common {
    type Error = &'static str;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let i = COMMON
            .binary_search_by_key(&value, |(s, _)| s.as_bytes())
            .map_err(|_| "unknown key")?;
        Ok(COMMON[i].1)
    }
}

impl From<Common> for &'static str {
    fn from(value: Common) -> Self {
        COMMON[value as usize].0
    }
}

impl Display for Common {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", COMMON[*self as usize].0)
    }
}

pub(crate) type NVec = tinyvec::TinyVec<[u8; 14]>;

/// Representation of the key part of key/value pairs in [`Record`]
#[derive(PartialEq, Eq, Clone)]
pub enum Key {
    /// regular ASCII-only name as returned by parser
    Name(NVec),
    /// special case for *uid
    NameUID(NVec),
    /// special case for *gid
    NameGID(NVec),
    /// special case for common values
    Common(Common),
    /// regular ASCII-only name, output/serialization in all-caps, for
    /// translated / "enriched" values
    NameTranslated(NVec),
    /// `a0`, `a1`, `a2[0]`, `a2[1]`…
    Arg(u32, Option<u16>),
    /// `a0_len` …
    ArgLen(u32),
    Literal(&'static str),
}

impl Default for Key {
    fn default() -> Self {
        Key::Literal("no_key")
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::Arg(x, Some(y)) => write!(f, "a{}[{}]", x, y),
            Key::Arg(x, None) => write!(f, "a{}", x),
            Key::ArgLen(x) => write!(f, "a{}_len", x),
            Key::Name(r) | Key::NameUID(r) | Key::NameGID(r) => {
                // safety: The parser guarantees an ASCII-only key.
                let s = unsafe { str::from_utf8_unchecked(r) };
                f.write_str(s)
            }
            Key::Common(c) => write!(f, "{}", c),
            Key::NameTranslated(r) => {
                // safety: The parser guarantees an ASCII-only key.
                let s = unsafe { str::from_utf8_unchecked(r) };
                f.write_str(&str::to_ascii_uppercase(s))
            }
            Key::Literal(s) => f.write_str(s),
        }
    }
}

impl Serialize for Key {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Key::Arg(x, Some(y)) => s.collect_str(&format_args!("a{}[{}]", x, y)),
            Key::Arg(x, None) => s.collect_str(&format_args!("a{}", x)),
            Key::ArgLen(x) => s.collect_str(&format_args!("a{}_len", x)),
            Key::Name(r) | Key::NameUID(r) | Key::NameGID(r) => {
                // safety: The parser guarantees an ASCII-only key.
                s.collect_str(unsafe { str::from_utf8_unchecked(r) })
            }
            Key::Common(c) => s.collect_str(&format_args!("{}", c)),
            Key::NameTranslated(r) => {
                // safety: The parser guarantees an ASCII-only key.
                s.collect_str(&str::to_ascii_uppercase(unsafe {
                    str::from_utf8_unchecked(r)
                }))
            }
            Key::Literal(l) => s.collect_str(l),
        }
    }
}

impl PartialEq<str> for Key {
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<[u8]> for Key {
    fn eq(&self, other: &[u8]) -> bool {
        match self {
            Key::Name(r) | Key::NameUID(r) | Key::NameGID(r) => r.as_ref() == other,
            _ => self.to_string().as_bytes() == other,
        }
    }
}

impl From<&'static str> for Key {
    fn from(value: &'static str) -> Self {
        Self::Literal(value)
    }
}

impl From<&[u8]> for Key {
    fn from(value: &[u8]) -> Self {
        Self::Name(NVec::from(value))
    }
}

/// Quotes in [`Value`] strings
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Quote {
    None,
    Single,
    Double,
    Braces,
}

#[derive(Clone)]
pub enum Number {
    Hex(u64),
    Dec(i64),
    Oct(u64),
}

impl Debug for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Num:<{}>", self)
    }
}

impl Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Number::Hex(n) => write!(f, "0x{:x}", n),
            Number::Dec(n) => write!(f, "{}", n),
            Number::Oct(n) => write!(f, "0o{:o}", n),
        }
    }
}

impl Serialize for Number {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Number::Dec(n) => s.serialize_i64(*n),
            _ => s.collect_str(&format_args!("{}", self)),
        }
    }
}

/// Representation of the value part of key/value pairs in [`Record`]
#[derive(Clone)]
pub enum Value<'a> {
    Empty,
    Str(&'a [u8], Quote),
    /// Segments are generated in Coalesce::normalize() from `EXECVE`
    /// / `aX[Y]` fragments.
    Segments(Vec<&'a [u8]>),
    /// Lists are generated in Coalesce::normalize() e.g.: `EXECVE` /
    /// `a0`, `a1`, `a2` … -> `ARGV`
    List(Vec<Value<'a>>),
    StringifiedList(Vec<Value<'a>>),
    /// Key/Value map, used in ENV (environment variables) list
    Map(Vec<(Key, Value<'a>)>),
    /// Values generated in parse() from unquoted Str values
    ///
    /// For example, `SYSCALL` / `a0` etc are interpreted as
    /// hexadecimal numbers.
    Number(Number),
    /// Elements removed from ARGV lists
    Skipped((usize, usize)),
    Literal(&'static str),
    Owned(Vec<u8>),
}

impl Default for Value<'_> {
    fn default() -> Self {
        Self::Empty
    }
}

impl Value<'_> {
    pub fn str_len(&self) -> usize {
        match self {
            Value::Str(r, _) => r.len(),
            Value::Segments(vr) => vr.iter().map(|r| r.len()).sum(),
            _ => 0,
        }
    }
}

/// List of [`Key`]/[`Value`] pairs, that are, for the most part,
/// stored offsets into the raw log line.
pub struct Record<'a> {
    elems: Vec<(Key, Value<'a>)>,
    arena: Vec<Vec<u8>>,
    _pin: std::marker::PhantomPinned,
}

impl Default for Record<'_> {
    fn default() -> Self {
        Record {
            elems: Vec::with_capacity(8),
            arena: vec![],
            _pin: std::marker::PhantomPinned,
        }
    }
}

impl Debug for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut seq = f.debug_struct("Record");
        for (k, v) in self {
            seq.field(&k.to_string(), &v);
        }
        seq.finish()
    }
}

impl Serialize for Record<'_> {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for (k, v) in self.into_iter() {
            match k {
                Key::Arg(_, _) | Key::ArgLen(_) => continue,
                _ => map.serialize_entry(&k, &v)?,
            }
        }
        map.end()
    }
}

impl<'a> Record<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(len: usize) -> Self {
        Self {
            elems: Vec::with_capacity(len),
            ..Self::default()
        }
    }

    fn add_slice<'i>(&mut self, input: &'i [u8]) -> &'a [u8]
    where
        'a: 'i,
    {
        let ilen = input.len();

        // let changed_buf: &Vec<u8>;
        for buf in self.arena.iter() {
            let Range { start, end } = input.as_ptr_range();
            if buf.as_slice().as_ptr_range().contains(&start)
                && buf.as_slice().as_ptr_range().contains(&end)
            {
                let s = std::ptr::slice_from_raw_parts(start, ilen);
                return unsafe { &*s };
            }
        }
        for buf in self.arena.iter_mut() {
            if buf.capacity() - buf.len() > ilen {
                let e = buf.len();
                buf.extend(input);
                let s = std::ptr::slice_from_raw_parts(buf[e..].as_ptr(), ilen);
                return unsafe { &*s };
            }
        }
        self.arena
            .push(Vec::with_capacity(1014 * (1 + (ilen / 1024))));
        let i = self.arena.len() - 1;
        let new_buf = &mut self.arena[i];
        new_buf.extend(input);
        let s = std::ptr::slice_from_raw_parts(new_buf[..].as_ptr(), ilen);
        unsafe { &*s }
    }

    fn add_value<'i>(&mut self, v: Value<'i>) -> Value<'a>
    where
        'a: 'i,
    {
        match v {
            Value::Str(s, q) => Value::Str(self.add_slice(s), q),
            Value::Owned(s) => Value::Str(self.add_slice(s.as_slice()), Quote::None),
            Value::List(vs) => Value::List(vs.into_iter().map(|v| self.add_value(v)).collect()),
            Value::StringifiedList(vs) => {
                Value::StringifiedList(vs.into_iter().map(|v| self.add_value(v)).collect())
            }
            Value::Segments(vs) => {
                let vs = vs.iter().map(|s| self.add_slice(s)).collect();
                Value::Segments(vs)
            }
            Value::Map(vs) => Value::Map(
                vs.into_iter()
                    .map(|(k, v)| (k, self.add_value(v)))
                    .collect(),
            ),
            // safety: These enum variants are self-contained.
            Value::Empty | Value::Literal(_) | Value::Number(_) | Value::Skipped(_) => unsafe {
                std::mem::transmute::<Value<'i>, Value<'a>>(v)
            },
        }
    }

    pub fn reserve(&mut self, additional: usize) {
        self.elems.reserve(additional);
    }

    pub fn push(&mut self, kv: (Key, Value)) {
        let (k, v) = kv;
        let v = self.add_value(v);
        self.elems.push((k, v));
    }

    pub fn len(&self) -> usize {
        self.elems.len()
    }

    pub fn is_empty(&self) -> bool {
        self.elems.is_empty()
    }

    pub fn retain<F>(&mut self, f: F)
    where
        F: FnMut(&(Key, Value<'a>)) -> bool,
    {
        self.elems.retain(f)
    }

    /// Merges two Records into one
    pub fn concat(&mut self, other: Self) {
        self.arena.extend(other.arena);
        self.elems.reserve(other.elems.len());
        for (k, v) in other.elems {
            self.push((k, v));
        }
    }

    /// Retrieves the first value found for a given key
    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Option<&Value> {
        let key = key.as_ref();
        self.elems.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

/*
impl<'a> Extend<(Key, Value<'a>)> for Record<'_> {
    fn extend<T: IntoIterator<Item = (Key, Value<'a>)>>(&mut self, iter: T) {
        todo!()
    }
}
*/

impl Clone for Record<'_> {
    fn clone(&self) -> Self {
        let mut new = Record::default();
        self.into_iter()
            .cloned()
            .for_each(|(k, v)| new.push((k, v)));
        new
    }
}

impl<'a> IntoIterator for &'a Record<'a> {
    type Item = &'a (Key, Value<'a>);
    type IntoIter = std::slice::Iter<'a, (Key, Value<'a>)>;
    fn into_iter(self) -> Self::IntoIter {
        self.elems.iter()
    }
}

impl TryFrom<Value<'_>> for Vec<u8> {
    type Error = &'static str;
    fn try_from(v: Value) -> Result<Self, Self::Error> {
        match v {
            Value::Str(r, Quote::Braces) => {
                let mut s = Vec::with_capacity(r.len() + 2);
                s.push(b'{');
                s.extend(Vec::from(r));
                s.push(b'}');
                Ok(s)
            }
            Value::Str(r, _) => Ok(Vec::from(r)),
            Value::Empty => Ok("".into()),
            Value::Segments(ranges) => {
                let l = ranges.iter().map(|r| r.len()).sum();
                let mut sb = Vec::with_capacity(l);
                for r in ranges {
                    sb.extend(Vec::from(r));
                }
                Ok(sb)
            }
            Value::Number(_) => Err("Won't convert number to string"),
            Value::List(_) | Value::StringifiedList(_) => Err("Can't convert list to scalar"),
            Value::Map(_) => Err("Can't convert map to scalar"),
            Value::Skipped(_) => Err("Can't convert skipped to scalar"),
            Value::Literal(s) => Ok(s.to_string().into()),
            Value::Owned(v) => Ok(v),
        }
    }
}

impl TryFrom<Value<'_>> for Vec<Vec<u8>> {
    type Error = &'static str;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::List(values) | Value::StringifiedList(values) => {
                let mut rv = Vec::with_capacity(values.len());
                for v in values {
                    let s = Vec::try_from(v)?;
                    rv.push(s);
                }
                Ok(rv)
            }
            _ => Err("not a list"),
        }
    }
}

impl Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(r, _q) => write!(f, "Str:<{}>", &String::from_utf8_lossy(r)),
            Value::Empty => write!(f, "Empty"),
            Value::Segments(segs) => {
                write!(f, "Segments<")?;
                for (n, r) in segs.iter().enumerate() {
                    if n > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", String::from_utf8_lossy(r))?;
                }
                write!(f, ">")
            }
            Value::List(vs) => {
                write!(f, "List:<")?;
                for (n, v) in vs.iter().enumerate() {
                    if n > 0 {
                        write!(f, ", ")?;
                    }
                    match v {
                        Value::Str(r, _) => {
                            write!(f, "{}", String::from_utf8_lossy(r))?;
                        }
                        Value::Segments(rs) => {
                            for r in rs {
                                write!(f, "{}", String::from_utf8_lossy(r))?;
                            }
                        }
                        Value::Number(n) => write!(f, "{:?}", n)?,
                        Value::Skipped(n) => {
                            write!(f, "Skip<elems{} bytes={}>", n.0, n.1)?;
                        }
                        Value::Empty => panic!("list can't contain empty value"),
                        Value::List(_) | Value::StringifiedList(_) => {
                            panic!("list can't contain list")
                        }
                        Value::Map(_) => panic!("list can't contain map"),
                        Value::Literal(v) => write!(f, "{:?}", v)?,
                        Value::Owned(v) => write!(f, "{}", String::from_utf8_lossy(v))?,
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
                            write!(f, "{}", String::from_utf8_lossy(r))?;
                        }
                        Value::Segments(rs) => {
                            for r in rs {
                                write!(f, "{}", String::from_utf8_lossy(r))?;
                            }
                        }
                        Value::Number(n) => write!(f, "{:?}", n)?,
                        Value::Skipped(n) => {
                            write!(f, "Skip<elems={} bytes={}>", n.0, n.1)?;
                        }
                        Value::Empty => panic!("list can't contain empty value"),
                        Value::List(_) | Value::StringifiedList(_) => {
                            panic!("list can't contain list")
                        }
                        Value::Map(_) => panic!("List can't contain mapr"),
                        Value::Literal(v) => write!(f, "{}", v)?,
                        Value::Owned(v) => write!(f, "{}", String::from_utf8_lossy(v))?,
                    }
                }
                write!(f, ">")
            }
            Value::Map(vs) => {
                write!(f, "Map:<")?;
                for (n, v) in vs.iter().enumerate() {
                    if n > 0 {
                        write!(f, " ")?;
                    }
                    let v = match &v.1 {
                        Value::Str(r, _q) => String::from_utf8_lossy(r).into(),
                        Value::Number(n) => format!("{:?}", n),
                        _ => todo!(),
                    };
                    write!(f, "{}={}", n, v)?;
                }
                write!(f, ">")
            }
            Value::Number(n) => write!(f, "{:?}", n),
            Value::Skipped(n) => write!(f, "Skip<elems={} bytes={}>", n.0, n.1),
            Value::Literal(s) => write!(f, "{:?}", s),
            Value::Owned(v) => write!(f, "{}", String::from_utf8_lossy(v)),
        }
    }
}

impl Serialize for Value<'_> {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Empty => s.serialize_none(),
            Value::Str(r, q) => {
                let (q1, q2) = if let Quote::Braces = q {
                    ("{", "}")
                } else {
                    ("", "")
                };
                s.collect_str(&format_args!("{}{}{}", q1, r.to_quoted_string(), q2))
            }
            Value::Segments(segs) => {
                let l = segs.iter().map(|r| r.len()).sum();
                let mut sb = String::with_capacity(l);
                for seg in segs {
                    sb.push_str(&seg.to_quoted_string());
                }
                s.collect_str(&sb)
            }
            Value::List(vs) => s.collect_seq(vs.iter()),
            Value::StringifiedList(vs) => {
                let mut buf: Vec<u8> = Vec::with_capacity(vs.len());
                let mut first = true;
                for v in vs {
                    if first {
                        first = false;
                    } else {
                        buf.push(b' ');
                    }
                    if let Value::Skipped((args, bytes)) = v {
                        buf.extend(
                            format!("<<< Skipped: args={}, bytes={} >>>", args, bytes).bytes(),
                        );
                    } else {
                        buf.extend(v.clone().try_into().unwrap_or_else(|_| vec![b'x']));
                    }
                }
                s.serialize_str(&buf.to_quoted_string())
            }
            Value::Number(n) => n.serialize(s),
            Value::Map(vs) => {
                let mut map = s.serialize_map(Some(vs.len()))?;
                for (k, v) in vs {
                    match k {
                        Key::Name(n) => map.serialize_key(&n.as_slice().to_quoted_string())?,
                        Key::Literal(n) => map.serialize_key(n)?,
                        _ => todo!(),
                    }
                    match v {
                        Value::Str(r, _q) => map.serialize_value(&r.to_quoted_string())?,
                        Value::Number(n) => map.serialize_value(&n)?,
                        _ => todo!(),
                    }
                }
                map.end()
            }
            Value::Skipped((args, bytes)) => {
                let mut map = s.serialize_map(Some(2))?;
                map.serialize_entry("skipped_args", args)?;
                map.serialize_entry("skipped_bytes", bytes)?;
                map.end()
            }
            Value::Literal(v) => s.collect_str(v),
            Value::Owned(v) => s.collect_str(&v.to_quoted_string()),
        }
    }
}

impl PartialEq<str> for Value<'_> {
    fn eq(&self, other: &str) -> bool {
        self == other.as_bytes()
    }
}

impl PartialEq<[u8]> for Value<'_> {
    fn eq(&self, other: &[u8]) -> bool {
        match self {
            Value::Empty => other.is_empty(),
            Value::Str(r, _) => r == &other,
            Value::Segments(segs) => {
                let l = segs.iter().map(|s| s.len()).sum();
                let mut buf: Vec<u8> = Vec::with_capacity(l);
                for s in segs {
                    buf.extend(*s);
                }
                buf == other
            }
            Value::Literal(s) => s.as_bytes() == other,
            Value::Owned(v) => v == other,
            Value::List(_)
            | Value::StringifiedList(_)
            | Value::Map(_)
            | Value::Skipped(_)
            | Value::Number(_) => false,
        }
    }
}

impl<'a> From<&'a [u8]> for Value<'a> {
    fn from(value: &'a [u8]) -> Self {
        Value::Str(value, Quote::None)
    }
}

impl<'a> From<&'a str> for Value<'a> {
    fn from(value: &'a str) -> Self {
        Self::from(value.as_bytes())
    }
}

impl From<Vec<u8>> for Value<'_> {
    fn from(value: Vec<u8>) -> Self {
        Value::Owned(value)
    }
}

impl From<String> for Value<'_> {
    fn from(value: String) -> Self {
        Self::from(Vec::from(value))
    }
}

impl From<i64> for Value<'_> {
    fn from(value: i64) -> Self {
        Value::Number(Number::Dec(value))
    }
}

/// The Offset trait provides an implementation for adding offset to Range.
trait Offset {
    fn offset(&self, offset: usize) -> Self;
}

impl Offset for Range<usize> {
    fn offset(&self, offset: usize) -> Self {
        Range {
            start: self.start + offset,
            end: self.end + offset,
        }
    }
}
