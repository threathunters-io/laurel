use std::{
    fmt,
    io::{self, Read, Write},
};

use serde::de;

use crate::quote::*;

/// A Formatter for serde_josn that outputs byte buffers as
/// URI-encodeed strings.
#[derive(Clone, Debug)]
pub struct SpecialFormatter;

impl serde_json::ser::Formatter for SpecialFormatter {
    fn write_byte_array<W>(&mut self, writer: &mut W, value: &[u8]) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.begin_string(writer)?;
        URIEscapeWriter(&mut BackslashEscapeWriter(writer))
            .write(value)
            .map(|_| ())?;
        self.end_string(writer)
    }
}

pub fn to_writer<W, T>(writer: W, value: &T) -> serde_json::Result<()>
where
    W: Write,
    T: ?Sized + serde::Serialize,
{
    let mut ser = serde_json::Serializer::with_formatter(writer, SpecialFormatter);
    value.serialize(&mut ser)
}

struct Deserializer<R: Read>(serde_json::Deserializer<serde_json::de::IoRead<R>>);

impl<R: Read> Deserializer<R> {
    fn new(reader: R) -> Self {
        Deserializer(serde_json::Deserializer::from_reader(reader))
    }
}

macro_rules! forward {
    ($method:ident ( $($var:ident: $ty:ty),* )  ) => {
        fn $method<V>(self $(, $var : $ty)* , visitor: V) -> serde_json::Result<V::Value>
        where
            V: de::Visitor<'de>,
        {
            self.0.$method($($var ,)* visitor)
        }
    };
}

macro_rules! forward_trivial {
    ( $($method:ident),* ) => {
        $(
            fn $method<V>(self, visitor: V) -> serde_json::Result<V::Value>
            where
                V: de::Visitor<'de>,
            {
                self.0.$method(visitor)
            }
        )*
    }
}

use std::marker::PhantomData;

struct BytesVisitor<'de, V: de::Visitor<'de>>(V, PhantomData<&'de ()>);

impl<'de, V> de::Visitor<'de> for BytesVisitor<'de, V>
where
    V: de::Visitor<'de>,
{
    type Value = <V as de::Visitor<'de>>::Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string containing vaild percent-escape expressions")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let mut decoded = vec![];
        let mut input = v.iter();

        while let Some(c) = input.next() {
            decoded.push(*c);
            if *c == b'%' {
                let x1 = input
                    .next()
                    .ok_or_else(|| de::Error::custom("unexpected end of string".to_string()))?;
                let x2 = input
                    .next()
                    .ok_or_else(|| de::Error::custom("unexpected end of string".to_string()))?;
                let idx = decoded.len() - 1;
                faster_hex::hex_decode(&[*x1, *x2], &mut decoded[idx..=idx])
                    .map_err(de::Error::custom)?;
            }
        }

        self.0.visit_bytes(&decoded)
    }
}

impl<'de, R: Read> de::Deserializer<'de> for &mut Deserializer<R> {
    type Error = serde_json::Error;

    forward_trivial! {
        deserialize_any,
        deserialize_bool,
        deserialize_f32, deserialize_f64,
        deserialize_char, deserialize_str, deserialize_string,
        deserialize_option,
        deserialize_unit,
        deserialize_u8, deserialize_u16, deserialize_u32, deserialize_u64, deserialize_u128,
        deserialize_i8, deserialize_i16, deserialize_i32, deserialize_i64, deserialize_i128,
        deserialize_seq, deserialize_map,
        deserialize_identifier,
        deserialize_ignored_any
    }

    forward! {deserialize_unit_struct ( name: &'static str ) }
    forward! {deserialize_newtype_struct ( name: &'static str ) }
    forward! {deserialize_tuple ( len: usize ) }
    forward! {deserialize_tuple_struct ( name: &'static str, len: usize ) }
    forward! {deserialize_struct ( name: &'static str, fields: &'static [&'static str] ) }
    forward! {deserialize_enum ( name: &'static str, variants: &'static [&'static str] ) }

    fn deserialize_bytes<V>(self, visitor: V) -> serde_json::Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        // problem: we can't access peek
        self.0.deserialize_bytes(BytesVisitor(visitor, PhantomData))
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> serde_json::Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }
}

pub fn from_reader<'de, R, T>(reader: R) -> serde_json::Result<T>
where
    R: Read,
    T: de::Deserialize<'de>,
{
    let mut d = crate::json::Deserializer::new(reader);
    de::Deserialize::deserialize(&mut d)
}

#[cfg(test)]
mod test {
    use super::{from_reader, to_writer};

    fn ser(value: &[u8]) -> String {
        let mut buf = vec![];
        to_writer(&mut buf, serde_bytes::Bytes::new(value)).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn de(value: &str) -> serde_bytes::ByteBuf {
        from_reader(value.as_bytes()).unwrap()
    }

    #[test]
    fn json_serialize() {
        for (buf, serialized) in &[
            (&b" "[..], r#"" ""#),
            (&b"asdf"[..], r#""asdf""#),
            (&b"+"[..], r#""%2b""#),
            (&b"%"[..], r#""%25""#),
            (&b"+++"[..], r#""%2b%2b%2b""#),
            (&b"%%%"[..], r#""%25%25%25""#),
            (&b"%+%"[..], r#""%25%2b%25""#),
            (&b"\xc3\xa4"[..], r#""ä""#),
            (&b"\xe2\x82\xac"[..], r#""€""#),
            (&b"\xf0\x9f\x92\x96"[..], r#""💖""#),
            (&b"\xc3\xa4\xc3\xb6\xc3\xbc"[..], r#""äöü""#),
            (&b"abcd\xc3\xa4\xc3\xb6\xc3\xbcefgh"[..], r#""abcdäöüefgh""#),
            (&b"\xf0\x9f\x84\xbb\xf0\x9f\x84\xb0\xf0\x9f\x85\x84\xf0\x9f\x85\x81\xf0\x9f\x84\xb4\xf0\x9f\x84\xbb"[..], r#""🄻🄰🅄🅁🄴🄻""#),
            (&b"\xc3\xc3\xa4"[..], r#""%c3ä""#),
            (&b"\xf0\xf0\x9f\x92\x96"[..], r#""%f0💖""#),
            (&b"\xf0\x9f\xf0\x9f\x92\x96"[..], r#""%f0%9f💖""#),
            (&b"\xf0\x9f\x92\xf0\x9f\x92\x96"[..], r#""%f0%9f%92💖""#),

            (&b"\xed\xa0\x80"[..], r#""%ed%a0%80""#), // illegal surrogate codepoint 0xd800
            (&b"\xed\xa3\xbf"[..], r#""%ed%a3%bf""#), // illegal surrogate codepoint 0xd8ff
            (&b"\xed\xbf\xbf"[..], r#""%ed%bf%bf""#), // illegal surrogate codepoint 0xdfff
        ] {
            assert_eq!(ser(buf), *serialized);
            assert_eq!(*buf, *de(serialized));
        }
    }
}
