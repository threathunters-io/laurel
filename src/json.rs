use std::io::{Result, Write};

use crate::quote::*;

/// A Formatter for serde_josn that outputs byte buffers as
/// URI-encodeed strings.
#[derive(Clone, Debug)]
pub struct SpecialFormatter;

impl serde_json::ser::Formatter for SpecialFormatter {
    fn write_byte_array<W>(&mut self, writer: &mut W, value: &[u8]) -> Result<()>
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

#[cfg(test)]
mod test {
    use super::to_writer;
    use crate::types::Bytes;

    fn serialized(value: &[u8]) -> String {
        let mut buf = vec![];
        to_writer(&mut buf, &Bytes(value)).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn json_serialize() {
        for (buf, expected) in &[
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
            assert_eq!(serialized(buf), *expected);
        }
    }
}
