use std::io::{Result, Write};

const HEXDIGITS: &[u8; 16] = b"0123456789abcdef";

/// Adapter that applies backslash-coding according to JSON rules to
/// the bytes written.
pub(crate) struct BackslashEscapeWriter<'a, W>(pub &'a mut W)
where
    W: ?Sized + Write;

impl<'a, W> Write for BackslashEscapeWriter<'a, W>
where
    W: ?Sized + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut quoted = [b'\\', b'u', b'0', b'0', b'0', b'0'];
        let mut start_unquoted = 0;
        for (n, c) in buf.iter().enumerate() {
            let quoted = match c {
                b'"' => &br#"\""#[..],
                b'\\' => &br#"\\"#[..],
                b'\x08' => &br#"\b"#[..],
                b'\x0c' => &br#"\f"#[..],
                b'\n' => &br#"\n"#[..],
                b'\r' => &br#"\r"#[..],
                b'\t' => &br#"\t"#[..],
                c if *c < 32 => {
                    quoted[4] = HEXDIGITS[((*c & 0xf0) >> 4) as usize];
                    quoted[5] = HEXDIGITS[(*c & 0x0f) as usize];
                    &quoted
                }
                _ => continue,
            };
            self.0.write_all(&buf[start_unquoted..n])?;
            self.0.write_all(quoted)?;
            start_unquoted = n + 1;
        }
        self.0.write_all(&buf[start_unquoted..])?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

fn write_quoted_byte<W>(writer: &mut W, value: u8) -> Result<()>
where
    W: ?Sized + Write,
{
    let value = value as usize;
    writer.write_all(&[b'%', HEXDIGITS[value >> 4], HEXDIGITS[value & 0x0f]])
}

/// Adapter that applies URI-escaping (except ' ' -> '+') to the bytes writen.
///
/// Printable ASCII characters except `%`, `+`, and `\b`, `\f`, `\n`,
/// `\r`, `\t` are left as-is.
///
/// This is the "inner" encoding of the JSON strings produced by Laurel.
pub(crate) struct URIEscapeWriter<'a, W>(pub &'a mut W)
where
    W: ?Sized + Write;

impl<'a, W> Write for URIEscapeWriter<'a, W>
where
    W: ?Sized + Write,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut utf8state: Option<u8> = None;
        let mut stash = tinyvec::array_vec!([u8; 4]);
        let mut start_unquoted = 0;
        for (n, c) in buf.iter().enumerate() {
            loop {
                match utf8state {
                    None => {
                        if *c >= 32
                            && *c < 127
                            && ![b'%', b'+', b'\x08', b'\x0c', b'\n', b'\r', b'\t'].contains(c)
                        {
                            // simple byte, collect to be output as-is.
                            break;
                        }
                        self.0.write_all(&buf[start_unquoted..n])?;
                        start_unquoted = n + 1;
                        let len = match *c {
                            n if n & 0b11100000 == 0b11000000 => 1,
                            n if n & 0b11110000 == 0b11100000 => 2,
                            n if n & 0b11111000 == 0b11110000 => 3,
                            _ => {
                                // simple non-representable byte
                                write_quoted_byte(self.0, *c)?;
                                break;
                            }
                        };
                        stash.clear();
                        stash.push(*c);
                        utf8state = Some(len);
                        break;
                    }
                    Some(ref mut len) => {
                        if *c & 0b11000000 == 0b10000000 {
                            start_unquoted = n + 1;
                            stash.push(*c);
                            *len -= 1;
                            // Complete UTF-8 multi-byte-sequence. Write.
                            if *len == 0 {
                                match std::str::from_utf8(&stash) {
                                    Ok(_) => self.0.write_all(&stash)?,
                                    _ => stash
                                        .iter()
                                        .try_for_each(|c| write_quoted_byte(self.0, *c))?,
                                }
                                utf8state = None;
                            }
                            break;
                        } else {
                            // Incomplete UTF-8 multi-byte sequence.
                            // Write and re-evaluate current byte.
                            stash
                                .iter()
                                .try_for_each(|c| write_quoted_byte(self.0, *c))?;
                            utf8state = None;
                        }
                    }
                }
            }
        }
        // invalid UTF-8 multi-byte-sequence at end of input.
        match utf8state {
            Some(_) => stash
                .iter()
                .try_for_each(|c| write_quoted_byte(self.0, *c))?,
            None => self.0.write_all(&buf[start_unquoted..])?,
        };
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<()> {
        self.0.flush()
    }
}

#[cfg(test)]
mod test {
    use super::URIEscapeWriter;
    use std::io::Write;

    fn uri_escaped(value: &[u8]) -> String {
        let mut buf = Vec::with_capacity(value.len());
        URIEscapeWriter(&mut buf).write(&value).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn uri_escape() {
        assert_eq!(" ", uri_escaped(b" "));
        assert_eq!("asdf", uri_escaped(b"asdf"));
        assert_eq!("%2b", uri_escaped(b"+"));
        assert_eq!("%25", uri_escaped(b"%"));
        assert_eq!("%2b%2b%2b", uri_escaped(b"+++"));
        assert_eq!("%25%25%25", uri_escaped(b"%%%"));
        assert_eq!("%25%2b%25", uri_escaped(b"%+%"));
        assert_eq!("ä", uri_escaped(b"\xc3\xa4"));
        assert_eq!("€", uri_escaped(b"\xe2\x82\xac"));
        assert_eq!("💖", uri_escaped(b"\xf0\x9f\x92\x96"));
        assert_eq!("äöü", uri_escaped(b"\xc3\xa4\xc3\xb6\xc3\xbc"));
        assert_eq!(
            "abcdäöüefgh",
            uri_escaped(b"abcd\xc3\xa4\xc3\xb6\xc3\xbcefgh")
        );
        assert_eq!("🄻🄰🅄🅁🄴🄻", uri_escaped(b"\xf0\x9f\x84\xbb\xf0\x9f\x84\xb0\xf0\x9f\x85\x84\xf0\x9f\x85\x81\xf0\x9f\x84\xb4\xf0\x9f\x84\xbb"));
        assert_eq!("%c3ä", uri_escaped(b"\xc3\xc3\xa4"));
        assert_eq!("%f0💖", uri_escaped(b"\xf0\xf0\x9f\x92\x96"));
        assert_eq!("%f0💖%f0", uri_escaped(b"\xf0\xf0\x9f\x92\x96\xf0"));
        assert_eq!("%f0💖asdf", uri_escaped(b"\xf0\xf0\x9f\x92\x96asdf"));
        assert_eq!("%f0%9f💖", uri_escaped(b"\xf0\x9f\xf0\x9f\x92\x96"));
        assert_eq!("%f0%9f%92💖", uri_escaped(b"\xf0\x9f\x92\xf0\x9f\x92\x96"));
        // This will probably need some corner cases.
    }
}
