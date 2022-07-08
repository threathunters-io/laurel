use std::str;

/// Format byte sequence as a string that is suitable for serializing
/// to the audit log
pub(crate) trait ToQuotedString {
    fn to_quoted_string(&self) -> String;
}

const HEXDIGITS: &[u8;16] = b"0123456789abcdef";

fn push_byte_quoted(sb: &mut Vec<u8>, byte: u8) {
    let byte = byte as usize;
    // safety: We have created a 3 byte ASCII string, i.e. valid Unicode.
    sb.extend(&[b'%', HEXDIGITS[byte >> 4], HEXDIGITS[byte & 15]] );
}

impl ToQuotedString for [u8] {
    fn to_quoted_string(self: &[u8]) -> String {
        let mut sb: Vec<u8> = Vec::with_capacity(self.len());
        // Are we currently inside a UTF-8 multibyte sequence?
        let mut utf8state: Option<u8> = None;
        let mut bytes = Vec::with_capacity(3);
        for c in self {
            loop {
                match utf8state {
                    None => {
                        let len: u8 =
                            if *c >= 32 && *c < 127 && *c != b'%' && *c != b'+' {
                                // simple byte, psuh as-is.
                                sb.push(*c);
                                break;
                            } else if *c & 0b11100000 == 0b11000000 {
                                1
                            } else if *c & 0b11110000 == 0b11100000 {
                                2
                            } else if *c & 0b11111000 == 0b11110000 {
                                3
                            } else {
                                // simple non-representable byte
                                push_byte_quoted(&mut sb, *c);
                                break;
                            };
                        bytes.clear();
                        bytes.push(*c);
                        utf8state = Some(len);
                        break;
                    },
                    Some(ref mut len) => {
                        if *c & 0b11000000 == 0b10000000 {
                            bytes.push(*c);
                            *len -= 1;
                            if *len == 0 {
                                match str::from_utf8(&bytes) {
                                    Ok(s) => sb.extend(s.bytes()),
                                    _ => bytes.iter().for_each(|c|push_byte_quoted(&mut sb, *c)),
                                }
                                utf8state = None;
                            }
                            break;
                        } else {
                            // incomplete UTF-8 multi-byte sequence,
                            // output collected bytes.
                            bytes.iter().for_each(|c|push_byte_quoted(&mut sb, *c));
                            utf8state = None;
                        }
                    }
                }
            }
        }
        if utf8state.is_some() {
            bytes.iter().for_each(|c|push_byte_quoted(&mut sb, *c));
        }
        // safety: We have verified that individual bytes and byte
        // sequences that were added were valid UTF-8 characters or
        // character sequences.
        unsafe { String::from_utf8_unchecked(sb) }
    }
}

#[cfg(test)]
mod test {
    use super::ToQuotedString;
    #[test]
    fn to_quoted_string() {
        assert_eq!(" ", b" ".to_quoted_string());
        assert_eq!("asdf", b"asdf".to_quoted_string());
        assert_eq!("%2b", b"+".to_quoted_string());
        assert_eq!("%25", b"%".to_quoted_string());
        assert_eq!("%2b%2b%2b", b"+++".to_quoted_string());
        assert_eq!("%25%25%25", b"%%%".to_quoted_string());
        assert_eq!("%25%2b%25", b"%+%".to_quoted_string());
        assert_eq!("ä", b"\xc3\xa4".to_quoted_string());
        assert_eq!("€", b"\xe2\x82\xac".to_quoted_string());
        assert_eq!("💖", b"\xf0\x9f\x92\x96".to_quoted_string());
        assert_eq!("äöü", b"\xc3\xa4\xc3\xb6\xc3\xbc".to_quoted_string());
        assert_eq!("abcdäöüefgh", b"abcd\xc3\xa4\xc3\xb6\xc3\xbcefgh".to_quoted_string());
        assert_eq!("🄻🄰🅄🅁🄴🄻", b"\xf0\x9f\x84\xbb\xf0\x9f\x84\xb0\xf0\x9f\x85\x84\xf0\x9f\x85\x81\xf0\x9f\x84\xb4\xf0\x9f\x84\xbb".to_quoted_string());
        assert_eq!("%c3ä", b"\xc3\xc3\xa4".to_quoted_string());
        assert_eq!("%f0💖", b"\xf0\xf0\x9f\x92\x96".to_quoted_string());
        assert_eq!("%f0%9f💖", b"\xf0\x9f\xf0\x9f\x92\x96".to_quoted_string());
        assert_eq!("%f0%9f%92💖", b"\xf0\x9f\x92\xf0\x9f\x92\x96".to_quoted_string());
        // This will probably need some corner cases.
    }
}
