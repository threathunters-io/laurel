use std::str;

/// Format byte sequence as a string that is suitable for serializing
/// to the audit log
pub(crate) trait ToQuotedString {
    fn to_quoted_string(&self) -> String;
}

impl ToQuotedString for [u8] {
    fn to_quoted_string(self: &[u8]) -> String {
        let mut sb = String::with_capacity(self.len());
        let mut utf8state: Option<u8> = None;
        let mut bytes = Vec::with_capacity(3);
        for c in self {
            loop {
                match utf8state {
                    None => {
                        let l: u8 =
                            if *c >= 32 && *c < 127 && *c != b'%' && *c != b'+' {
                                sb.push(*c as char);
                                break;
                            } else if *c & 0b11100000 == 0b11000000 {
                                1
                            } else if *c & 0b11110000 == 0b11100000 {
                                2
                            } else if *c & 0b11111000 == 0b11110000 {
                                3
                            } else {
                                sb.push_str(&format!("%{:02x}", *c));
                                break;
                            };
                        bytes.clear();
                        bytes.push(*c);
                        utf8state = Some(l);
                        break;
                    },
                    Some(ref mut l) => {
                        if *c & 0b11000000 == 0b10000000 {
                            bytes.push(*c);
                            *l -= 1;
                            if *l == 0 {
                                match str::from_utf8(&bytes) {
                                    Ok(s) => sb.push_str(s),
                                    _ => bytes.iter().for_each(|c|sb.push_str(&format!("%{:02x}", c))),
                                }
                                utf8state = None;
                            }
                            break;
                        } else {
                            bytes.iter().for_each(|c|sb.push_str(&format!("%{:02x}", c)));
                            utf8state = None;
                            continue;
                        }
                    }
                }
            }
        }
        if utf8state.is_some() {
            bytes.iter().for_each(|c|sb.push_str(&format!("%{:02x}", c)));
        }
        sb
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
