use std::str::{self,FromStr};
use std::ops::Range;

use crate::constants::*;
use crate::types::*;

use nom::{IResult,
          Offset,
          branch::*,
          character::*,
          character::complete::*,
          bytes::complete::*,
          sequence::*,
          multi::*,
          combinator::*,
};

/// Parse a single log line as produced by _auditd(8)_
#[allow(clippy::type_complexity)]
pub fn parse(mut raw: Vec<u8>) -> Result<(Option<Vec<u8>>, MessageType, EventID, Record),String> {
    let (rest, (nd, ty, id)) = parse_header(&raw)
        .map_err(|e| format!("cannot parse header: {}", e.map_input(String::from_utf8_lossy)))?;

    let (rest, body) = parse_body(rest, ty)
        .map_err(|e| format!("cannot parse body: {}", e.map_input(String::from_utf8_lossy)))?;

    if !rest.is_empty() {
        return Err(format!("garbage at end of message: {}", String::from_utf8_lossy(rest)));
    }

    let nd = nd.map(|s| s.to_vec() );

    let mut hex_strides =
        Vec::with_capacity(body.iter()
                           .filter(|(_,v)| matches!(v, PValue::HexStr(_)))
                           .count());
    
    let mut elems = Vec::with_capacity(body.len());

    for (k,v) in body {
        let k = match &k {
            PKey::Name(s) => Key::Name(to_range(&raw, s)),
            PKey::NameUID(s) => Key::NameUID(to_range(&raw, s)),
            PKey::NameGID(s) => Key::NameGID(to_range(&raw, s)),
            PKey::Arg(x,y) => Key::Arg(*x,*y),
            PKey::ArgLen(x) => Key::ArgLen(*x),
        };
        let v = match &v {
            PValue::Empty => Value::Empty,
            PValue::Number(n) => Value::Number(n.clone()),
            PValue::Str(s,q) => Value::Str(to_range(&raw, s), *q),
            PValue::List(vs) => Value::List(
                vs.iter()
                    .map(|s| Value::Str(to_range(&raw, s), Quote::None) )
                    .collect::<Vec<_>>()),
            PValue::HexStr(s) => {
                // Record position of hex string. In-place Conversion
                // happens below.
                let o = raw.offset(s);
                hex_strides.push(o .. o+s.len());
                Value::Str(o .. o+s.len()/2, Quote::None)
            },
        };
        elems.push((k,v));
    }

    for stride in hex_strides {
        for i in 0 .. stride.len()/2 {
            // safety: The area to be hex-decoded has been recognized
            // as valid ASCII (and thus UTF-8) by the nom parser.
            let d = unsafe {
                str::from_utf8_unchecked(&raw[stride.start+2*i .. stride.start+2*i+2])
            };
            raw[stride.start+i] = u8::from_str_radix(d, 16)
                .map_err(|_| {
                    let hex_str = unsafe { str::from_utf8_unchecked(&raw[stride.clone()]) };
                    format!("{} ({}) can't hex-decode {}", id, ty, hex_str)
                })?;
        }
    }

    Ok((nd, ty, id, Record{elems, raw}))
}

#[inline(always)]
fn to_range(line: &[u8], subset: &[u8]) -> Range<usize> {
    let s = line.offset(subset);
    s .. s+subset.len()
}

/// Recognize the header: node, type, event identifier
#[inline(always)]
#[allow(clippy::type_complexity)]
fn parse_header(input: &[u8]) -> IResult<&[u8], (Option<&[u8]>, MessageType, EventID)> {
    tuple((
        opt(terminated(parse_node, is_a(" "))),
        terminated(parse_type, is_a(" ")),
        parse_msgid
    )) (input)
}

/// Recognize the node name
#[inline(always)]
fn parse_node(input: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag("node="), is_not(" \t\r\n")) (input)
}

/// Recognize event type
#[inline(always)]
fn parse_type(input: &[u8]) -> IResult<&[u8], MessageType> {
    preceded(
        tag("type="),
        alt((
            map_res(
                recognize(many1_count(alt((alphanumeric1,tag("_"))))),
                |s| EVENT_IDS.get(s)
                    .ok_or(format!("unknown event id {}",
                                   String::from_utf8_lossy(s)))
                    .map(|n|MessageType(*n))),
            map_res(
                delimited(tag("UNKNOWN["),
                          is_a("0123456789"),
                          tag("]")),
                |s| str::from_utf8(s).unwrap().parse::<u32>().map(MessageType))
        )) ) (input)
}

/// Recognize the "msg=audit(…):" event identifier
#[inline(always)]
fn parse_msgid(input: &[u8]) -> IResult<&[u8], EventID> {
    map_res(
        tuple((
            tag("msg=audit("),
            digit1,tag("."),digit1,tag(":"),digit1,tag("):"),take_while(is_space),
        )),
        |(_,sec,_,msec,_,seq,_,_)| -> Result<EventID,std::num::ParseIntError> {
            Ok(
                EventID{
                    // safety: captured strings contain only ASCII digits
                    timestamp: 1000 * unsafe { str::from_utf8_unchecked(sec) }.parse::<u64>()?
                        + unsafe { str::from_utf8_unchecked(msec) }.parse::<u64>()?,
                    sequence: unsafe { str::from_utf8_unchecked(seq) }.parse::<u32>()?,
                }
            )
        }) (input)
}

enum PKey<'a> {
    Name(&'a[u8]),
    NameUID(&'a[u8]),
    NameGID(&'a[u8]),
    /// `a0`, `a1`, `a2[0]`, `a2[1]`…
    Arg(u16, Option<u16>),
    /// `a0_len` …
    ArgLen(u16),
}

enum PValue<'a> {
    Empty,
    HexStr(&'a[u8]),
    Str(&'a[u8], Quote),
    List(Vec<&'a[u8]>),
    Number(Number),
}

/// Recognize the body: Multiple key/value pairs, with special cases
/// for some irregular messages
#[inline(always)]
fn parse_body(input: &[u8], ty: MessageType) -> IResult<&[u8], Vec<(PKey,PValue)>> {
    let (input, special) = opt(
        alt((
            map_res(
                tuple((
                    tuple((tag("avc:"),space0)),
                    alt((tag("granted"),tag("denied"))),
                    tuple((space0,tag("{"),space0)),
                    many1(terminated(parse_identifier,space0)),
                    tuple((tag("}"),space0,tag("for"),space0)),
                )),
                |(_,k,_,v,_)| -> Result<_,()> {
                    Ok((PKey::Name(k),PValue::List(v)))
                }
            ),
            map_res(
                tuple(( tag("netlabel"), tag(":"), space0 )),
                |(s,_,_)| -> Result<_,()> {
                    Ok((PKey::Name(s),PValue::Empty))
                }
            )
        ))) (input)?;

    let (input, mut kv) = terminated(
        separated_list0(
            take_while1( |c| c == b' ' || c == b'\x1d' ),
            |input| parse_kv(input,ty)
        ),
        newline) (input)?;

    if let Some(s) = special { kv.push(s) }

    Ok((input,kv))
}

/// Recognize one key/value pair
#[inline(always)]
fn parse_kv(input: &[u8], ty: MessageType) -> IResult<&[u8], (PKey, PValue)> {
    let (input, key) = match ty {
        // Special case for execve arguments: aX, aX[Y], aX_len
        msg_type::EXECVE if !input.is_empty() && input[0] == b'a' => terminated(
            alt((parse_key_a_x_len, parse_key_a_xy, parse_key_a_x, parse_key)),
            tag("=")) (input),
        // SYCALL: Special case for syscall params: aX
        msg_type::SYSCALL => terminated(
            alt((parse_key_a_x, parse_key)),
            tag("=")) (input),
        _ => terminated(parse_key, tag("=")) (input)
    }?;

    let (input, value) = match (ty,&key) {
        (msg_type::SYSCALL, PKey::Arg(_,None)) => {
            map_res(
                recognize(terminated(
                    many1_count(take_while1(is_hex_digit)),
                    peek(take_while1(is_sep)))
                ),
                |s| -> Result<_,()> {
                    let ps = unsafe { str::from_utf8_unchecked(s) };
                    match u64::from_str_radix(ps, 16) {
                        Ok(n) =>  Ok(PValue::Number(Number::Hex(n))),
                        Err(_) => Ok(PValue::Str(s, Quote::None)),
                    }
                }) (input)?
        },
        (msg_type::EXECVE, PKey::Arg(_,_)) =>
            parse_encoded (input)?,
        (msg_type::EXECVE, PKey::ArgLen(_)) =>
            parse_dec (input)?,
        (_, PKey::Name(name)) => {
            match FIELD_TYPES.get(name) {
                Some(&FieldType::Encoded) =>
                    alt((parse_encoded, |input| parse_unspec_value (input, ty, name))) (input)?,
                Some(&FieldType::NumericHex) =>
                    alt((parse_hex, |input| parse_unspec_value(input, ty, name))) (input)?,
                Some(&FieldType::NumericDec) =>
                    alt((parse_dec, |input| parse_unspec_value(input, ty, name))) (input)?,
                Some(&FieldType::NumericOct) => 
                    alt((parse_oct, |input| parse_unspec_value(input, ty, name))) (input)?,
                _ => alt((parse_encoded, |input| parse_unspec_value(input, ty, name))) (input)?
                // FIXME: Some(&FieldType::Numeric)
            }
        },
        (_, PKey::NameUID(name)) | (_, PKey::NameGID(name)) => {
            alt((parse_dec, |input| parse_unspec_value(input, ty, name))) (input)?
        },
        _ => parse_encoded (input)?,
    };

    Ok((input, (key, value)))
}

/// Recognize encoded value:
/// 
/// May be double-quoted string, hex-encoded blob, (null), ?.
#[inline(always)]
fn parse_encoded(input: &[u8]) -> IResult<&[u8], PValue> {
    alt((
        map_res(
            delimited(tag("\""), take_while(is_safe_chr), tag("\"")),
            |s| -> Result<_,()> {
                Ok(PValue::Str(s, Quote::Double))
            }
        ),
        map_res(
            terminated(
                recognize(many1_count(take_while_m_n(2, 2, is_hex_digit))),
                peek(take_while1(is_sep))
            ),
            |s| -> Result<_,()> { Ok(PValue::HexStr(s)) } ),
        map_res(
            terminated(
                alt((tag("(null)"),tag("?"))),
                peek(take_while1(is_sep))
            ),
            |_| -> Result<_,()> { Ok(PValue::Empty) } )
    )) (input)
}

/// Recognize hexadecimal value
#[inline(always)]
fn parse_hex(input: &[u8]) -> IResult<&[u8], PValue> {
    map_res(
        terminated(
            take_while1(is_hex_digit),
            peek(take_while1(is_sep)),
        ),
        |digits| -> Result<_,std::num::ParseIntError> {
            let digits = unsafe { str::from_utf8_unchecked(digits) };
            Ok(PValue::Number(Number::Hex(u64::from_str_radix(digits, 16)?)))
        }
    ) (input)
}

/// Recognize decimal value
#[inline(always)]
fn parse_dec(input: &[u8]) -> IResult<&[u8], PValue> {
    map_res(
        terminated(
            pair(opt(tag("-")),take_while1(is_digit)),
            peek(take_while1(is_sep)),
        ),
        |(sign,digits)| -> Result<_,std::num::ParseIntError> {
            let sign = if sign.is_some() { -1 } else { 1 };
            let digits = unsafe { str::from_utf8_unchecked(digits) };
            Ok(PValue::Number(Number::Dec(sign * i64::from_str(digits)?)))
        }
    ) (input)
}

/// Recognize octal value
#[inline(always)]
fn parse_oct(input: &[u8]) -> IResult<&[u8], PValue> {
    map_res(
        terminated(
            take_while1(is_oct_digit),
            peek(take_while1(is_sep)),
        ),
        |digits| -> Result<_,std::num::ParseIntError> {
            let digits = unsafe { str::from_utf8_unchecked(digits) };
            Ok(PValue::Number(Number::Oct(u64::from_str_radix(digits, 8)?)))
        }
    ) (input)
}

#[inline(always)]
fn parse_unspec_value<'a>(input: &'a[u8], ty: MessageType, name: &[u8]) -> IResult<&'a[u8], PValue<'a>> {
    // work around apparent AppArmor breakage
    match (ty, name) {
        (msg_type::SYSCALL, b"subj") =>
            if let Ok((input, s)) =
                recognize(
                    tuple((
                        opt(tag("=")),
                        take_while(is_safe_chr),
                        opt(delimited(tag(" ("), parse_identifier, tag(")"))),
                    ))) (input)
            {
                return Ok((input, PValue::Str(s, Quote::None)));
            }
        (msg_type::AVC, b"info") =>
            if let Ok((input, s)) =
                delimited::<_,_,_,_,(),_,_,_>(tag("\""), take_while(|c| c != b'"'), tag("\"") ) (input)
            {
                return Ok((input,PValue::Str(s, Quote::None)));
            },
        _ => ()
    };

    alt((
        map_res(
            terminated(
                take_while1(is_safe_unquoted_chr),
                peek(take_while1(is_sep))
            ),
            |s| -> Result<_,()> { Ok(PValue::Str(s, Quote::None)) }
        ),
        map_res(
            delimited(tag("'"), take_while(|c| c != b'\''), tag("'")),
            |s| -> Result<_,()> { Ok(PValue::Str(s, Quote::Single)) }
        ),
        map_res(
            delimited(tag("\""), take_while(|c| c != b'"'), tag("\"")),
            |s| -> Result<_,()> { Ok(PValue::Str(s, Quote::Double)) }
        ),
        map_res(
            delimited(tag("{"), take_while(|c| c != b'}'), tag("}")),
            |s| -> Result<_,()> { Ok(PValue::Str(s, Quote::Braces)) }
        ),
        map_res(
            peek(take_while1(is_sep)),
            |_| -> Result<_,()> { Ok(PValue::Empty) }
        ),
    )) (input)
}

/// Recognize regular keys of key/value pairs
#[inline(always)]
fn parse_key(input: &[u8]) -> IResult<&[u8], PKey> {
    map_res(
        recognize(pair(alpha1, many0_count(alt((alphanumeric1,is_a("-_")))))),
        |s: &[u8]| -> Result<_,()> {
            if s.ends_with(b"uid") {
                Ok(PKey::NameUID(s))
            } else if s.ends_with(b"gid") {
                Ok(PKey::NameGID(s))
            } else {
                Ok(PKey::Name(s))
            }
        }
    ) (input)
}

/// Recognize length specifier for EXECVE split arguments, e.g. a1_len
#[inline(always)]
fn parse_key_a_x_len(input: &[u8]) -> IResult<&[u8], PKey> {
    map_res(
        delimited(tag("a"), digit1, tag("_len")),
        |x| -> Result<_,std::num::ParseIntError> {
            let x = unsafe { str::from_utf8_unchecked(x) }.parse()?;
            Ok(PKey::ArgLen(x))
        }
    ) (input)
}

/// Recognize EXECVE split arguments, e.g. a1[3]
#[inline(always)]
fn parse_key_a_xy(input: &[u8]) -> IResult<&[u8],PKey> {
    map_res(
        tuple((tag("a"),digit1,tag("["),digit1,tag("]"))),
        |(_,x,_,y,_)| -> Result<PKey,std::num::ParseIntError> {
            let x = unsafe { str::from_utf8_unchecked(x) }.parse()?;
            let y = unsafe { str::from_utf8_unchecked(y) }.parse()?;
            Ok(PKey::Arg(x,Some(y)))
        }
    ) (input)
}

/// Recognize SYSCALL, EXECVE regular argument keys, e.g. a1, a2, a3…
#[inline(always)]
fn parse_key_a_x(input: &[u8]) -> IResult<&[u8],PKey> {
    map_res(
        preceded(tag("a"), digit1),
        |x| -> Result<PKey,std::num::ParseIntError> {
            let x = unsafe { str::from_utf8_unchecked(x) }.parse()?;
            Ok(PKey::Arg(x,None))
        }
    ) (input)
}

/// Recognize identifiers (used in some irregular messages)
/// Like [A-Za-z_][A-Za-z0-9_]*
#[inline(always)]
fn parse_identifier(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(
        pair(
            alt((alpha1, tag("_"))),
            many0_count(alt((alphanumeric1,tag("_"))))
        )
    ) (input)
}

/// Characters permitted in kernel "encoded" strings that would
/// otherwise be hex-encoded.
#[inline(always)]
fn is_safe_chr(c: u8) -> bool { c == b'!' || (b'#'..=b'~').contains(&c) }

/// Characters permitted in kernel "encoded" strings, minus
/// single-quotes, braces
#[inline(always)]
fn is_safe_unquoted_chr(c: u8) -> bool {
    (b'#'..=b'&').contains(&c) || (b'('..=b'z').contains(&c) ||
        c == b'!'|| c == b'|' || c == b'~'
}

/// Separator characters
#[inline(always)]
fn is_sep(c: u8) -> bool { c == b' ' || c == b'\x1d' || c == b'\n' }



#[cfg(test)]
mod test {
    use super::*;
    use super::msg_type::*;

    fn do_parse<T>(text: T) -> Result<(Option<Vec<u8>>, MessageType, EventID, Record),String>
    where T: AsRef<[u8]>,
    {
        parse(Vec::from(text.as_ref()))
    }

    #[test]
    fn parser() {
        // ensure that constant init works
        assert_eq!(format!("--{}--", EOE), "--EOE--");
        assert_eq!(format!("--{}--", MessageType(9999)), "--UNKNOWN[9999]--");

        let (_, t, id, _rv) = do_parse(include_bytes!("testdata/line-eoe.txt")).unwrap();
        assert_eq!(t, EOE);
        assert_eq!(id, EventID{timestamp: 1615225617302, sequence: 25836});

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-syscall.txt")).unwrap();
        assert_eq!(t, SYSCALL);
        assert_eq!(id, EventID{timestamp: 1615114232375, sequence: 15558});
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!("arch: Num:<0xc000003e>",
                        "syscall: Num:<59>",
                        "success: Str:<yes>",
                        "exit: Num:<0>",
                        "a0: Num:<0x63b29337fd18>",
                        "a1: Num:<0x63b293387d58>",
                        "a2: Num:<0x63b293375640>",
                        "a3: Num:<0xfffffffffffff000>",
                        "items: Num:<2>",
                        "ppid: Num:<10883>",
                        "pid: Num:<10884>",
                        "auid: Num:<1000>",
                        "uid: Num:<0>",
                        "gid: Num:<0>",
                        "euid: Num:<0>",
                        "suid: Num:<0>",
                        "fsuid: Num:<0>",
                        "egid: Num:<0>",
                        "sgid: Num:<0>",
                        "fsgid: Num:<0>",
                        "tty: Str:<pts1>",
                        "ses: Num:<1>",
                        "comm: Str:<whoami>",
                        "exe: Str:</usr/bin/whoami>",
                        "key: Empty",
                        "ARCH: Str:<x86_64>",
                        "SYSCALL: Str:<execve>",
                        "AUID: Str:<user>",
                        "UID: Str:<root>",
                        "GID: Str:<root>",
                        "EUID: Str:<root>",
                        "SUID: Str:<root>",
                        "FSUID: Str:<root>",
                        "EGID: Str:<root>",
                        "SGID: Str:<root>",
                        "FSGID: Str:<root>",
                   ));

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-execve.txt")).unwrap();
        assert_eq!(t, EXECVE);
        assert_eq!(id, EventID{timestamp: 1614788539386, sequence: 13232});
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!("argc: Num:<0>",
                        "a0: Str:<whoami>"));

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-path.txt")).unwrap();
        assert_eq!(t, PATH);
        assert_eq!(id, EventID{timestamp: 1614788539386, sequence: 13232});
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!("item: Num:<0>",
                        "name: Str:</usr/bin/whoami>",
                        "inode: Num:<261214>",
                        "dev: Str:<ca:03>",
                        "mode: Num:<0o100755>",
                        "ouid: Num:<0>",
                        "ogid: Num:<0>",
                        "rdev: Str:<00:00>",
                        "nametype: Str:<NORMAL>",
                        "cap_fp: Num:<0x0>",
                        "cap_fi: Num:<0x0>",
                        "cap_fe: Num:<0>",
                        "cap_fver: Num:<0x0>",
                   ));

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-path-enriched.txt")).unwrap();
        assert_eq!(t, PATH);
        assert_eq!(id, EventID{timestamp: 1615113648978, sequence: 15219});
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!("item: Num:<1>",
                        "name: Str:</lib64/ld-linux-x86-64.so.2>",
                        "inode: Num:<262146>",
                        "dev: Str:<ca:03>",
                        "mode: Num:<0o100755>",
                        "ouid: Num:<0>",
                        "ogid: Num:<0>",
                        "rdev: Str:<00:00>",
                        "nametype: Str:<NORMAL>",
                        "cap_fp: Num:<0x0>",
                        "cap_fi: Num:<0x0>",
                        "cap_fe: Num:<0>",
                        "cap_fver: Num:<0x0>",
                        "OUID: Str:<root>",
                        "OGID: Str:<root>",
                   ));

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-user-acct.txt")).unwrap();
        assert_eq!(t, USER_ACCT);
        assert_eq!(id, EventID{timestamp: 1615113648981, sequence: 15220});
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!("pid: Num:<9460>",
                        "uid: Num:<1000>",
                        "auid: Num:<1000>",
                        "ses: Num:<1>",
                        "msg: Str:<op=PAM:accounting grantors=pam_permit acct=\"user\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/1 res=success>",
                        "UID: Str:<user>",
                        "AUID: Str:<user>",
                   ));

        let (_, t, id, _) = do_parse(include_bytes!("testdata/line-unknown.txt")).unwrap();
        assert_eq!(t, BPF);
        assert_eq!(id, EventID{timestamp: 1626883065201, sequence: 216697});

        let (_, t, _, rv) = do_parse(include_bytes!("testdata/line-avc-denied.txt")).unwrap();
        assert_eq!(t, AVC);
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!(
                       "pid: Num:<15381>",
                       "comm: Str:<laurel>",
                       "capability: Num:<7>",
                       "scontext: Str:<system_u:system_r:auditd_t:s0>",
                       "tcontext: Str:<system_u:system_r:auditd_t:s0>",
                       "tclass: Str:<capability>",
                       "permissive: Num:<1>",
                       "denied: List:<setuid>",
                   ));

        let (_, t, _, rv) = do_parse(include_bytes!("testdata/line-avc-granted.txt")).unwrap();
        assert_eq!(t, AVC);
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!(
                       "pid: Num:<11209>",
                       "comm: Str:<tuned>",
                       "scontext: Str:<system_u:system_r:tuned_t:s0>",
                       "tcontext: Str:<system_u:object_r:security_t:s0>",
                       "tclass: Str:<security>",
                       "granted: List:<setsecparam>",
                   ));

        let (_, t, _, rv) = do_parse(include_bytes!("testdata/line-netlabel.txt")).unwrap();
        assert_eq!(t, MAC_UNLBL_ALLOW);
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!(
                       "auid: Num:<0>",
                       "ses: Num:<0>",
                       // FIXME: strings should be numbers
                       "unlbl_accept: Str:<1>",
                       "old: Str:<0>",
                       "AUID: Str:<root>",
                       "netlabel: Empty",
                   ));

        let (_,_,_, rv) = do_parse(include_bytes!("testdata/line-broken-subj1.txt")).unwrap();
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!("arch: Num:<0xc000003e>",
                        "syscall: Num:<59>",
                        "success: Str:<yes>",
                        "exit: Num:<0>",
                        "a0: Num:<0x55b26d44a6a0>",
                        "a1: Num:<0x55b26d44a878>",
                        "a2: Num:<0x55b26d44a8e8>",
                        "a3: Num:<0x7faeccab5850>",
                        "items: Num:<2>",
                        "ppid: Num:<659>",
                        "pid: Num:<661>",
                        "auid: Num:<4294967295>",
                        "uid: Num:<0>",
                        "gid: Num:<0>",
                        "euid: Num:<0>",
                        "suid: Num:<0>",
                        "fsuid: Num:<0>",
                        "egid: Num:<0>",
                        "sgid: Num:<0>",
                        "fsgid: Num:<0>",
                        "tty: Str:<(none)>",
                        "ses: Num:<4294967295>",
                        "comm: Str:<dhclient>",
                        "exe: Str:</sbin/dhclient>",
                        "subj: Str:</{,usr/}sbin/dhclient>",
                        "key: Empty",
                   ));

        let (_,_,_, rv) = do_parse(include_bytes!("testdata/line-broken-subj2.txt")).unwrap();
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!(
                       "arch: Num:<0xc000003e>",
                       "syscall: Num:<49>",
                       "success: Str:<yes>",
                       "exit: Num:<0>",
                       "a0: Num:<0x15>",
                       "a1: Num:<0x55c5e046e264>",
                       "a2: Num:<0x1c>",
                       "a3: Num:<0x7ffc8fab77ec>",
                       "items: Num:<0>",
                       "ppid: Num:<1899774>",
                       "pid: Num:<1899780>",
                       "auid: Num:<4294967295>",
                       "uid: Num:<0>",
                       "gid: Num:<0>",
                       "euid: Num:<0>",
                       "suid: Num:<0>",
                       "fsuid: Num:<0>",
                       "egid: Num:<0>",
                       "sgid: Num:<0>",
                       "fsgid: Num:<0>",
                       "tty: Str:<(none)>",
                       "ses: Num:<4294967295>",
                       "comm: Str:<ntpd>",
                       "exe: Str:</usr/sbin/ntpd>",
                       "subj: Str:<=/usr/sbin/ntpd (enforce)>",
                       "key: Empty",
                   ));

        let (_,_,_, rv) = do_parse(include_bytes!("testdata/line-broken-avc-info.txt")).unwrap();
        assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                   vec!(
                       "apparmor: Str:<STATUS>",
                       "operation: Str:<profile_replace>",
                       "info: Str:<same as current profile, skipping>",
                       "profile: Str:<unconfined>",
                       "name: Str:<snap-update-ns.amazon-ssm-agent>",
                       "pid: Num:<3981295>",
                       "comm: Str:<apparmor_parser>",
                   ));

        do_parse(include_bytes!("testdata/line-daemon-end.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-netfilter.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-anom-abend.txt")).unwrap();
    }
}
