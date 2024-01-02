use std::convert::{From, TryFrom};
use std::ops::Range;
use std::str;

use crate::constants::*;
use crate::types::*;

use nom::{
    branch::*, bytes::complete::*, character::complete::*, character::*, combinator::*, multi::*,
    sequence::*, IResult, Offset,
};

use nom::character::complete::{i64 as dec_i64, u16 as dec_u16, u32 as dec_u32, u64 as dec_u64};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("cannot parse header: {}", String::from_utf8_lossy(.0))]
    MalformedHeader(Vec<u8>),
    #[error("cannot parse body: {}", String::from_utf8_lossy(.0))]
    MalformedBody(Vec<u8>),
    #[error("garbage at end of message: {}", String::from_utf8_lossy(.0))]
    TrailingGarbage(Vec<u8>),
    #[error("{id} ({ty}) can't hex-decode {}", String::from_utf8_lossy(.hex_str))]
    HexDecodeError {
        ty: MessageType,
        id: EventID,
        hex_str: Vec<u8>,
    },
}

/// Parse a single log line as produced by _auditd(8)_
///
/// If `skip_enriched` is set and _auditd_ has been configured to
/// produce `log_format=ENRICHED` logs, i.e. to resolve uid, gid,
/// syscall, arch, sockaddr fields, those resolved values are dropped
/// by the parser.
#[allow(clippy::type_complexity)]
pub fn parse(
    mut raw: Vec<u8>,
    skip_enriched: bool,
) -> Result<(Option<Vec<u8>>, MessageType, EventID, Record), ParseError> {
    let (rest, (nd, ty, id)) =
        parse_header(&raw).map_err(|_| ParseError::MalformedHeader(raw.clone()))?;

    let (rest, body) = parse_body(rest, ty, skip_enriched)
        .map_err(|_| ParseError::MalformedBody(rest.to_vec()))?;

    if !rest.is_empty() {
        return Err(ParseError::TrailingGarbage(rest.to_vec()));
    }

    let nd = nd.map(|s| s.to_vec());

    let mut hex_strides = Vec::with_capacity(
        body.iter()
            .filter(|(_, v)| matches!(v, PValue::HexStr(_)))
            .count(),
    );

    let mut elems = Vec::with_capacity(body.len());

    for (k, v) in body {
        let v = match &v {
            PValue::Empty => Value::Empty,
            PValue::Number(n) => Value::Number(n.clone()),
            PValue::Str(s, q) => Value::Str(to_range(&raw, s), *q),
            PValue::List(vs) => Value::List(
                vs.iter()
                    .map(|s| Value::Str(to_range(&raw, s), Quote::None))
                    .collect::<Vec<_>>(),
            ),
            PValue::HexStr(s) => {
                // Record position of hex string. In-place Conversion
                // happens below.
                let o = raw.offset(s);
                hex_strides.push(o..o + s.len());
                Value::Str(o..o + s.len() / 2, Quote::None)
            }
        };
        elems.push((k, v));
    }

    for stride in hex_strides {
        for i in 0..stride.len() / 2 {
            // safety: The area to be hex-decoded has been recognized
            // as valid ASCII (and thus UTF-8) by the nom parser.
            let d = unsafe {
                str::from_utf8_unchecked(&raw[stride.start + 2 * i..stride.start + 2 * i + 2])
            };
            raw[stride.start + i] =
                u8::from_str_radix(d, 16).map_err(|_| ParseError::HexDecodeError {
                    id,
                    ty,
                    hex_str: raw[stride.clone()].to_vec(),
                })?;
        }
    }

    Ok((nd, ty, id, Record { elems, raw }))
}

#[inline(always)]
fn to_range(line: &[u8], subset: &[u8]) -> Range<usize> {
    let s = line.offset(subset);
    s..s + subset.len()
}

/// Recognize the header: node, type, event identifier
#[inline(always)]
#[allow(clippy::type_complexity)]
fn parse_header(input: &[u8]) -> IResult<&[u8], (Option<&[u8]>, MessageType, EventID)> {
    tuple((
        opt(terminated(parse_node, is_a(" "))),
        terminated(parse_type, is_a(" ")),
        parse_msgid,
    ))(input)
}

/// Recognize the node name
#[inline(always)]
fn parse_node(input: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(tag("node="), is_not(" \t\r\n"))(input)
}

/// Recognize event type
#[inline(always)]
fn parse_type(input: &[u8]) -> IResult<&[u8], MessageType> {
    preceded(
        tag("type="),
        alt((
            map_res(
                recognize(many1_count(alt((alphanumeric1, tag("_"))))),
                |s| {
                    EVENT_IDS
                        .get(s)
                        .ok_or(format!("unknown event id {}", String::from_utf8_lossy(s)))
                        .map(|n| MessageType(*n))
                },
            ),
            map(delimited(tag("UNKNOWN["), dec_u32, tag("]")), MessageType),
        )),
    )(input)
}

/// Recognize the "msg=audit(…):" event identifier
#[inline(always)]
fn parse_msgid(input: &[u8]) -> IResult<&[u8], EventID> {
    map(
        tuple((
            preceded(tag("msg=audit("), dec_u64),
            delimited(tag("."), dec_u64, tag(":")),
            terminated(dec_u32, pair(tag("):"), space0)),
        )),
        |(sec, msec, sequence)| EventID {
            timestamp: 1000 * sec + msec,
            sequence,
        },
    )(input)
}

#[derive(Clone)]
enum PValue<'a> {
    Empty,
    HexStr(&'a [u8]),
    Str(&'a [u8], Quote),
    List(Vec<&'a [u8]>),
    Number(Number),
}

/// Recognize the body: Multiple key/value pairs, with special cases
/// for some irregular messages
#[inline(always)]
fn parse_body(
    input: &[u8],
    ty: MessageType,
    skip_enriched: bool,
) -> IResult<&[u8], Vec<(Key, PValue)>> {
    // Handle some corner cases that don't fit the general key=value
    // scheme.
    let (input, special) = match ty {
        msg_type::AVC => opt(map(
            tuple((
                preceded(
                    pair(tag("avc:"), space0),
                    alt((tag("granted"), tag("denied"))),
                ),
                delimited(
                    tuple((space0, tag("{"), space0)),
                    many1(terminated(parse_identifier, space0)),
                    tuple((tag("}"), space0, tag("for"), space0)),
                ),
            )),
            |(k, v)| (Key::Name(NVec::from(k)), PValue::List(v)),
        ))(input)?,
        msg_type::TTY => {
            let (input, _) = opt(tag("tty "))(input)?;
            (input, None)
        }
        msg_type::MAC_POLICY_LOAD => {
            let (input, _) = opt(tag("policy loaded "))(input)?;
            (input, None)
        }
        _ => opt(map(
            terminated(tag("netlabel"), pair(tag(":"), space0)),
            |s| (Key::Name(NVec::from(s)), PValue::Empty),
        ))(input)?,
    };

    let (input, mut kv) = if skip_enriched {
        terminated(
            separated_list0(tag(b" "), |input| parse_kv(input, ty)),
            alt((
                value((), tuple((tag("\x1d"), many1(none_of("\n")), tag("\n")))),
                value((), tag("\n")),
            )),
        )(input)?
    } else {
        terminated(
            separated_list0(take_while1(|c| c == b' ' || c == b'\x1d'), |input| {
                parse_kv(input, ty)
            }),
            newline,
        )(input)?
    };

    if let Some(s) = special {
        kv.push(s)
    }

    Ok((input, kv))
}

/// Recognize one key/value pair
#[inline(always)]
fn parse_kv(input: &[u8], ty: MessageType) -> IResult<&[u8], (Key, PValue)> {
    let (input, key) = match ty {
        // Special case for execve arguments: aX, aX[Y], aX_len
        msg_type::EXECVE
            if !input.is_empty() && input[0] == b'a' && !input.starts_with(b"argc") =>
        {
            terminated(
                alt((parse_key_a_x_len, parse_key_a_xy, parse_key_a_x)),
                tag("="),
            )(input)
        }
        // Special case for syscall params: aX
        msg_type::SYSCALL => terminated(alt((parse_key_a_x, parse_key)), tag("="))(input),
        _ => terminated(parse_key, tag("="))(input),
    }?;

    let (input, value) = match (ty, &key) {
        (msg_type::SYSCALL, Key::Arg(_, None)) => map(
            recognize(terminated(
                many1_count(take_while1(is_hex_digit)),
                peek(take_while1(is_sep)),
            )),
            |s| {
                let ps = unsafe { str::from_utf8_unchecked(s) };
                match u64::from_str_radix(ps, 16) {
                    Ok(n) => PValue::Number(Number::Hex(n)),
                    Err(_) => PValue::Str(s, Quote::None),
                }
            },
        )(input)?,
        (msg_type::SYSCALL, Key::Common(c)) => parse_common(input, ty, *c)?,
        (msg_type::EXECVE, Key::Arg(_, _)) => parse_encoded(input)?,
        (msg_type::EXECVE, Key::ArgLen(_)) => parse_dec(input)?,
        (_, Key::Name(name)) => parse_named(input, ty, name)?,
        (_, Key::Common(c)) => parse_common(input, ty, *c)?,
        (_, Key::NameUID(name)) | (_, Key::NameGID(name)) => {
            alt((parse_dec, |input| parse_unspec_value(input, ty, name)))(input)?
        }
        _ => parse_encoded(input)?,
    };

    Ok((input, (key, value)))
}

#[inline(always)]
fn parse_named<'a>(input: &'a [u8], ty: MessageType, name: &[u8]) -> IResult<&'a [u8], PValue<'a>> {
    match FIELD_TYPES.get(name) {
        Some(&FieldType::Encoded) => {
            alt((parse_encoded, |input| parse_unspec_value(input, ty, name)))(input)
        }
        Some(&FieldType::NumericHex) => {
            alt((parse_hex, |input| parse_unspec_value(input, ty, name)))(input)
        }
        Some(&FieldType::NumericDec) => {
            alt((parse_dec, |input| parse_unspec_value(input, ty, name)))(input)
        }
        Some(&FieldType::NumericOct) => {
            alt((parse_oct, |input| parse_unspec_value(input, ty, name)))(input)
        }
        // FIXME: Some(&FieldType::Numeric)
        _ => alt((parse_encoded, |input| parse_unspec_value(input, ty, name)))(input),
    }
}

#[inline(always)]
fn parse_common(input: &[u8], ty: MessageType, c: Common) -> IResult<&[u8], PValue> {
    let name = <&str>::from(c).as_bytes();
    match c {
        Common::Arch => alt((parse_hex, |input| parse_unspec_value(input, ty, name)))(input),
        Common::Syscall
        | Common::Items
        | Common::Pid
        | Common::PPid
        | Common::Exit
        | Common::Ses => alt((parse_dec, |input| parse_unspec_value(input, ty, name)))(input),
        Common::Success | Common::Tty | Common::Comm | Common::Exe | Common::Subj | Common::Key => {
            alt((parse_encoded, |input| parse_unspec_value(input, ty, name)))(input)
        }
    }
}

/// Recognize encoded value:
///
/// May be double-quoted string, hex-encoded blob, (null), ?.
#[inline(always)]
fn parse_encoded(input: &[u8]) -> IResult<&[u8], PValue> {
    alt((
        map(parse_str_dq_safe, |s| PValue::Str(s, Quote::Double)),
        terminated(
            map(
                recognize(many1_count(take_while_m_n(2, 2, is_hex_digit))),
                PValue::HexStr,
            ),
            peek(take_while1(is_sep)),
        ),
        terminated(
            value(PValue::Empty, alt((tag("(null)"), tag("?")))),
            peek(take_while1(is_sep)),
        ),
    ))(input)
}

/// Recognize hexadecimal value
#[inline(always)]
fn parse_hex(input: &[u8]) -> IResult<&[u8], PValue> {
    map_res(
        terminated(take_while1(is_hex_digit), peek(take_while1(is_sep))),
        |digits| -> Result<_, std::num::ParseIntError> {
            let digits = unsafe { str::from_utf8_unchecked(digits) };
            Ok(PValue::Number(Number::Hex(u64::from_str_radix(
                digits, 16,
            )?)))
        },
    )(input)
}

/// Recognize decimal value
#[inline(always)]
fn parse_dec(input: &[u8]) -> IResult<&[u8], PValue> {
    map(terminated(dec_i64, peek(take_while1(is_sep))), |n| {
        PValue::Number(Number::Dec(n))
    })(input)
}

/// Recognize octal value
#[inline(always)]
fn parse_oct(input: &[u8]) -> IResult<&[u8], PValue> {
    map_res(
        terminated(take_while1(is_oct_digit), peek(take_while1(is_sep))),
        |digits| -> Result<_, std::num::ParseIntError> {
            let digits = unsafe { str::from_utf8_unchecked(digits) };
            Ok(PValue::Number(Number::Oct(u64::from_str_radix(digits, 8)?)))
        },
    )(input)
}

#[inline(always)]
fn parse_unspec_value<'a>(
    input: &'a [u8],
    ty: MessageType,
    name: &[u8],
) -> IResult<&'a [u8], PValue<'a>> {
    // work around apparent AppArmor breakage
    match (ty, name) {
        (_, b"subj") => {
            if let Ok((input, s)) = recognize(tuple((
                opt(tag("=")),
                parse_str_unq,
                opt(delimited(tag(" ("), parse_identifier, tag(")"))),
            )))(input)
            {
                return Ok((input, PValue::Str(s, Quote::None)));
            }
        }
        (msg_type::AVC, b"info") => {
            if let Ok((input, s)) = parse_str_dq(input) {
                return Ok((input, PValue::Str(s, Quote::None)));
            }
        }
        _ => (),
    };

    alt((
        terminated(
            map(take_while1(is_safe_unquoted_chr), |s| {
                PValue::Str(s, Quote::None)
            }),
            peek(take_while1(is_sep)),
        ),
        map(parse_kv_sq, |s| PValue::Str(s, Quote::Single)),
        map(parse_str_sq, |s| PValue::Str(s, Quote::Single)),
        map(parse_str_dq, |s| PValue::Str(s, Quote::Double)),
        map(parse_kv_braced, |s| PValue::Str(s, Quote::Braces)),
        map(parse_str_braced, |s| PValue::Str(s, Quote::Braces)),
        value(PValue::Empty, peek(take_while1(is_sep))),
    ))(input)
}

#[inline(always)]
fn parse_str_sq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("'"), take_while(|c| c != b'\''), tag("'"))(input)
}

#[inline(always)]
fn parse_str_dq_safe(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("\""), take_while(is_safe_chr), tag("\""))(input)
}

#[inline(always)]
fn parse_str_dq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("\""), take_while(|c| c != b'"'), tag("\""))(input)
}

#[inline(always)]
fn parse_str_braced(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(tag("{ "), take_until(" }"), tag(" }"))(input)
}

#[inline(always)]
fn parse_str_unq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(is_safe_chr)(input)
}

#[inline(always)]
fn parse_str_unq_inside_sq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    take_while(|c| is_safe_chr(c) && c != b'\'')(input)
}

/// More "correct" variant of parse_str_sq
#[inline(always)]
fn parse_kv_sq(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(
        tag("'"),
        recognize(separated_list0(
            tag(" "),
            tuple((
                recognize(pair(alpha1, many0_count(alt((alphanumeric1, is_a("-_")))))),
                tag("="),
                alt((parse_str_dq, parse_str_braced, parse_str_unq_inside_sq)),
            )),
        )),
        tag("'"),
    )(input)
}

/// More "correct" variant of parse_str_braced
#[inline(always)]
fn parse_kv_braced(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(
        tag("{ "),
        recognize(separated_list0(
            tag(" "),
            tuple((
                recognize(pair(alpha1, many0_count(alt((alphanumeric1, is_a("-_")))))),
                tag("="),
                alt((parse_str_sq, parse_str_dq, parse_str_unq)),
            )),
        )),
        tag(" }"),
    )(input)
}

/// Recognize regular keys of key/value pairs
#[inline(always)]
fn parse_key(input: &[u8]) -> IResult<&[u8], Key> {
    map(
        recognize(pair(alpha1, many0_count(alt((alphanumeric1, is_a("-_")))))),
        |s: &[u8]| {
            if let Ok(c) = Common::try_from(s) {
                Key::Common(c)
            } else if s.ends_with(b"uid") {
                Key::NameUID(NVec::from(s))
            } else if s.ends_with(b"gid") {
                Key::NameGID(NVec::from(s))
            } else {
                Key::Name(NVec::from(s))
            }
        },
    )(input)
}

/// Recognize length specifier for EXECVE split arguments, e.g. a1_len
#[inline(always)]
fn parse_key_a_x_len(input: &[u8]) -> IResult<&[u8], Key> {
    map(delimited(tag("a"), dec_u32, tag("_len")), Key::ArgLen)(input)
}

/// Recognize EXECVE split arguments, e.g. a1[3]
#[inline(always)]
fn parse_key_a_xy(input: &[u8]) -> IResult<&[u8], Key> {
    map(
        pair(
            preceded(tag("a"), dec_u32),
            delimited(tag("["), dec_u16, tag("]")),
        ),
        |(x, y)| Key::Arg(x, Some(y)),
    )(input)
}

/// Recognize SYSCALL, EXECVE regular argument keys, e.g. a1, a2, a3…
#[inline(always)]
fn parse_key_a_x(input: &[u8]) -> IResult<&[u8], Key> {
    map(preceded(tag("a"), u32), |x| Key::Arg(x, None))(input)
}

/// Recognize identifiers (used in some irregular messages)
/// Like [A-Za-z_][A-Za-z0-9_]*
#[inline(always)]
fn parse_identifier(input: &[u8]) -> IResult<&[u8], &[u8]> {
    recognize(pair(
        alt((alpha1, tag("_"))),
        many0_count(alt((alphanumeric1, tag("_")))),
    ))(input)
}

/// Characters permitted in kernel "encoded" strings that would
/// otherwise be hex-encoded.
#[inline(always)]
fn is_safe_chr(c: u8) -> bool {
    c == b'!' || (b'#'..=b'~').contains(&c)
}

/// Characters permitted in kernel "encoded" strings, minus
/// single-quotes, braces
#[inline(always)]
fn is_safe_unquoted_chr(c: u8) -> bool {
    (b'#'..=b'&').contains(&c) || (b'('..=b'z').contains(&c) || c == b'!' || c == b'|' || c == b'~'
}

/// Separator characters
#[inline(always)]
fn is_sep(c: u8) -> bool {
    c == b' ' || c == b'\x1d' || c == b'\n'
}

#[cfg(test)]
mod test {
    use super::msg_type::*;
    use super::*;

    fn do_parse<T>(text: T) -> Result<(Option<Vec<u8>>, MessageType, EventID, Record), ParseError>
    where
        T: AsRef<[u8]>,
    {
        parse(Vec::from(text.as_ref()), false)
    }

    #[test]
    fn parser() {
        // ensure that constant init works
        assert_eq!(format!("--{}--", EOE), "--EOE--");
        assert_eq!(format!("--{}--", MessageType(9999)), "--UNKNOWN[9999]--");

        let (_, t, id, _rv) = do_parse(include_bytes!("testdata/line-eoe.txt")).unwrap();
        assert_eq!(t, EOE);
        assert_eq!(
            id,
            EventID {
                timestamp: 1615225617302,
                sequence: 25836
            }
        );

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-syscall.txt")).unwrap();
        assert_eq!(t, SYSCALL);
        assert_eq!(
            id,
            EventID {
                timestamp: 1615114232375,
                sequence: 15558
            }
        );
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "arch: Num:<0xc000003e>",
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
            )
        );

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-execve.txt")).unwrap();
        assert_eq!(t, EXECVE);
        assert_eq!(
            id,
            EventID {
                timestamp: 1614788539386,
                sequence: 13232
            }
        );
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!("argc: Num:<0>", "a0: Str:<whoami>")
        );

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-path.txt")).unwrap();
        assert_eq!(t, PATH);
        assert_eq!(
            id,
            EventID {
                timestamp: 1614788539386,
                sequence: 13232
            }
        );
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "item: Num:<0>",
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
            )
        );

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-path-enriched.txt")).unwrap();
        assert_eq!(t, PATH);
        assert_eq!(
            id,
            EventID {
                timestamp: 1615113648978,
                sequence: 15219
            }
        );
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "item: Num:<1>",
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
            )
        );

        let (_, t, id, rv) = do_parse(include_bytes!("testdata/line-user-acct.txt")).unwrap();
        assert_eq!(t, USER_ACCT);
        assert_eq!(
            id,
            EventID {
                timestamp: 1615113648981,
                sequence: 15220
            }
        );
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
        assert_eq!(
            id,
            EventID {
                timestamp: 1626883065201,
                sequence: 216697
            }
        );

        let (_, t, _, rv) = do_parse(include_bytes!("testdata/line-avc-denied.txt")).unwrap();
        assert_eq!(t, AVC);
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "pid: Num:<15381>",
                "comm: Str:<laurel>",
                "capability: Num:<7>",
                "scontext: Str:<system_u:system_r:auditd_t:s0>",
                "tcontext: Str:<system_u:system_r:auditd_t:s0>",
                "tclass: Str:<capability>",
                "permissive: Num:<1>",
                "denied: List:<setuid>",
            )
        );

        let (_, t, _, rv) = do_parse(include_bytes!("testdata/line-avc-granted.txt")).unwrap();
        assert_eq!(t, AVC);
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "pid: Num:<11209>",
                "comm: Str:<tuned>",
                "scontext: Str:<system_u:system_r:tuned_t:s0>",
                "tcontext: Str:<system_u:object_r:security_t:s0>",
                "tclass: Str:<security>",
                "granted: List:<setsecparam>",
            )
        );

        let (_, t, _, rv) = do_parse(include_bytes!("testdata/line-netlabel.txt")).unwrap();
        assert_eq!(t, MAC_UNLBL_ALLOW);
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "auid: Num:<0>",
                "ses: Num:<0>",
                // FIXME: strings should be numbers
                "unlbl_accept: Str:<1>",
                "old: Str:<0>",
                "AUID: Str:<root>",
                "netlabel: Empty",
            )
        );

        let (_, _, _, rv) = do_parse(include_bytes!("testdata/line-broken-subj1.txt")).unwrap();
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "arch: Num:<0xc000003e>",
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
            )
        );

        let (_, _, _, rv) = do_parse(include_bytes!("testdata/line-broken-subj2.txt")).unwrap();
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
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
            )
        );

        let (_, _, _, rv) = do_parse(include_bytes!("testdata/line-broken-avc-info.txt")).unwrap();
        assert_eq!(
            rv.into_iter()
                .map(|(k, v)| format!("{:?}: {:?}", k, v))
                .collect::<Vec<_>>(),
            vec!(
                "apparmor: Str:<STATUS>",
                "operation: Str:<profile_replace>",
                "info: Str:<same as current profile, skipping>",
                "profile: Str:<unconfined>",
                "name: Str:<snap-update-ns.amazon-ssm-agent>",
                "pid: Num:<3981295>",
                "comm: Str:<apparmor_parser>",
            )
        );

        do_parse(include_bytes!("testdata/line-daemon-end.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-netfilter.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-anom-abend.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-anom-abend-2.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-user-auth.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-sockaddr-unix.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-sockaddr-unix-2.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-user-auth-2.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-mac-policy-load.txt")).unwrap();
        do_parse(include_bytes!("testdata/line-tty.txt")).unwrap();
    }

    #[test]
    #[should_panic]
    fn breakage_sockaddr_unknown() {
        do_parse(include_bytes!("testdata/line-sockaddr-unknown.txt")).unwrap();
    }
}
