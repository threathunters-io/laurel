use std::str::{self,FromStr};

use crate::constants::*;
use crate::types::*;

/// Parse a single log line as produced by _auditd(8)_
///
/// The parser is based around a parsing expression grammar that
/// understands quoted strings. Hex-encoded strings are properly
/// decoded.
pub fn parse(mut line: Vec<u8>) -> Result<(MessageType, EventID, Record),String> {
    let (typ, id, mut values) = audit_parser::record(&line[..]).map_err(|e|e.to_string())?;

    // Fix up SYSCALL aN arguments. They may have been recognized as
    // Str or HexStr and are converted to numbers here.
    if typ == msg_type::SYSCALL {
        for (k,v) in values.iter_mut() {
            if let Key::Arg(_, None) = k {
                let s = match v {
                    Value::Str(r, Quote::None) | Value::HexStr(r) => {
                        // safety: The parser guarantees an ASCII-only value.
                        unsafe { str::from_utf8_unchecked(&line[r.clone()]) }
                    }
                    _ => continue,
                };
                if let Ok(n) = u64::from_str_radix(&s, 16) {
                    *v = Value::Number(Number::Hex(n));
                }
            }
        }
    }

    // Convert hex strings contained in the line buffer in-place.
    for (k, v) in values.iter_mut() {
        match v {
            Value::HexStr(r) => {
                let mut digits = Vec::from(&line[r.clone()])
                    .into_iter()
                    .map(|c| match c {
                        b'0'..=b'9' => (c - b'0'),
                        b'A'..=b'F' => (c - b'A') + 10,
                        b'a'..=b'f' => (c - b'a') + 10,
                        _ => unreachable!(),
                    });
                let start = r.start as usize;
                for p in 0 .. r.len() / 2 {
                    if let (Some(hi), Some(lo)) = (digits.next(), digits.next()) {
                        line[start + p] = (hi<<4) + lo;
                    }
                }
                *v = Value::Str(r.start .. r.start + (r.end-r.start)/2, Quote::None);
            }
            Value::Str(vr, Quote::None) => {
                if let Key::Name(k) = k {
                    if let Some(typ) = FIELD_TYPES.get(&line[k.clone()]) {
                        let s : &[u8] = &line[vr.clone()];
                        // safety: The parser guarantees an ASCII-only value.
                        let s = unsafe { str::from_utf8_unchecked(s) };
                        match typ {
                            FieldType::NumericDec => {
                                if let Ok(n) = u64::from_str(&s) {
                                    *v = Value::Number(Number::Dec(n));
                                }
                            },
                            FieldType::NumericHex => {
                                if let Ok(n) = u64::from_str_radix(&s, 16) {
                                    *v = Value::Number(Number::Hex(n));
                                }
                            },
                            FieldType::NumericOct => {
                                if let Ok(n) = u64::from_str_radix(&s, 8) {
                                    *v = Value::Number(Number::Oct(n));
                                }
                            },
                            _ => (),
                        }
                    }
                }
            }
            _ => (),
        }
    }

    Ok((typ, id, Record{elems: values, raw: line}))
}

peg::parser!{
    grammar audit_parser() for [u8] {
        pub(super) rule record() -> (MessageType, EventID, Vec<(Key,Value)>) =
            ("node=" $([^b' ']+) " ")?
            "type=" t:typ() _
            "msg=audit(" s:number() "." ms:number() ":" seq:number() "):" _?
            kvs:((kv() ** _) **<,2> [b'\x1d'])
            "\n"
        {
            (
                t,
                EventID{timestamp: s*1000 + ms, sequence: seq as u32},
                kvs.into_iter().flatten().collect::<Vec<_>>(),
            )
        }

        // whitespace
        rule _ = " "+
        // "end of token" for positive lookahead usage.
        // Matches on whitespace and on "EOF".
        rule eot() = [b' '|0x1d|b'\n'] / ![_]
        // simple decimal number
        rule number() -> u64 = num:$([b'0'..=b'9']+) {
            let mut acc: u64 = 0;
            for digit in num.iter() {
                acc = acc * 10 + (*digit - b'0') as u64
            }
            acc
        }
        // EXECVE, SYSCALL, etc.
        rule typ() -> MessageType
            = "UNKNOWN[" n:number() "]"     { MessageType(n as u32) }
            / name:$( [b'A'..=b'Z'|b'_']+ ) { MessageType(EVENT_IDS[name]) }

        rule kvs() -> Vec<(Key, Value)> = kv() ** _

        rule key() -> (Key, Option<&'input[u8]>)
            = "a" x:number() "[" y:number() "]"
            { (Key::Arg(x as u16, Some(y as u16)), None) }
            / "a" x:number() "_len"
            { (Key::ArgLen(x as u16), None) }
            / "a" x:number()
            { (Key::Arg(x as u16, None), None) }
            / b:position!() name:ident() e:position!()
            { (Key::Name(b..e), Some(name)) }

        rule ident() -> &'input[u8] = $( [b'a'..=b'z'|b'A'..=b'Z']
                                         [b'a'..=b'z'|b'A'..=b'Z'|b'0'..=b'9'|b'_'|b'-']* )

        rule hex_string() -> &'input[u8] = $( ([b'0'..=b'9'|b'A'..=b'F']*<2>)+ )
        // all printable ASCII except <SPC> and double quote
        rule safestr() -> &'input[u8] = $( [b'!'|b'#'..=b'~']* )
        // ... and except single quote and braces
        rule safeunq() -> &'input[u8] = $( [b'!'|b'#'..=b'&'|b'('..=b'z'|b'|'|b'~']+ )

        rule kv() -> (Key, Value)
            // "encoded" string value
            = k:key() "=" b:position!() (hex_string()) e:position!() &eot() {
                match k {
                    (Key::Arg(_,_), _) =>  (k.0, Value::HexStr(b..e)),
                    (Key::Name(_), Some(name))
                        if FIELD_TYPES.get(name) == Some(&FieldType::Encoded)
                        => (k.0, Value::HexStr(b..e)),
                    (Key::Literal(_), _) => unreachable!(),
                    (_, _) => (k.0, Value::Str(b..e, Quote::None)),
                }
            }
            // special case for empty string, single "?", unquoted (null)
            / k:key() "=" ( "(null)" / "?" )? &eot() {
                (k.0, Value::Empty)
            }
            // regular "quoted" string
            / k:key() "=\"" b:position!() safestr()    e:position!() "\"" &eot() {
                (k.0, Value::Str(b..e, Quote::Double))
            }
            // strings observed in audit output from user-space programs
            / k:key() "='"  b:position!() $([^b'\'']*) e:position!() "'"  &eot() {
                (k.0, Value::Str(b..e, Quote::Single))
            }
            / k:key() "={"  b:position!() $([^b'}']*)  e:position!()  "}" &eot() {
                (k.0, Value::Str(b..e, Quote::Braces))
            }
            // default: interpret as string
            / k:key() "="   b:position!() safeunq()    e:position!()      &eot() {
                (k.0, Value::Str(b..e, Quote::None))
            }
            / b:position!() [^ b'\n']* e:position!() {
                (Key::Literal("NOT_PARSED"), Value::Str(b..e, Quote::None))
            }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use super::msg_type::*;
    #[test]
    fn parser() -> Result<(),String> {
        // ensure that constant init works
        assert_eq!(format!("--{}--", EOE), "--EOE--");
        assert_eq!(format!("--{}--", MessageType(9999)), "--UNKNOWN[9999]--");
        {
            let (t, id, _rv) = parse(Vec::from(br#"type=EOE msg=audit(1615225617.302:25836):
"#.as_ref()))?;
            assert_eq!(t, EOE);
            assert_eq!(id, EventID{timestamp: 1615225617302, sequence: 25836});
        }
        {
            let (t, id, rv) = parse(Vec::from(br#"type=SYSCALL msg=audit(1615114232.375:15558): arch=c000003e syscall=59 success=yes exit=0 a0=63b29337fd18 a1=63b293387d58 a2=63b293375640 a3=fffffffffffff000 items=2 ppid=10883 pid=10884 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm="whoami" exe="/usr/bin/whoami" key=(null)ARCH=x86_64 SYSCALL=execve AUID="user" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
"#.as_ref()))?;
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
        }
        {
            let (t, id, rv) = parse(Vec::from(br#"type=EXECVE msg=audit(1614788539.386:13232): argc=0 a0="whoami"
"#.as_ref()))?;
            assert_eq!(t, EXECVE);
            assert_eq!(id, EventID{timestamp: 1614788539386, sequence: 13232});
            // FIXME: This should be argv["whoami"]
            assert_eq!(rv.into_iter().map(|(k,v)| format!("{:?}: {:?}", k, v)).collect::<Vec<_>>(),
                       vec!("argc: Num:<0>",
                            "a0: Str:<whoami>"));
        }
        {
            let (t, id, rv) = parse(Vec::from(br#"node=work type=PATH msg=audit(1614788539.386:13232): item=0 name="/usr/bin/whoami" inode=261214 dev=ca:03 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
"#.as_ref()))?;
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
        }
        {
            let (t, id, rv) = parse(Vec::from(br#"type=PATH msg=audit(1615113648.978:15219): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=262146 dev=ca:03 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0OUID="root" OGID="root"
"#.as_ref()))?;
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
        }
        {
            let (t, id, rv) = parse(Vec::from(br#"type=USER_ACCT msg=audit(1615113648.981:15220): pid=9460 uid=1000 auid=1000 ses=1 msg='op=PAM:accounting grantors=pam_permit acct="user" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'UID="user" AUID="user"
"#.as_ref()))?;
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
        }
        {
            let (t, id, _rv) = parse(Vec::from(br#"type=UNKNOWN[1334] msg=audit(1626883065.201:216697): prog-id=45 op=UNLOAD
"#.as_ref()))?;
            assert_eq!(t, BPF);
            assert_eq!(id, EventID{timestamp: 1626883065201, sequence: 216697});
        }
        {
            let (t, _id, _rv) = parse(Vec::from(br#"type=AVC msg=audit(1631798689.083:65686): avc:  denied  { setuid } for  pid=15381 comm="laurel" capability=7  scontext=system_u:system_r:auditd_t:s0 tcontext=system_u:system_r:auditd_t:s0 tclass=capability permissive=1
"#.as_ref()))?;
            assert_eq!(t, AVC);
        }
        {
            let (t, _id, _rv) = parse(Vec::from(br#"type=AVC msg=audit(1631870323.500:7098): avc:  granted  { setsecparam } for  pid=11209 comm="tuned" scontext=system_u:system_r:tuned_t:s0 tcontext=system_u:object_r:security_t:s0 tclass=security
"#.as_ref()))?;
            assert_eq!(t, AVC);
        }
        {
            let (t, _id, _rv) = parse(Vec::from(br#"type=MAC_UNLBL_ALLOW msg=audit(1631783567.248:3): netlabel: auid=0 ses=0 unlbl_accept=1 old=0AUID="root"
"#.as_ref()))?;
            assert_eq!(t, MAC_UNLBL_ALLOW);
        }


        Ok(())
    }
}
