use indexmap::IndexMap;

use serde::Deserialize;

use std::io::BufRead;

#[derive(Deserialize)]
#[serde(untagged)]
enum EventValues {
    Single(Record),
    Multi(Vec<Record>),
}

#[derive(Deserialize, Default)]
struct Record(IndexMap<String, serde_json::Value>);

#[derive(Deserialize)]
struct Event {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "NODE")]
    node: Option<String>,
    #[serde(flatten)]
    events: IndexMap<String, EventValues>,
}

// copy form parser.rs
#[inline(always)]
fn is_safe_chr(c: u8) -> bool {
    c == b'!' || (b'#'..=b'~').contains(&c)
}

fn print_record(typ: &str, r: &Record) {
    use serde_json::Value;
    let mut kv = r.0.clone();

    if typ == "AVC" {
        for key in &["denied", "granted"] {
            if let Some(Value::Array(permissions)) = kv.get(*key) {
                let mut pstr = String::default();
                for p in permissions.iter().map(|v| v.as_str().unwrap_or_default()) {
                    if !pstr.is_empty() {
                        pstr.push_str(", ");
                    }
                    pstr.push_str(p);
                }
                print!(" avc:  {key}  {{ {pstr} }} for ");
                kv.shift_remove(*key);
            }
        }
    }

    for (n, (k, v)) in kv.iter().enumerate() {
        if n == 4 && typ == "SYSCALL" {
            if let Some(Value::Array(a)) = kv.get("ARGV") {
                for (n, v) in a.iter().enumerate() {
                    if let Value::String(s) = v {
                        if !s.starts_with("0x") {
                            continue;
                        }
                        print!(" a{n}={}", &s[2..]);
                    }
                }
            }
        }
        if k == &k.to_uppercase() {
            continue;
        }
        print!(" {k}=");
        match v {
            Value::String(s) if ["scontext", "tclass", "tcontext"].contains(&k.as_str()) => {
                print!("{s}");
            }
            Value::String(s) => {
                let b: &[u8] = s.as_bytes();
                if b.iter().cloned().all(is_safe_chr) {
                    if (b.starts_with(b"0x") || b.starts_with(b"0o"))
                        && ["SYSCALL", "PATH"].contains(&typ)
                    {
                        print!("{}", &s[2..]);
                    } else {
                        print!("{v}");
                    }
                } else {
                    b.iter().for_each(|c| print!("{:02X}", c));
                }
            }
            Value::Array(_) => {
                todo!()
            }
            Value::Object(_) => {
                todo!()
            }
            _ => print!("{v}"),
        };
    }
    println!();
}

fn main() {
    let stdin = std::io::stdin().lock();
    for line in stdin.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                println!("error: {e}");
                continue;
            }
        };
        let ev: Event = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                println!("error: {e}");
                continue;
            }
        };
        let msgid = ev.id;
        let prefix = match ev.node {
            Some(node) => format!("node={node} msg=audit({msgid}): "),
            None => format!("msg=audit({msgid}):"),
        };
        for (typ, body) in ev.events.iter() {
            match (typ.as_str(), body) {
                ("PARENT_INFO", _) => continue,
                ("EXECVE", EventValues::Single(r)) => {
                    let mut r2 = Record::default();
                    match r.0.get("argc") {
                        None => continue,
                        Some(n) => r2.0.insert("argc".into(), n.clone()),
                    };
                    if let Some(serde_json::Value::String(s)) = r.0.get("ARGV_STR") {
                        for (n, arg) in s.split(' ').enumerate() {
                            r2.0.insert(format!("a{n}"), serde_json::Value::String(arg.into()));
                        }
                    } else if let Some(serde_json::Value::Array(a)) = r.0.get("ARGV") {
                        for (n, arg) in a.iter().enumerate() {
                            r2.0.insert(format!("a{n}"), arg.clone());
                        }
                    } else {
                        continue;
                    }
                    print!("type={typ} {prefix}");
                    print_record(typ, &r2);
                }
                (_, EventValues::Single(r)) => {
                    print!("type={typ} {prefix}");
                    print_record(typ, r);
                }
                (_, EventValues::Multi(rs)) => {
                    for r in rs {
                        print!("type={typ} {prefix}");
                        print_record(typ, r);
                    }
                }
            };
        }
        println!("type=EOE {prefix} ");
    }
}
