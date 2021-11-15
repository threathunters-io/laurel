use std::collections::{HashMap,HashSet,VecDeque};
use std::error::Error;
use std::ops::Range;

use indexmap::IndexMap;

use serde::{Serialize,Serializer};
use serde::ser::{SerializeSeq,SerializeMap};

use crate::constants::{ARCH_NAMES,SYSCALL_NAMES,msg_type::*};
use crate::userdb::UserDB;
use crate::proc::{ProcTable,get_environ};
use crate::types::*;
use crate::parser::parse;
use crate::quoted_string::ToQuotedString;
use crate::sockaddr::SocketAddr;

/// Collect records in [`EventBody`] context as single or multiple
/// instances.
///
/// Examples for single instances are `SYSCALL`,`EXECVE` (even if the
/// latter can be split across multiple lines). An example for
/// multiple instances is `PATH`.
///
/// "Multi" records are serialized as list-of-maps (`[ { "key":
/// "value", … }, { "key": "value", … } … ]`)
#[derive(Debug,Clone)]
pub enum EventValues {
    // e.g SYSCALL, EXECVE
    Single(Record),
    // e.g. PATH
    Multi(Vec<Record>),
}

impl Serialize for EventValues {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        match self {
            EventValues::Single(rv) => rv.serialize(serializer),
            EventValues::Multi(rvs) => {
                let mut seq = serializer.serialize_seq(Some(rvs.len()))?;
                for rv in rvs {
                    seq.serialize_element(rv)?;
                }
                seq.end()
            }
        }
    }
}

/// The content of an Event, sorted by message types
#[derive(Debug,Default)]
pub struct EventBody {
    values: IndexMap<MessageType,EventValues>,
}

#[derive(Debug)]
pub struct Event {
    node: Option<Vec<u8>>,
    id: EventID,
    body: EventBody,
}

impl Serialize for Event {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let mut length = 1 + self.body.values.len();
        if let Some(_) = self.node {
            length += 1
        };
        let mut map = s.serialize_map(Some(length))?;
        map.serialize_key("ID")?;
        map.serialize_value(&self.id)?;
        if let Some(node) = &self.node {
            map.serialize_key("NODE")?;
            map.serialize_value(&node.as_slice().to_quoted_string())?;
        }
        for (k,v) in &self.body.values {
            map.serialize_entry(&k,&v)?;
        }
        map.end()
    }
}

/// Coalesce collects Audit Records from individual lines and assembles them to Events
#[derive(Debug,Default)]
pub struct Coalesce {
    /// Events that are being collected/processed
    inflight: HashMap<(Option<Vec<u8>>, EventID), EventBody>,
    /// Event IDs that have been recently processed
    done: HashSet<(Option<Vec<u8>>, EventID)>,
    /// Timestamp for next cleanup
    next_expire: Option<u64>,
    /// process table built from observing process-related events
    processes: ProcTable,
    /// creadential cache
    userdb: UserDB,
    /// Generate ARGV and ARGV_STR from EXECVE
    pub execve_argv_list: bool,
    pub execve_argv_string: bool,
    pub execve_env: HashSet<Vec<u8>>,

    pub translate_universal: bool,
    pub translate_userdb: bool,
}

const EXPIRE_PERIOD: u64  = 30_000;
const EXPIRE_TIMEOUT: u64 = 120_000;

/// generate translation of SocketAddr enum to a format similar to
/// what auditd log_format=ENRICHED produces
fn translate_socketaddr(rv: &mut Record, sa: SocketAddr) -> Value {
    let mut m = Vec::new();
    let f = rv.put(b"saddr_fam");
    match sa {
        SocketAddr::Local(sa) => {
            m.push((f, rv.put(b"local")));
            m.push((rv.put(b"path"),
                    rv.put(&sa.path)));
        },
        SocketAddr::Inet(sa) => {
            m.push((f, rv.put(b"inet")));
            m.push((rv.put(b"addr"),
                    rv.put(format!("{}", sa.ip()).as_bytes())));
            m.push((rv.put(b"port"),
                    rv.put(format!("{}", sa.port()).as_bytes())));
        },
        SocketAddr::AX25(sa) => {
            m.push((f, rv.put(b"ax25")));
            m.push((rv.put(b"call"),
                    rv.put(&sa.call)));
        },
        SocketAddr::ATMPVC(sa) => {
            m.push((f, rv.put(b"atmpvc")));
            m.push((rv.put(b"itf"),
                    rv.put(format!("{}", sa.itf).as_bytes())));
            m.push((rv.put(b"vpi"),
                    rv.put(format!("{}", sa.vpi).as_bytes())));
            m.push((rv.put(b"vci"),
                    rv.put(format!("{}", sa.vci).as_bytes())));
        },
        SocketAddr::X25(sa) => {
            m.push((f, rv.put(b"x25")));
            m.push((rv.put(b"addr"),
                    rv.put(&sa.address)));
        },
        SocketAddr::IPX(sa) => {
            m.push((f, rv.put(b"ipx")));
            m.push((rv.put(b"network"),
                    rv.put(format!("{:08x}", sa.network)
                           .as_bytes())));
            m.push((rv.put(b"node"),
                    rv.put(
                        format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                                sa.node[0], sa.node[1],
                                sa.node[2], sa.node[3],
                                sa.node[4], sa.node[5])
                            .as_bytes())));
            m.push((rv.put(b"port"),
                    rv.put(format!("{}", sa.port).as_bytes())));
            m.push((rv.put(b"type"),
                    rv.put(format!("{}", sa.typ).as_bytes())));
        },
        SocketAddr::Inet6(sa) => {
            m.push((f, rv.put(b"inet6")));
            m.push((rv.put(b"addr"),
                    rv.put(format!("{}", sa.ip()).as_bytes())));
            m.push((rv.put(b"port"),
                    rv.put(format!("{}", sa.port()).as_bytes())));
            m.push((rv.put(b"flowinfo"),
                    rv.put(format!("{}", sa.flowinfo())
                           .as_bytes())));
            m.push((rv.put(b"scope_id"),
                    rv.put(format!("{}", sa.scope_id())
                           .as_bytes())));
        },
        SocketAddr::Netlink(sa) => {
            m.push((f, rv.put(b"netlink")));
            m.push((rv.put(b"pid"),
                    rv.put(format!("{}", sa.pid).as_bytes())));
            m.push((rv.put(b"groups"),
                    rv.put(format!("{}", sa.groups).as_bytes())));
        },
        SocketAddr::VM(sa) => {
            m.push((f, rv.put(b"vsock")));
            m.push((rv.put(b"cid"),
                    rv.put(format!("{}", sa.cid).as_bytes())));
            m.push((rv.put(b"port"),
                    rv.put(format!("{}", sa.port).as_bytes())));
        },
    }
    return Value::Map(m);
}


impl Coalesce {
    /// Fill shadow process table from system's /proc directory
    pub fn populate_proc_table(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(self.processes = ProcTable::from_proc()?)
    }

    /// Cleans up stale "done" entries
    fn expire_done(&mut self, now: u64) {
        let node_ids = self.done.iter()
            .filter(|(_, id)| id.timestamp + EXPIRE_TIMEOUT > now)
            .cloned()
            .collect::<Vec<_>>();
        for node_id in node_ids {
            self.done.remove(&node_id);
        }
        self.next_expire = Some(now + EXPIRE_PERIOD);
    }

    /// Translates UID, GID and variants, e.g.:
    /// - auid=1000 -> AUID="user"
    /// - ogid=1000 -> OGID="user"
    #[inline(always)]
    fn translate_userdb(&mut self, rv: &mut Record, k: &Key, v: &Value) -> Option<(Key, Value)> {
        if !self.translate_userdb { return None }
        if let Key::Name(r) = k {
            let name = &rv.raw[r.clone()];
            if name.ends_with(b"uid") {
                if let Value::Number(Number::Dec(d)) = v {
                    if let Some(user) = self.userdb.get_user(*d as u32) {
                        return Some((Key::UpperCaseName(r.clone()),
                                     Value::Str(rv.put(user.as_bytes()), Quote::None)));
                    }
                }
            } else if name.ends_with(b"gid") {
                if let Value::Number(Number::Dec(d)) = v {
                    if let Some(group) = self.userdb.get_group(*d as u32) {
                        return Some((Key::UpperCaseName(r.clone()),
                                     Value::Str(rv.put(group.as_bytes()), Quote::None)));
                    }
                }
            }
        }
        return None;
    }

    /// Rewrite EventBody to normal form
    ///
    /// This function
    /// - turns SYSCALL/a* fields into a single an ARGV list
    /// - turns EXECVE/a* and EXECVE/a*[*] fields into an ARGV list
    /// - turns PROCTITLE/proctitle into a (abbreviated) ARGV list
    /// - translates *uid, *gid, syscall, arch, sockaddr if configured to do so.
    fn normalize_eventbody(&mut self, eb: &mut EventBody) {
        for (typ,ev) in eb.values.iter_mut() {
            match (typ,ev) {
                (&SYSCALL, EventValues::Single(rv)) => {
                    rv.raw.reserve(
                        if self.translate_universal { 16 } else { 0 } +
                        if self.translate_userdb { 72 } else { 0 } );
                    let mut new = Vec::with_capacity(rv.elems.len() - 3);
                    let mut translated = VecDeque::with_capacity(11);
                    let mut argv = Vec::with_capacity(4);
                    let mut arch = None;
                    let mut syscall = None;
                    for (k,v) in &rv.elems.clone() {
                        match k {
                            Key::Arg(_,None) => {
                                // FIXME: check argv length
                                argv.push(v.clone());
                                continue;
                            },
                            Key::Name(r) => {
                                let name = &rv.raw[r.clone()];
                                match name {
                                    b"arch" if self.translate_universal => {
                                        if let Value::Number(Number::Hex(n)) = v {
                                            arch = Some((r.clone(), n.clone()));
                                        }
                                    },
                                    b"syscall" if self.translate_universal => {
                                        if let Value::Number(Number::Dec(n)) = v {
                                            syscall = Some((r.clone(), n.clone()));
                                        }
                                    },
                                    b"ARCH"|b"SYSCALL" if self.translate_universal => continue,
                                    _ => {
                                        if let Some((k,v)) = self.translate_userdb(rv, k, v) {
                                            translated.push_back((k,v));
                                        }
                                    },
                                }
                            },
                            _ => (),
                        };
                        new.push((k.clone(), v.clone()));
                    }
                    if let (Some(arch), Some(syscall)) = (arch, syscall) {
                        if let Some(arch_name) = ARCH_NAMES.get(&(arch.1 as u32)) {
                            if let Some(syscall_name) = SYSCALL_NAMES.get(arch_name)
                                .and_then(|syscall_tbl| syscall_tbl.get(&(syscall.1 as u32)))
                            {
                                let v = rv.put(syscall_name);
                                translated.push_front((Key::UpperCaseName(syscall.0), Value::Str(v, Quote::None)));
                            }
                            let v = rv.put(arch_name);
                            translated.push_front((Key::UpperCaseName(arch.0), Value::Str(v, Quote::None)));
                        }
                    }
                    new.push((Key::Literal("ARGV"), Value::List(argv)));
                    new.extend(translated);
                    rv.elems = new;
                },
                (&EXECVE, EventValues::Single(rv)) => {
                    let mut new: Vec<(Key, Value)> = Vec::new();
                    let mut argv: Vec<Value> = Vec::new();
                    for (k, v) in rv.into_iter() {
                        match k.key {
                            Key::ArgLen(_) => continue,
                            Key::Arg(i, None) => {
                                let idx = *i as usize;
                                if argv.len() <= idx {
                                    argv.resize(idx+1, Value::Empty);
                                };
                                argv[idx] = v.value.clone();
                            },
                            Key::Arg(i, Some(f)) => {
                                let idx = *i as usize;
                                if argv.len() <= idx {
                                    argv.resize(idx+1, Value::Empty);
                                    argv[idx] = Value::Segments(Vec::new());
                                }
                                if let Some(Value::Segments(l)) = argv.get_mut(idx) {
                                    let frag = *f as usize;
                                    let r = match v.value {
                                        Value::Str(r, _) => r,
                                        _ => &Range{start: 0, end: 0}, // FIXME
                                    };
                                    if l.len() <= frag {
                                        l.resize(frag+1, 0..0);
                                        l[frag] = r.clone();
                                    }
                                }
                            },
                            _ => new.push((k.key.clone(), v.value.clone())),
                        };
                    }
                    if self.execve_argv_list {
                        new.push((Key::Literal("ARGV"), Value::List(argv.clone())));
                    }
                    if self.execve_argv_string {
                        new.push((Key::Literal("ARGV_STR"), Value::StringifiedList(argv.clone())));
                    }
                    rv.elems = new;
                },
                (&SOCKADDR, EventValues::Multi(rvs)) => {
                    for mut rv in rvs {
                        let mut new = Vec::new();
                        let mut translated = Vec::new();
                        for (k,v) in &rv.elems.clone() {
                            if let (Key::Name(kr),Value::Str(vr, _)) = (k,v) {
                                let name = &rv.raw[kr.clone()];
                                match name {
                                    b"saddr" if self.translate_universal => {
                                        if let Ok(sa) = SocketAddr::parse(&rv.raw[vr.clone()]) {
                                            translated.push((Key::UpperCaseName(kr.clone()), translate_socketaddr(&mut rv, sa)));
                                            continue;
                                        }
                                    },
                                    b"SADDR" if self.translate_universal => continue,
                                    _ => {},
                                }
                            }
                            new.push((k.clone(),v.clone()));
                        }
                        new.extend(translated);
                        rv.elems = new;
                    }
                },
                (&PROCTITLE, EventValues::Single(rv)) => {
                    if let Some(v) = rv.get(b"proctitle") {
                        if let Value::Str(r, _) = v.value {
                            let mut argv: Vec<Value> = Vec::new();
                            let mut prev = r.start;
                            for i in r.start ..= r.end {
                                if (i == r.end || rv.raw[i] == 0) &&
                                    !(prev..i).is_empty()
                                {
                                    argv.push(Value::Str(prev..i, Quote::None));
                                    prev = i+1;
                                }
                            }
                            rv.elems = vec!((Key::Literal("ARGV"), Value::List(argv)));
                        }
                    }
                },
                (_, EventValues::Single(rv)) => {
                    let mut translated = Vec::new();
                    for (k,v) in &rv.elems.clone() {
                        if let Some((k,v)) = self.translate_userdb(rv, k, v) {
                            translated.push((k,v));
                        }
                    }
                    rv.elems.extend(translated);
                },
                (_, EventValues::Multi(rvs)) => {
                    for rv in rvs {
                        let mut translated = Vec::new();
                        for (k,v) in &rv.elems.clone() {
                            if let Some((k,v)) = self.translate_userdb(rv, k, v) {
                                translated.push((k,v));
                            }
                        }
                        rv.elems.extend(translated);
                    }
                },
            }
        }
    }

    /// Add environment variables to event body
    fn augment_execve_env(&mut self, execve: &mut Record, pid: u64) {
        if self.execve_env.is_empty() {
            return;
        }
        let vars = get_environ(pid).ok()
            .and_then( |environ| {
                let added = environ.iter()
                    .filter( |(k,_v)| self.execve_env.contains(k) )
                    .map( |(k,v)| {
                        let rk = execve.put(k);
                        let rv = execve.put(v);
                        (rk,rv)
                    })
                    .collect::<Vec<_>>();
                if added.len() > 0 { Some(added) } else { None }
            });
        match vars {
            Some(a) => {
                execve.elems.push( (Key::Literal("ENV"),Value::Map(a)) );
            }
            None => {}
        };
    }

    /// Augment event with information from shadow process table
    fn augment_syscall(&mut self, eb: &mut EventBody) {
        let sc = match eb.values.get(&SYSCALL) {
            Some(EventValues::Single(r)) => r,
            _ => return,
        };
        if let Some(v) = sc.get(b"ppid") {
            if let Value::Number(Number::Dec(ppid)) = v.value {
                if let Some(p) = self.processes.get_process(*ppid) {
                    let mut pi = Record::default();
                    let vs = p.argv.iter()
                        .map(|v| Value::Str(pi.put(v), Quote::None))
                        .collect::<Vec<_>>();
                    if self.execve_argv_string {
                        let k = Key::Name(pi.put(b"ARGV_STR"));
                        pi.elems.push((k, Value::StringifiedList(vs.clone())));
                    }
                    if self.execve_argv_list {
                        let k = Key::Name(pi.put(b"ARGV"));
                        pi.elems.push((k, Value::List(vs)));
                    }
                    let kv = (Key::Name(pi.put(b"ppid")), Value::Number(Number::Dec(p.ppid)));
                    pi.elems.push(kv);
                    eb.values.insert(PARENT_INFO, EventValues::Single(pi));
                }
            }
        }
    }

    /// Ingest a log line and add it to the coalesce object.
    ///
    /// Simple one-liner events are returned immediately.
    ///
    /// For complex multi-line events (SYSCALL + additional
    /// information), corresponding records are collected and only the
    /// Event ID is returned. The entire event is returned only when
    /// an EOE ("end of event") line for the event is encountered.
    ///
    /// The line is consumed and serves as backing store for the
    /// EventBody objects.
    pub fn process_line(&mut self, line: Vec<u8>) -> Result<Option<Event>, Box<dyn Error>> {
        let (node, typ, id, rv) = parse(line)?;
        let nid = (node.clone(), id);
        match self.next_expire {
            Some(t) if t < id.timestamp => {
                self.expire_done(id.timestamp);
                self.processes.expire();
            },
            None => self.next_expire = Some(id.timestamp + EXPIRE_PERIOD),
            _ => (),
        };
        match typ {
            SYSCALL => {
                if self.inflight.contains_key(&nid) {
                    return Err(format!("duplicate SYSCALL for id {}", id).into());
                }
                let mut eb = EventBody::default();
                eb.values.insert(typ, EventValues::Single(rv));
                self.augment_syscall(&mut eb);
                self.inflight.insert(nid, eb);
                return Ok(None);
            },
            EOE => {
                if self.done.contains(&nid) {
                    return Err(format!("duplicate EOE for id {}", id).into());
                }
                self.done.insert(nid.clone());
                let mut eb = self.inflight.remove(&nid)
                    .ok_or(format!("Event {} for EOE marker not found", &id))?;
                self.normalize_eventbody(&mut eb);

                let mut pid = None;
                if let Some(EventValues::Single(ref syscall)) = eb.values.get(&SYSCALL) {
                    #[allow(unused_must_use)]
                    if let Some(EventValues::Single(ref execve)) = eb.values.get(&EXECVE) {
                        self.processes.add_execve(&id, &syscall, &execve);
                    }
                    if let Some(v) = syscall.get(b"pid") {
                        if let Value::Number(Number::Dec(p)) = v.value {
                            pid = Some(*p);
                        }
                    }
                };
                match (pid, eb.values.get_mut(&EXECVE)) {
                    (Some(pid), Some(EventValues::Single(ref mut execve))) =>  {
                        self.augment_execve_env(execve, pid);
                    }
                    _ => (),
                };
                return Ok(Some(Event{node, id, body: eb}));
            },
            _ => {
                if let Some(eb) = self.inflight.get_mut(&nid) {
                    match eb.values.get_mut(&typ) {
                        Some(EventValues::Single(v)) => v.extend(rv),
                        Some(EventValues::Multi(v)) => v.push(rv),
                        None => match typ {
                            EXECVE | PROCTITLE | CWD => {
                                eb.values.insert(typ, EventValues::Single(rv));
                            },
                            _ => {
                                eb.values.insert(typ, EventValues::Multi(vec!(rv)));
                            },
                        }
                    };
                    Ok(None)
                } else {
                    self.done.insert(nid);
                    let mut values = IndexMap::new();
                    values.insert(typ, EventValues::Single(rv));
                    Ok(Some(Event{node, id, body: EventBody{values}}))
                }
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::{BufReader,BufRead};

    #[test]
    fn coalesce() -> Result<(), String> {
        let mut c = Coalesce { execve_argv_list: true, ..Coalesce::default() };

        match c.process_line(
            Vec::from(*include_bytes!("testdata/line-user-acct.txt"))
        ).unwrap() {
            None => panic!("failed to emit event body"),
            Some(eb) => println!("got {:?}", eb),
        };

        let mut event = None;
        for line in BufReader::new(include_bytes!("testdata/record-execve.txt").as_ref()).lines() {
            let mut line = line.unwrap().clone();
            line.push('\n');
            match c.process_line(line.as_bytes().to_vec())
                .expect(&format!("failed to parse {:?}", line))
            {
                Some(o) => {
                    event = Some(o);
                    break;
                }
                None => (),
            }
        }
        match event {
            None => panic!("failed to emit event bodyr"),
            Some(eb) => println!("got {:?}", eb),
        };
        Ok(())
    }

    #[test]
    fn coalesce_long() -> Result<(), String> {
        let mut c = Coalesce { execve_argv_list: true, ..Coalesce::default() };

        let mut event = None;
        for line in BufReader::new(include_bytes!("testdata/record-execve-long.txt").as_ref()).lines() {
            let mut line = line.unwrap().clone();
            line.push('\n');
            match c.process_line(line.as_bytes().to_vec())
                .expect(&format!("failed to parse {:?}", line))
            {
                Some(o) => {
                    event = Some(o);
                    break;
                }
                None => (),
            }
        }
        match event {
            None => panic!("failed to emit event bodyr"),
            Some(eb) => println!("got {:?}", eb),
        };
        Ok(())
    }
}
