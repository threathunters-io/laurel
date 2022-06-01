use std::collections::{BTreeMap,HashSet,VecDeque};
use std::error::Error;
use std::io::Write;
use std::ops::Range;
use std::time::{SystemTime,UNIX_EPOCH};

use indexmap::IndexMap;

use serde::{Serialize,Serializer};
use serde::ser::{SerializeSeq,SerializeMap};
use serde_json::json;

use crate::constants::{ARCH_NAMES,SYSCALL_NAMES,msg_type::*};
use crate::userdb::UserDB;
use crate::proc::{ProcTable,get_environ};
use crate::types::*;
use crate::parser::parse;
use crate::quoted_string::ToQuotedString;
use crate::sockaddr::SocketAddr;
use crate::label_matcher::LabelMatcher;

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


#[derive(Clone,Debug)]
pub struct Event {
    node: Option<Vec<u8>>,
    id: EventID,
    body: IndexMap<MessageType,EventValues>,
}

impl Event {
    fn new(node: Option<Vec<u8>>, id: EventID) -> Self {
        Event { node, id, body: IndexMap::with_capacity(5) }
    }
}

impl Serialize for Event {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let mut length = 1 + self.body.len();
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
        for (k,v) in &self.body {
            map.serialize_entry(&k,&v)?;
        }
        map.end()
    }
}

/// Coalesce collects Audit Records from individual lines and assembles them to Events
pub struct Coalesce<'a> {
    /// Events that are being collected/processed
    inflight: BTreeMap<(Option<Vec<u8>>, EventID), Event>,
    /// Event IDs that have been recently processed
    done: HashSet<(Option<Vec<u8>>, EventID)>,
    /// Timestamp for next cleanup
    next_expire: Option<u64>,
    /// process table built from observing process-related events
    processes: ProcTable,
    /// output function
    emit_fn: Box<dyn 'a + FnMut(&Event)>,
    /// creadential cache
    userdb: UserDB,
    /// Generate ARGV and ARGV_STR from EXECVE
    pub execve_argv_list: bool,
    pub execve_argv_string: bool,
    pub execve_env: HashSet<Vec<u8>>,

    pub proc_label_keys: HashSet<Vec<u8>>,
    pub proc_propagate_labels: HashSet<Vec<u8>>,

    pub translate_universal: bool,
    pub translate_userdb: bool,

    pub label_exe: Option<&'a LabelMatcher>,
}

const EXPIRE_PERIOD: u64  = 1_000;
const EXPIRE_INFLIGHT_TIMEOUT: u64 = 5_000;
const EXPIRE_DONE_TIMEOUT: u64 = 120_000;

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

impl<'a> Coalesce<'a> {
    /// Creates a `Coalsesce`. `emit_fn` is the function that takes
    /// completed events.
    pub fn new<F: 'a + FnMut(&Event)>(emit_fn: F) -> Self {
        Coalesce {
            inflight: BTreeMap::new(),
            done: HashSet::new(),
            next_expire: None,
            processes: ProcTable::default(),
            emit_fn: Box::new(emit_fn),
            userdb: UserDB::default(),
            execve_argv_list: true,
            execve_argv_string: false,
            execve_env: HashSet::new(),
            proc_label_keys: HashSet::new(),
            proc_propagate_labels: HashSet::new(),
            translate_universal: false,
            translate_userdb: false,
            label_exe: None,
        }
    }

    /// Fill shadow process table from system's /proc directory
    pub fn populate_proc_table(&mut self) -> Result<(), Box<dyn Error>> {
        self.processes = ProcTable::from_proc(self.label_exe, &self.proc_propagate_labels)?;

        Ok(())
    }

    /// Fill userdb
    pub fn populate_userdb(&mut self) {
        self.userdb.populate()
    }

    /// Flush out events
    ///
    /// Called every EXPIRE_PERIOD ms and when Coalesce is destroyed.
    fn expire_inflight(&mut self, now: u64) {
        let node_ids = self.inflight.keys()
            .filter( |(_, id)| id.timestamp + EXPIRE_INFLIGHT_TIMEOUT < now )
            .cloned()
            .collect::<Vec<_>>();
        for node_id in node_ids {
            if let Some(event) = self.inflight.remove(&node_id) {
                self.emit_event(event);
            }
        }
    }

    fn expire_done(&mut self, now: u64) {
        let node_ids = self.done.iter()
            .filter(| (_, id)| id.timestamp + EXPIRE_DONE_TIMEOUT < now )
            .cloned()
            .collect::<Vec<_>>();
        for node_id in node_ids {
            self.done.remove(&node_id);
        }
    }

    /// Translates UID, GID and variants, e.g.:
    /// - auid=1000 -> AUID="user"
    /// - ogid=1000 -> OGID="user"
    #[inline(always)]
    fn translate_userdb(&mut self, rv: &mut Record, k: &Key, v: &Value) -> Option<(Key, Value)> {
        if !self.translate_userdb { return None }
        match k {
            Key::NameUID(r) => {
                if let Value::Number(Number::Dec(d)) = v {
                    let translated = if *d == 0xffffffff {
                        "unset".to_string()
                    } else if let Some(user) = self.userdb.get_user(*d as u32) {
                        user.to_string()
                    } else {
                        format!("unknown({})", d)
                    };
                    return Some((Key::NameTranslated(r.clone()),
                                 Value::Str(rv.put(translated.as_bytes()), Quote::Double)));
                }
            },
            Key::NameGID(r) => {
                if let Value::Number(Number::Dec(d)) = v {
                    let translated = if *d == 0xffffffff {
                        "unset".to_string()
                    } else if let Some(group) = self.userdb.get_group(*d as u32) {
                        group.to_string()
                    } else {
                        format!("unknown({})", d)
                    };
                    return Some((Key::NameTranslated(r.clone()),
                                 Value::Str(rv.put(translated.as_bytes()), Quote::Double)));
                }
            },
            _ => (),
        };
        return None;
    }

    /// Rewrite event to normal form
    ///
    /// This function
    /// - turns SYSCALL/a* fields into a single an ARGV list
    /// - turns EXECVE/a* and EXECVE/a*[*] fields into an ARGV list
    /// - turns PROCTITLE/proctitle into a (abbreviated) ARGV list
    /// - translates *uid, *gid, syscall, arch, sockaddr if configured to do so.
    /// - collects environment variables for EXECVE
    /// - registers process in shadow process table for EXECVE
    fn transform_event(&mut self, ev: &mut Event) {
        let mut pid: Option<u32> = None;
        let mut ppid: Option<u32> = None;
        let mut comm: Option<Vec<u8>> = None;
        let mut exe: Option<Vec<u8>> = None;
        let mut key: Option<Vec<u8>> = None;
        let mut syscall_is_exec = false;
        for tv in ev.body.iter_mut() {
            match tv {
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
                        match (k,v) {
                            (Key::Arg(_,None), _) => {
                                // FIXME: check argv length
                                argv.push(v.clone());
                                continue;
                            },
                            (Key::ArgLen(_), _) => continue,
                            (Key::Name(r), Value::Number(n)) => {
                                let name = &rv.raw[r.clone()];
                                match (name, n) {
                                    (b"arch", Number::Hex(n)) =>
                                        arch = Some((r.clone(), *n)),
                                    (b"syscall", Number::Dec(n)) =>
                                        syscall = Some((r.clone(), *n)),
                                    (b"pid", Number::Dec(n)) => pid = Some(*n as u32),
                                    (b"ppid", Number::Dec(n)) => ppid = Some(*n as u32),
                                    _ => (),
                                }
                            },
                            (Key::Name(r), v) => {
                                let name = &rv.raw[r.clone()];
                                match name {
                                    b"ARCH" =>
                                        if let &Some(_) = &arch { continue },
                                    b"SYSCALL" =>
                                        if let &Some(_) = &syscall { continue },
                                    b"key" =>
                                        if let Value::Str(r, _) = v {
                                            key = Some(rv.raw[r.clone()].into());
                                        },
                                    b"comm" =>
                                        if let Value::Str(r,_) = v {
                                            comm = Some(rv.raw[r.clone()].into());
                                        },
                                    b"exe" =>
                                        if let Value::Str(r,_) = v {
                                            exe = Some(rv.raw[r.clone()].into());
                                        },
                                    _ => (),
                                };
                            },
                            _ => if let Some((k,v)) = self.translate_userdb(rv, k, v) {
                                translated.push_back((k,v));
                            },
                        };
                        new.push((k.clone(), v.clone()));
                    }
                    if let (Some(arch), Some(syscall)) = (arch, syscall) {
                        if let Some(arch_name) = ARCH_NAMES.get(&(arch.1 as u32)) {
                            if let Some(syscall_name) = SYSCALL_NAMES.get(arch_name)
                                .and_then(|syscall_tbl| syscall_tbl.get(&(syscall.1 as u32)))
                            {
                                if self.translate_universal {
                                    let v = rv.put(syscall_name);
                                    translated.push_front((Key::NameTranslated(syscall.0), Value::Str(v, Quote::None)));
                                }
                                if syscall_name.windows(6).any(|s| s == b"execve") {
                                    syscall_is_exec = true;
                                }
                            }
                            if self.translate_universal {
                                let v = rv.put(arch_name);
                                translated.push_front((Key::NameTranslated(arch.0), Value::Str(v, Quote::None)));
                            }
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

                    // ARGV
                    if self.execve_argv_list {
                        new.push((Key::Literal("ARGV"), Value::List(argv.clone())));
                    }
                    // ARGV_STR
                    if self.execve_argv_string {
                        new.push((Key::Literal("ARGV_STR"), Value::StringifiedList(argv.clone())));
                    }
                    // ENV
                    match pid {
                        Some(pid) if !self.execve_env.is_empty() => {
                            if let Ok(vars) = get_environ(pid, |k| self.execve_env.contains(k) ) {
                                let map = vars.iter()
                                    .map(|(k,v)| (rv.put(k), rv.put(v)))
                                    .collect();
                                new.push( (Key::Literal("ENV"), Value::Map(map)) );
                            }
                        },
                        _ => (),
                    };

                    rv.elems = new;

                    // register process, add propagated labels from
                    // parent if applicable
                    if let (Some(pid), Some(ppid)) = (pid, ppid) {
                        let argv = argv.iter().filter_map(
                            |v| match v {
                                Value::Str(r,_) => Some(Vec::from(&rv.raw[r.clone()])),
                                _ => None
                            }
                        ).collect();
                        self.processes.add_process(pid, ppid, ev.id, comm.clone(), exe.clone(), argv);

                        if let Some(parent) = self.processes.get_process(ppid) {
                            for l in self.proc_propagate_labels.intersection(&parent.labels) {
                                self.processes.add_label(pid, &l);
                            }
                        }
                    }
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
                                            translated.push((Key::NameTranslated(kr.clone()), translate_socketaddr(&mut rv, sa)));
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

        if let (Some(pid), Some(key)) = (&pid, &key) {
            if self.proc_label_keys.contains(key) {
                self.processes.add_label(*pid, key);
            }
        }

        if let (Some(exe), Some(pid), Some(label_exe), true) =
            (&exe, &pid, &self.label_exe, syscall_is_exec)
        {
            for label in label_exe.matches(&exe) {
                self.processes.add_label(*pid, label);
            }
        }

        // PARENT_INFO
        if let Some(ppid) = ppid {
            if let Some(p) = self.processes.get_process(ppid) {
                let mut pi = Record::default();
                if let Some(id) = p.event_id {
                    let r = pi.put(&format!("{}", id).as_bytes());
                    pi.elems.push((Key::Literal("ID"), Value::Str(r, Quote::None)));
                }
                if let Some(comm) = p.comm {
                    let r = pi.put(&comm);
                    pi.elems.push((Key::Literal("comm"), Value::Str(r, Quote::None)));
                }
                if let Some(exe) = p.exe {
                    let r = pi.put(&exe);
                    pi.elems.push((Key::Literal("exe"), Value::Str(r, Quote::None)));
                }
                let argv = p.argv.iter()
                    .map(|v| Value::Str(pi.put(v), Quote::None))
                    .collect::<Vec<_>>();
                if self.execve_argv_list {
                    pi.elems.push((Key::Literal("ARGV"), Value::List(argv.clone())));
                }
                if self.execve_argv_string {
                    pi.elems.push((Key::Literal("ARGV_STR"), Value::StringifiedList(argv.clone())));
                }
                let kv = (Key::Name(pi.put(b"ppid")), Value::Number(Number::Dec(p.ppid as i64)));
                pi.elems.push(kv);
                ev.body.insert(PARENT_INFO, EventValues::Single(pi));
            }
        }
        if let (Some(pid), Some(EventValues::Single(sc))) =
            (pid, ev.body.get_mut(&SYSCALL))
        {
            let labels = self.processes.get_process(pid)
                .and_then(|p| Some(p.labels))
                .unwrap_or(HashSet::new());
            if labels.len() > 0 {
                let labels = labels.iter()
                    .map(|l| Value::Str(sc.put(l), Quote::None))
                    .collect::<Vec<_>>();
                sc.elems.push((Key::Literal("LABELS"), Value::List(labels)));
            }
        }
    }

    /// Do bookkeeping on event, transform, emit it via the provided
    /// output function.
    fn emit_event(&mut self, mut ev: Event) {
        self.done.insert((ev.node.clone(), ev.id));

        self.transform_event(&mut ev);

        (self.emit_fn)(&ev)
    }

    /// Ingest a log line and add it to the coalesce object.
    ///
    /// Simple one-liner events are emitted immediately.
    ///
    /// For complex multi-line events (SYSCALL + additional
    /// information), corresponding records are collected. The entire
    /// event is emitted only when an EOE ("end of event") line for
    /// the event is encountered.
    ///
    /// The line is consumed and serves as backing store for the
    /// EventBody objects.
    pub fn process_line(&mut self, line: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let (node, typ, id, rv) = parse(line)?;
        let nid = (node.clone(), id);

        // clean out state every EXPIRE_PERIOD
        match self.next_expire {
            Some(t) if t < id.timestamp => {
                self.expire_inflight(id.timestamp);
                self.expire_done(id.timestamp);
                self.processes.expire();
                self.next_expire = Some(id.timestamp + EXPIRE_PERIOD)
            },
            None => self.next_expire = Some(id.timestamp + EXPIRE_PERIOD),
            _ => (),
        };

        if typ == EOE {
            if self.done.contains(&nid) {
                return Err(format!("duplicate event id {}", id).into());
            }
            let ev = self.inflight.remove(&nid)
                .ok_or(format!("Event id {} for EOE marker not found", &id))?;
            self.emit_event(ev);
        } else if typ.is_multipart() {
            // kernel-level messages
            if !self.inflight.contains_key(&nid) {
                self.inflight.insert(nid.clone(), Event::new(node.clone(), id));
            }
            let ev = self.inflight.get_mut(&nid).unwrap();
            match ev.body.get_mut(&typ) {
                Some(EventValues::Single(v)) => v.extend(rv),
                Some(EventValues::Multi(v)) => v.push(rv),
                None => match typ {
                    SYSCALL => {
                        ev.body.insert(typ, EventValues::Single(rv));
                    },
                    EXECVE | PROCTITLE | CWD => {
                        ev.body.insert(typ, EventValues::Single(rv));
                    },
                    _ => {
                        ev.body.insert(typ, EventValues::Multi(vec!(rv)));
                    },
                }
            };
        } else {
            // user-space messages
            if self.done.contains(&nid) {
                return Err(format!("duplicate event id {}", id).into());
            }
            let mut ev = Event::new(node, id);
            ev.body.insert(typ, EventValues::Single(rv));
            self.emit_event(ev);
        }
        Ok(())
    }

    pub fn dump_state(&self, mut w: &mut dyn Write) -> Result<(), Box<dyn Error>>{
        serde_json::to_writer(&mut w, &json!({
            "ts": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            "message": {
                "type": "dump_state",
                "label_exe": self.label_exe,
                "inflight": self.inflight.iter().map(
                    |(k,v)| {
                        if let Some(node) = &k.0 {
                            (format!("{}::{}", String::from_utf8_lossy(node), k.1), v)
                        } else {
                            (format!("{}", k.1), v)
                        }
                    }
                ).collect::<BTreeMap<_,_>>(),
                "done": self.done.iter().map(
                    |v| if let Some(node ) = &v.0 {
                        format!("{}::{}", String::from_utf8_lossy(node), v.1)
                    } else {
                        format!("{}", v.1)
                    }
                ).collect::<Vec<_>>(),
                "processes": self.processes,
                "userdb": self.userdb,
                "next_expire": self.next_expire,
            },
        }))?;
        w.write(b"\n")?;
        w.flush()?;
        Ok(())
    }
}

impl Drop for Coalesce<'_> {
    fn drop(&mut self) { self.expire_inflight(u64::MAX) }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::cell::RefCell;
    use std::io::{BufReader,BufRead};
    use std::rc::Rc;
    use serde_json;

    fn event_to_json(e: &Event) -> String {
        let mut out = vec!();
        serde_json::to_writer(&mut out, e).unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    #[test]
    fn dump_state() -> Result<(),Box<dyn Error>> {
        let mut c = Coalesce::new( |_| {} );
        c.populate_proc_table()?;
        c.populate_userdb();
        c.process_line(br#"type=SYSCALL msg=audit(1615114232.375:15558): arch=c000003e syscall=59 success=yes exit=0 a0=63b29337fd18 a1=63b293387d58 a2=63b293375640 a3=fffffffffffff000 items=2 ppid=10883 pid=10884 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm="whoami" exe="/usr/bin/whoami" key=(null)
"#.to_vec())?;
        let mut buf: Vec<u8> = vec!();
        c.dump_state(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        Ok(())
    }

    fn strip_enriched<T>(text: T) -> Vec<u8>
    where T: AsRef<[u8]>,
    {
        let mut out = vec!();
        for line in BufReader::new(text.as_ref()).lines() {
            let line = line.unwrap().clone();
            for c in line.as_bytes() {
                match *c as char {
                    '\x1d' => break,
                    _ => out.push(*c),
                };
            }
            out.push('\n' as u8);
        }
        out
    }

    fn process_record<T>(c: &mut Coalesce, text: T) -> Result<(),Box<dyn Error>>
    where T: AsRef<[u8]>,
    {
        for line in BufReader::new(text.as_ref()).lines() {
            let mut line = line.unwrap().clone();
            line.push('\n');
            c.process_line(line.as_bytes().to_vec())?;
        }
        Ok(())
    }

    #[test]
    fn coalesce() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(Vec::new()));
        let mut c = Coalesce::new(|e: &Event| { ec.borrow_mut().push(e.clone()); } );

        process_record(&mut c, include_bytes!("testdata/line-user-acct.txt"))?;
        assert_eq!(ec.borrow().last().unwrap().id, EventID{ timestamp: 1615113648981, sequence: 15220});

        if let Ok(_) = process_record(&mut c, include_bytes!("testdata/line-user-acct.txt")) {
            panic!("failed to detect duplicate entries");
        };

        process_record(&mut c, include_bytes!("testdata/record-execve.txt"))?;
        assert_eq!(ec.borrow().last().unwrap().id, EventID{ timestamp: 1615114232375, sequence: 15558});

        process_record(&mut c, include_bytes!("testdata/record-execve-long.txt"))?;
        assert_eq!(ec.borrow().last().unwrap().id, EventID{ timestamp: 1615150974493, sequence: 21028});

        // recordds do not begin with SYSCALL.
        process_record(&mut c, include_bytes!("testdata/record-login.txt"))?;
        process_record(&mut c, include_bytes!("testdata/record-adjntpval.txt"))?;
        process_record(&mut c, include_bytes!("testdata/record-avc-apparmor.txt"))?;

        Ok(())
    }

    #[test]
    #[should_panic(expected = "expected 12 fields")]
    fn duplicate_uids() {
        let ec = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new( |e: &Event| { *ec.borrow_mut() = Some(e.clone()) } );
        c.translate_userdb = true;
        process_record(&mut c, include_bytes!("testdata/record-login.txt")).unwrap();
        if let EventValues::Multi(records) = &ec.borrow().as_ref().unwrap().body[&LOGIN] {
            // Check for: pid uid subj old-auid auid tty old-ses ses res UID OLD-AUID AUID
            let l = records[0].elems.len();
            assert!(l == 12, "expected 12 fields, got {}: {:?}", l, records[0].into_iter().collect::<Vec<_>>());
        } else {
            panic!("expected EventValues::Multi");
        };
    }

    #[test]
    fn translate_uids() {
        let ec = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new( |e: &Event| { *ec.borrow_mut() = Some(e.clone()) } );
        c.translate_userdb = true;
        process_record(&mut c, strip_enriched(include_bytes!("testdata/record-login.txt"))).unwrap();
        if let EventValues::Multi(records) = &ec.borrow().as_ref().unwrap().body[&LOGIN] {
            let mut uid = false;
            let mut old_auid = false;
            let mut auid = false;
            // UID="root" OLD-AUID="unset" AUID="root"
            for (k,v) in &records[0] {
                if &k == "UID" && &v == "root" { uid = true; }
                if &k == "OLD-AUID" && &v == "unset" { old_auid = true; }
                if &k == "AUID" && &v == "root" { auid = true; }
            }
            assert!(uid);
            assert!(old_auid);
            assert!(auid);
        } else {
            panic!("expected EventValues::Multi");
        };
    }

    #[test]
    fn key_label() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new( |e| {
            *ec.borrow_mut() = Some(e.clone());
        } );
        c.proc_label_keys.insert(Vec::from(&b"software_mgmt"[..]));
        c.proc_propagate_labels.insert(Vec::from(&b"software_mgmt"[..]));
        process_record(&mut c, include_bytes!("testdata/tree/00.txt"))?;
        {
            assert!(event_to_json(ec.borrow().as_ref().unwrap())
                    .contains(r#""LABELS":["software_mgmt"]"#),
                    "process gets 'software_mgmt' label from key");
        }

        process_record(&mut c, include_bytes!("testdata/tree/01.txt"))?;
        {
            assert!(event_to_json(ec.borrow().as_ref().unwrap())
                    .contains(r#""LABELS":["software_mgmt"]"#),
                    "child process inherits 'software_mgmt' label");
        }
        
        Ok(())
    }

    #[test]
    fn label_exe() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));
        let emitter = | e: &Event | { *ec.borrow_mut() = Some(e.clone()) };
        let lm = LabelMatcher::new(&[("whoami", "recon")])?;

        let mut c = Coalesce::new(emitter);
        c.label_exe = Some(&lm);
        process_record(&mut c, include_bytes!("testdata/record-execve.txt"))?;
        drop(c);
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["recon"]"#));

        let mut c = Coalesce::new(emitter);
        c.label_exe = Some(&lm);
        process_record(&mut c, strip_enriched(include_bytes!("testdata/record-execve.txt")))?;
        drop(c);
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["recon"]"#));
        
        Ok(())
    }
}
