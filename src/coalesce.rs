use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::io::Write;
use std::ops::Range;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use indexmap::IndexMap;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use serde_json::json;

use crate::constants::{msg_type::*, ARCH_NAMES, SYSCALL_NAMES};
use crate::label_matcher::LabelMatcher;
use crate::parser::parse;
use crate::proc::{get_environ, ProcTable, Process};
use crate::quoted_string::ToQuotedString;
use crate::sockaddr::SocketAddr;
use crate::types::*;
use crate::userdb::UserDB;

/// Collect records in [`EventBody`] context as single or multiple
/// instances.
///
/// Examples for single instances are `SYSCALL`,`EXECVE` (even if the
/// latter can be split across multiple lines). An example for
/// multiple instances is `PATH`.
///
/// "Multi" records are serialized as list-of-maps (`[ { "key":
/// "value", … }, { "key": "value", … } … ]`)
#[derive(Debug, Clone)]
pub enum EventValues {
    // e.g SYSCALL, EXECVE
    Single(Record),
    // e.g. PATH
    Multi(Vec<Record>),
}

impl Serialize for EventValues {
    #[inline(always)]
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            EventValues::Single(rv) => rv.serialize(s),
            EventValues::Multi(rvs) => s.collect_seq(rvs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub node: Option<Vec<u8>>,
    pub id: EventID,
    pub body: IndexMap<MessageType, EventValues>,
    pub filter: bool,
}

impl Event {
    fn new(node: Option<Vec<u8>>, id: EventID) -> Self {
        Event {
            node,
            id,
            body: IndexMap::with_capacity(5),
            filter: false,
        }
    }
}

impl Serialize for Event {
    #[inline(always)]
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let length = self.body.len() + if self.node.is_some() { 2 } else { 1 };
        let mut map = s.serialize_map(Some(length))?;
        map.serialize_key("ID")?;
        map.serialize_value(&self.id)?;
        if let Some(node) = &self.node {
            map.serialize_key("NODE")?;
            map.serialize_value(&node.as_slice().to_quoted_string())?;
        }
        for (k, v) in &self.body {
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

pub struct Settings<'a> {
    /// Generate ARGV and ARGV_STR from EXECVE
    pub execve_argv_list: bool,
    pub execve_argv_string: bool,

    pub execve_env: HashSet<Vec<u8>>,
    pub execve_argv_limit_bytes: Option<usize>,
    pub enrich_container: bool,
    pub enrich_pid: bool,
    pub enrich_parent_info: bool,
    pub enrich_script: bool,

    pub proc_label_keys: HashSet<Vec<u8>>,
    pub proc_propagate_labels: HashSet<Vec<u8>>,

    pub translate_universal: bool,
    pub translate_userdb: bool,

    pub label_exe: Option<&'a LabelMatcher>,
    pub unlabel_exe: Option<&'a LabelMatcher>,
    pub label_script: Option<&'a LabelMatcher>,
    pub unlabel_script: Option<&'a LabelMatcher>,

    pub filter_keys: HashSet<Vec<u8>>,
    pub filter_labels: HashSet<Vec<u8>>,
    pub filter_null_keys: bool,
}

impl Default for Settings<'_> {
    fn default() -> Self {
        Settings {
            execve_argv_list: true,
            execve_argv_string: false,
            execve_env: HashSet::new(),
            execve_argv_limit_bytes: None,
            enrich_container: false,
            enrich_pid: true,
            enrich_parent_info: false,
            enrich_script: true,
            proc_label_keys: HashSet::new(),
            proc_propagate_labels: HashSet::new(),
            translate_universal: false,
            translate_userdb: false,
            label_exe: None,
            unlabel_exe: None,
            label_script: None,
            unlabel_script: None,
            filter_keys: HashSet::new(),
            filter_labels: HashSet::new(),
            filter_null_keys: false,
        }
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
    /// Process table built from observing process-related events
    processes: ProcTable,
    /// Output function
    emit_fn: Box<dyn 'a + FnMut(&Event)>,
    /// Creadential cache
    userdb: UserDB,

    pub settings: Settings<'a>,
}

const EXPIRE_PERIOD: u64 = 1_000;
const EXPIRE_INFLIGHT_TIMEOUT: u64 = 5_000;
const EXPIRE_DONE_TIMEOUT: u64 = 120_000;

/// generate translation of SocketAddr enum to a format similar to
/// what auditd log_format=ENRICHED produces
fn translate_socketaddr(rv: &mut Record, sa: SocketAddr) -> Value {
    let f = SimpleKey::Literal("saddr_fam");
    let m = match sa {
        SocketAddr::Local(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("local"))),
                (
                    SimpleKey::Literal("path"),
                    SimpleValue::Str(rv.put(&sa.path)),
                ),
            ]
        }
        SocketAddr::Inet(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("inet"))),
                (
                    SimpleKey::Literal("addr"),
                    SimpleValue::Str(rv.put(format!("{}", sa.ip()))),
                ),
                (
                    SimpleKey::Literal("port"),
                    SimpleValue::Number(Number::Dec(sa.port().into())),
                ),
            ]
        }
        SocketAddr::AX25(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("ax25"))),
                (
                    SimpleKey::Literal("call"),
                    SimpleValue::Str(rv.put(&sa.call)),
                ),
            ]
        }
        SocketAddr::ATMPVC(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("atmpvc"))),
                (
                    SimpleKey::Literal("itf"),
                    SimpleValue::Number(Number::Dec(sa.itf.into())),
                ),
                (
                    SimpleKey::Literal("vpi"),
                    SimpleValue::Number(Number::Dec(sa.vpi.into())),
                ),
                (
                    SimpleKey::Literal("vci"),
                    SimpleValue::Number(Number::Dec(sa.vci.into())),
                ),
            ]
        }
        SocketAddr::X25(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("x25"))),
                (
                    SimpleKey::Literal("addr"),
                    SimpleValue::Str(rv.put(&sa.address)),
                ),
            ]
        }
        SocketAddr::IPX(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("ipx"))),
                (
                    SimpleKey::Literal("network"),
                    SimpleValue::Number(Number::Hex(sa.network.into())),
                ),
                (
                    SimpleKey::Literal("node"),
                    SimpleValue::Str(rv.put(format!(
                        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                        sa.node[0], sa.node[1], sa.node[2], sa.node[3], sa.node[4], sa.node[5]
                    ))),
                ),
                (
                    SimpleKey::Literal("port"),
                    SimpleValue::Number(Number::Dec(sa.port.into())),
                ),
                (
                    SimpleKey::Literal("type"),
                    SimpleValue::Number(Number::Dec(sa.typ.into())),
                ),
            ]
        }
        SocketAddr::Inet6(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("inet6"))),
                (
                    SimpleKey::Literal("addr"),
                    SimpleValue::Str(rv.put(format!("{}", sa.ip()))),
                ),
                (
                    SimpleKey::Literal("port"),
                    SimpleValue::Number(Number::Dec(sa.port().into())),
                ),
                (
                    SimpleKey::Literal("flowinfo"),
                    SimpleValue::Number(Number::Dec(sa.flowinfo().into())),
                ),
                (
                    SimpleKey::Literal("scope_id"),
                    SimpleValue::Number(Number::Dec(sa.scope_id().into())),
                ),
            ]
        }
        SocketAddr::Netlink(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("netlink"))),
                (
                    SimpleKey::Literal("pid"),
                    SimpleValue::Number(Number::Dec(sa.pid.into())),
                ),
                (
                    SimpleKey::Literal("groups"),
                    SimpleValue::Number(Number::Hex(sa.groups.into())),
                ),
            ]
        }
        SocketAddr::VM(sa) => {
            vec![
                (f, SimpleValue::Str(rv.put("vsock"))),
                (
                    SimpleKey::Literal("cid"),
                    SimpleValue::Number(Number::Dec(sa.cid.into())),
                ),
                (
                    SimpleKey::Literal("port"),
                    SimpleValue::Number(Number::Dec(sa.port.into())),
                ),
            ]
        }
    };
    Value::Map(m)
}

/// Returns a script name from path if exe's dev / inode don't match
///
/// This seems to work with Docker containers but not with Podman.
/// The executable's device and inode are inspected throguh the
/// /proc/<pid>/root/ symlink. This may fail for
///
/// - very short-lived processes
/// - container setups where the container's filesystem is constructed
///   using fuse-overlayfs (observed with
///   podman+fuse-overlayfs/1.4.0-1 on Debian/buster).
///
/// As an extra sanity check, exe is compared with normalized
/// PATH.name. If they are equal, no script is returned.
fn path_script_name(path: &Record, pid: u32, cwd: &[u8], exe: &[u8]) -> Option<NVec> {
    let mut proc_exe_path = Vec::from(format!("/proc/{}/root", pid).as_bytes());
    proc_exe_path.extend(exe);

    let meta = std::fs::metadata(OsStr::from_bytes(&proc_exe_path)).ok()?;
    let (e_dev, e_inode) = (meta.dev(), meta.ino());

    let mut p_dev: Option<u64> = None;
    let mut p_inode: Option<u64> = None;
    let mut name = None;
    for (k, v) in path {
        if k == "name" {
            if let Value::Str(r, _) = v.value {
                let mut pb = PathBuf::new();
                let s = Path::new(OsStr::from_bytes(&path.raw[r.clone()]));
                if !s.is_absolute() {
                    pb.push(OsStr::from_bytes(cwd));
                }
                pb.push(s);
                let mut tpb = PathBuf::new();
                // We can't just use PathBuf::canonicalize here
                // because we don't want symlinks to be rersolved.
                for c in pb.components() {
                    match c {
                        Component::RootDir if tpb.has_root() => {}
                        Component::CurDir => {}
                        Component::ParentDir => {
                            tpb.pop();
                        }
                        _ => tpb.push(c),
                    }
                }
                name = Some(NVec::from(tpb.as_os_str().as_bytes()))
            }
        } else if k == "inode" {
            if let Value::Number(Number::Dec(i)) = v.value {
                p_inode = Some(*i as _);
            }
        } else if k == "dev" {
            if let Value::Str(r, _) = v.value {
                let mut d = 0;
                let value = String::from_utf8_lossy(&v.raw[r.clone()]);
                for p in value.split(|c| c == ':') {
                    if let Ok(parsed) = u64::from_str_radix(p, 16) {
                        d <<= 8;
                        d |= parsed;
                    }
                }
                p_dev = Some(d as _);
            }
            break;
        }
    }
    match (p_dev, p_inode, name) {
        (Some(p_dev), Some(p_inode), _) if p_dev == e_dev && p_inode == e_inode => None,
        (Some(_), Some(_), Some(name)) if name != exe => Some(name),
        _ => None,
    }
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
            settings: Settings::default(),
        }
    }

    pub fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
        if self.settings.translate_userdb {
            self.userdb.populate();
        }
        self.processes = ProcTable::from_proc(
            self.settings.label_exe,
            &self.settings.proc_propagate_labels,
        )
        .map_err(|e| format!("populate proc table: {}", e))?;

        Ok(())
    }

    /// Flush out events
    ///
    /// Called every EXPIRE_PERIOD ms and when Coalesce is destroyed.
    fn expire_inflight(&mut self, now: u64) {
        let node_ids = self
            .inflight
            .keys()
            .filter(|(_, id)| id.timestamp + EXPIRE_INFLIGHT_TIMEOUT < now)
            .cloned()
            .collect::<Vec<_>>();
        for node_id in node_ids {
            if let Some(event) = self.inflight.remove(&node_id) {
                self.emit_event(event);
            }
        }
    }

    fn expire_done(&mut self, now: u64) {
        let node_ids = self
            .done
            .iter()
            .filter(|(_, id)| id.timestamp + EXPIRE_DONE_TIMEOUT < now)
            .cloned()
            .collect::<Vec<_>>();
        for node_id in node_ids {
            self.done.remove(&node_id);
        }
    }

    /// Translates UID, GID and variants, e.g.:
    /// - auid=1000 -> AUID="user"
    /// - ogid=1000 -> OGID="user"
    /// IDs that can't be resolved are translated into "unknown(n)".
    /// `(uint32)-1` is translated into "unset".
    #[inline(always)]
    fn translate_userdb(&mut self, rv: &mut Record, k: &Key, v: &Value) -> Option<(Key, Value)> {
        if !self.settings.translate_userdb {
            return None;
        }
        match k {
            Key::NameUID(r) => {
                if let Value::Number(Number::Dec(d)) = v {
                    let translated = if *d == 0xffffffff {
                        "unset".to_string()
                    } else if let Some(user) = self.userdb.get_user(*d as u32) {
                        user
                    } else {
                        format!("unknown({})", d)
                    };
                    return Some((
                        Key::NameTranslated(r.clone()),
                        Value::Str(rv.put(translated), Quote::Double),
                    ));
                }
            }
            Key::NameGID(r) => {
                if let Value::Number(Number::Dec(d)) = v {
                    let translated = if *d == 0xffffffff {
                        "unset".to_string()
                    } else if let Some(group) = self.userdb.get_group(*d as u32) {
                        group
                    } else {
                        format!("unknown({})", d)
                    };
                    return Some((
                        Key::NameTranslated(r.clone()),
                        Value::Str(rv.put(translated), Quote::Double),
                    ));
                }
            }
            _ => (),
        };
        None
    }

    /// Enrich "pid" entries using `ppid`, `exe`, `ID` (generating
    /// event id) from the shadow process table
    fn enrich_generic_pid(&mut self, rv: &mut Record, k: &Key, v: &Value) -> Option<(Key, Value)> {
        let pid = match v {
            Value::Number(Number::Dec(n)) => *n,
            _ => return None,
        };
        if !self.settings.enrich_pid {
            return None;
        }
        match &k {
            Key::Name(r) if r.ends_with(b"pid") => {
                let key = Key::NameTranslated(r.clone());
                let proc = self.processes.get_process(pid as _)?;
                if proc.event_id.is_none() && proc.exe.is_none() && proc.ppid == 0 {
                    None
                } else {
                    let mut m = Vec::with_capacity(3);
                    if let Some(id) = proc.event_id {
                        m.push((
                            SimpleKey::Literal("ID"),
                            SimpleValue::Str(rv.put(format!("{}", id))),
                        ));
                    }
                    if let Some(exe) = &proc.exe {
                        m.push((SimpleKey::Literal("exe"), SimpleValue::Str(rv.put(exe))));
                    }
                    if proc.ppid != 0 {
                        m.push((
                            SimpleKey::Literal("ppid"),
                            SimpleValue::Number(Number::Dec(proc.ppid.into())),
                        ));
                    }
                    Some((key, Value::Map(m)))
                }
            }
            _ => None,
        }
    }

    /// Rewrite event to normal form
    ///
    /// This function
    /// - turns SYSCALL/a* fields into a single an ARGV list
    /// - turns EXECVE/a* and EXECVE/a*[*] fields into an ARGV list
    /// - turns PROCTITLE/proctitle into a (abbreviated) ARGV list
    /// - translates *uid, *gid, syscall, arch, sockaddr if configured to do so.
    /// - enriches PID and container enrichment if configured to do so.
    /// - collects environment variables for EXECVE events
    /// - registers process in shadow process table for EXECVE events
    fn transform_event(&mut self, ev: &mut Event) {
        let mut arch: Option<u32> = None;
        let mut syscall: Option<u32> = None;
        let mut pid: Option<u32> = None;
        let mut ppid: Option<u32> = None;
        let mut comm: Option<NVec> = None;
        let mut exe: Option<NVec> = None;
        let mut key: Option<NVec> = None;

        let mut arch_name: Option<&'static str> = None;
        let mut syscall_name: Option<&'static str> = None;

        let mut syscall_is_exec = false;

        if let Some(EventValues::Single(rv)) = ev.body.get_mut(&SYSCALL) {
            let mut extra = 0;
            if self.settings.translate_universal {
                extra += 16 // syscall, arch
            }
            if self.settings.translate_userdb {
                extra += 72 // *uid, *gid: 9 entries.
            }
            rv.raw.reserve(extra);
            let mut new = Vec::with_capacity(rv.elems.len() - 3);
            let mut nrv = Record::default();
            let mut argv = Vec::with_capacity(4);
            for (k, v) in &rv.elems {
                match (k, v) {
                    (Key::Arg(_, None), _) => {
                        // FIXME: check argv length
                        argv.push(v.clone());
                        continue;
                    }
                    (Key::ArgLen(_), _) => continue,
                    (Key::Common(c), Value::Number(n)) => match (c, n) {
                        (Common::Arch, Number::Hex(n)) if arch.is_none() => arch = Some(*n as u32),
                        (Common::Syscall, Number::Dec(n)) if syscall.is_none() => {
                            syscall = Some(*n as u32)
                        }
                        (Common::Pid, Number::Dec(n)) if pid.is_none() => pid = Some(*n as u32),
                        (Common::PPid, Number::Dec(n)) if ppid.is_none() => ppid = Some(*n as u32),
                        _ => (),
                    },
                    (Key::Common(c), Value::Str(r, _)) => match c {
                        Common::Comm if comm.is_none() => comm = Some(rv.raw[r.clone()].into()),
                        Common::Exe if exe.is_none() => exe = Some(rv.raw[r.clone()].into()),
                        Common::Key if key.is_none() => key = Some(rv.raw[r.clone()].into()),
                        _ => (),
                    },
                    (Key::Name(name), Value::Str(_, _)) => {
                        match name.as_ref() {
                            b"ARCH" | b"SYSCALL" if self.settings.translate_universal => continue,
                            _ => (),
                        };
                    }
                    _ => {
                        if let Some((k, v)) = self.translate_userdb(&mut nrv, k, v) {
                            nrv.elems.push((k, v));
                        }
                    }
                };
                new.push((k.clone(), v.clone()));
            }
            new.push((Key::Literal("ARGV"), Value::List(argv)));
            rv.elems = new;
            rv.extend(nrv);
        }

        if let Some(EventValues::Single(rv)) = ev.body.get_mut(&EXECVE) {
            let mut new: Vec<(Key, Value)> = Vec::with_capacity(2);
            let mut argv: Vec<Value> = Vec::with_capacity(1);
            for (k, v) in &rv.elems {
                match k {
                    Key::ArgLen(_) => continue,
                    Key::Arg(i, None) => {
                        let idx = *i as usize;
                        if argv.len() <= idx {
                            argv.resize(idx + 1, Value::Empty);
                        };
                        argv[idx] = v.clone();
                    }
                    Key::Arg(i, Some(f)) => {
                        let idx = *i as usize;
                        if argv.len() <= idx {
                            argv.resize(idx + 1, Value::Empty);
                            argv[idx] = Value::Segments(Vec::new());
                        }
                        if let Some(Value::Segments(l)) = argv.get_mut(idx) {
                            let frag = *f as usize;
                            let r = match v {
                                Value::Str(r, _) => r,
                                _ => &Range { start: 0, end: 0 }, // FIXME
                            };
                            if l.len() <= frag {
                                l.resize(frag + 1, 0..0);
                                l[frag] = r.clone();
                            }
                        }
                    }
                    _ => new.push((k.clone(), v.clone())),
                };
            }

            // Strip data from the middle of excessively long ARGV
            if let Some(argv_max) = self.settings.execve_argv_limit_bytes {
                let argv_size: usize = argv.iter().map(|v| 1 + v.str_len()).sum();
                if argv_size > argv_max {
                    let diff = argv_size - argv_max;
                    let skip_range = (argv_size - diff) / 2..(argv_size + diff) / 2;
                    argv = {
                        let mut filtered = Vec::new();
                        let mut start = 0;
                        let mut skipped: Option<(usize, usize)> = None;
                        for arg in argv.iter() {
                            let end = start + arg.str_len();
                            if skip_range.contains(&start) || skip_range.contains(&end) {
                                skipped = match skipped {
                                    None => Some((1, end - start)),
                                    Some((args, bytes)) => {
                                        Some((args + 1, 1 + bytes + (end - start)))
                                    }
                                };
                            } else {
                                if let Some((args, bytes)) = skipped {
                                    filtered.push(Value::Skipped((args, bytes)));
                                    skipped = None;
                                }
                                filtered.push(arg.clone());
                            }
                            start = end + 1;
                        }
                        filtered
                    };
                }
            }

            // ARGV
            if self.settings.execve_argv_list {
                new.push((Key::Literal("ARGV"), Value::List(argv.clone())));
            }
            // ARGV_STR
            if self.settings.execve_argv_string {
                new.push((
                    Key::Literal("ARGV_STR"),
                    Value::StringifiedList(argv.clone()),
                ));
            }

            // ENV
            match pid {
                Some(pid) if !self.settings.execve_env.is_empty() => {
                    if let Ok(vars) = get_environ(pid, |k| self.settings.execve_env.contains(k)) {
                        let map = vars
                            .iter()
                            .map(|(k, v)| (SimpleKey::Str(rv.put(k)), SimpleValue::Str(rv.put(v))))
                            .collect();
                        new.push((Key::Literal("ENV"), Value::Map(map)));
                    }
                }
                _ => (),
            };

            rv.elems = new;
        }

        if let (Some(arch), Some(syscall)) = (arch, syscall) {
            if let Some(an) = ARCH_NAMES.get(&(arch as u32)) {
                arch_name = Some(*an);
                if let Some(sn) = SYSCALL_NAMES
                    .get(*an)
                    .and_then(|syscall_tbl| syscall_tbl.get(&(syscall as u32)))
                {
                    syscall_name = Some(sn);
                    if sn.contains("execve") {
                        syscall_is_exec = true;
                    }
                }
            }
        }

        // register process, add propagated labels from
        // parent if applicable
        let parent: Option<Process> = ppid.and_then(|ppid| self.processes.get_process(ppid));

        if let (Some(pid), Some(ppid), true) = (pid, ppid, syscall_is_exec) {
            self.processes.add_process(
                pid,
                ppid,
                ev.id,
                comm.as_ref().map(|s| s.to_vec()),
                exe.as_ref().map(|s| s.to_vec()),
            );

            if let Some(parent) = &parent {
                for l in self
                    .settings
                    .proc_propagate_labels
                    .intersection(&parent.labels)
                {
                    self.processes.add_label(pid, l);
                }
            }
        }

        if let (Some(pid), Some(key)) = (&pid, &key) {
            if self.settings.proc_label_keys.contains(key.as_ref()) {
                self.processes.add_label(*pid, key);
            }
        }

        if let (Some(exe), Some(pid), true) = (&exe, &pid, syscall_is_exec) {
            if let Some(label_exe) = &self.settings.label_exe {
                for label in label_exe.matches(exe) {
                    self.processes.add_label(*pid, label);
                }
            }
            if let Some(unlabel_exe) = &self.settings.unlabel_exe {
                for label in unlabel_exe.matches(exe) {
                    self.processes.remove_label(*pid, label);
                }
            }
        }

        let script: Option<NVec> = match (self.settings.enrich_script, self.settings.label_script) {
            (false, None) => None,
            _ => match (&exe, pid, ev.body.get(&PATH), syscall_is_exec) {
                (Some(exe), Some(pid), Some(EventValues::Multi(paths)), true) => {
                    let mut cwd = &b"/"[..];
                    if let Some(EventValues::Single(r)) = ev.body.get(&CWD) {
                        if let Some(rv) = r.get("cwd") {
                            if let Value::Str(r, _) = rv.value {
                                cwd = &rv.raw[r.clone()];
                            }
                        }
                    };
                    path_script_name(&paths[0], pid, cwd, exe)
                }
                _ => None,
            },
        };

        if let (Some(pid), Some(script)) = (pid, &script) {
            if let Some(label_script) = self.settings.label_script {
                for label in label_script.matches(script.as_ref()) {
                    self.processes.add_label(pid, label);
                }
            }
            if let Some(unlabel_script) = self.settings.unlabel_script {
                for label in unlabel_script.matches(script.as_ref()) {
                    self.processes.remove_label(pid, label);
                }
            }
        }

        // Since the event may be dropped here, manipulation of any
        // other state should not occur below.
        if let Some(key) = &key {
            if self.settings.filter_keys.contains(key.as_ref()) {
                ev.filter = true;
                return;
            }
        } else {
            if self.settings.filter_null_keys {
                ev.filter = true;
                return;
            }
        }

        let proc: Option<Process> = pid.and_then(|pid| self.processes.get_process(pid));

        for tv in ev.body.iter_mut() {
            match tv {
                (&SYSCALL, EventValues::Single(_)) | (&EXECVE, EventValues::Single(_)) => {}
                (&SOCKADDR, EventValues::Multi(rvs)) => {
                    for mut rv in rvs {
                        let mut new = Vec::with_capacity(rv.elems.len());
                        let mut nrv = Record::default();
                        for (k, v) in &rv.elems {
                            if let (Key::Name(name), Value::Str(vr, _)) = (k, v) {
                                match name.as_ref() {
                                    b"saddr" if self.settings.translate_universal => {
                                        if let Ok(sa) = SocketAddr::parse(&rv.raw[vr.clone()]) {
                                            let kv = (
                                                Key::Literal("SADDR"),
                                                translate_socketaddr(&mut nrv, sa),
                                            );
                                            nrv.elems.push(kv);
                                            continue;
                                        }
                                    }
                                    b"SADDR" if self.settings.translate_universal => continue,
                                    _ => {}
                                }
                            }
                            new.push((k.clone(), v.clone()));
                        }
                        rv.elems = new;
                        rv.extend(nrv);
                    }
                }
                (&PROCTITLE, EventValues::Single(rv)) => {
                    if let Some(v) = rv.get(b"proctitle") {
                        if let Value::Str(r, _) = v.value {
                            let mut argv: Vec<Value> = Vec::new();
                            let mut prev = r.start;
                            for i in r.start..=r.end {
                                if (i == r.end || rv.raw[i] == 0) && !(prev..i).is_empty() {
                                    argv.push(Value::Str(prev..i, Quote::None));
                                    prev = i + 1;
                                }
                            }
                            rv.elems = vec![(Key::Literal("ARGV"), Value::List(argv))];
                        }
                    }
                }
                (_, EventValues::Single(rv)) => {
                    let mut nrv = Record::default();
                    for (k, v) in &rv.elems {
                        if let Some((k, v)) = self.translate_userdb(&mut nrv, k, v) {
                            nrv.elems.push((k, v));
                        } else if let Some((k, v)) = self.enrich_generic_pid(&mut nrv, k, v) {
                            nrv.elems.push((k, v));
                        }
                    }
                    rv.extend(nrv);
                }
                (_, EventValues::Multi(rvs)) => {
                    for rv in rvs {
                        let mut nrv = Record::default();
                        for (k, v) in &rv.elems {
                            if let Some((k, v)) = self.translate_userdb(&mut nrv, k, v) {
                                nrv.elems.push((k, v));
                            } else if let Some((k, v)) = self.enrich_generic_pid(&mut nrv, k, v) {
                                nrv.elems.push((k, v));
                            }
                        }
                        rv.extend(nrv);
                    }
                }
            }
        }

        // PARENT_INFO
        if let (true, Some(parent)) = (self.settings.enrich_parent_info, &parent) {
            let mut pi = Record::default();
            if let Some(id) = parent.event_id {
                let r = pi.put(format!("{}", id));
                pi.elems
                    .push((Key::Literal("ID"), Value::Str(r, Quote::None)));
            }
            if let Some(comm) = &parent.comm {
                let r = pi.put(&comm);
                pi.elems
                    .push((Key::Literal("comm"), Value::Str(r, Quote::None)));
            }
            if let Some(exe) = &parent.exe {
                let r = pi.put(&exe);
                pi.elems
                    .push((Key::Literal("exe"), Value::Str(r, Quote::None)));
            }
            let kv = (
                Key::Literal("ppid"),
                Value::Number(Number::Dec(parent.ppid as i64)),
            );
            pi.elems.push(kv);
            ev.body.insert(PARENT_INFO, EventValues::Single(pi));
        }

        if let Some(EventValues::Single(sc)) = ev.body.get_mut(&SYSCALL) {
            if let (true, Some(an), Some(sn)) =
                (self.settings.translate_universal, arch_name, syscall_name)
            {
                sc.elems.push((Key::Literal("ARCH"), Value::Literal(an)));
                sc.elems.push((Key::Literal("SYSCALL"), Value::Literal(sn)));
            }

            if let (true, Some(parent)) = (self.settings.enrich_pid, &parent) {
                let mut m = Vec::with_capacity(4);
                if let Some(id) = &parent.event_id {
                    m.push((
                        SimpleKey::Literal("EVENT_ID"),
                        SimpleValue::Str(sc.put(format!("{}", id))),
                    ));
                }
                if let Some(comm) = &parent.comm {
                    m.push((SimpleKey::Literal("comm"), SimpleValue::Str(sc.put(comm))));
                }
                if let Some(exe) = &parent.exe {
                    m.push((SimpleKey::Literal("exe"), SimpleValue::Str(sc.put(exe))));
                }
                if parent.ppid != 0 {
                    m.push((
                        SimpleKey::Literal("ppid"),
                        SimpleValue::Number(Number::Dec(parent.ppid.into())),
                    ));
                }
                sc.elems.push((Key::Literal("PPID"), Value::Map(m)));
            }

            if let (true, Some(script)) = (self.settings.enrich_script, script) {
                let (k, v) = (
                    Key::Literal("SCRIPT"),
                    Value::Str(sc.put(script), Quote::None),
                );
                sc.elems.push((k, v));
            }

            if let Some(proc) = proc {
                if let (true, Some(event_id)) = (self.settings.enrich_pid, proc.event_id) {
                    let m = Value::Map(vec![(
                        SimpleKey::Literal("EVENT_ID"),
                        SimpleValue::Str(sc.put(format!("{}", event_id))),
                    )]);
                    sc.elems.push((Key::Literal("PID"), m));
                }

                if !proc.labels.is_empty() {
                    if proc
                        .labels
                        .iter()
                        .any(|x| self.settings.filter_labels.contains(x))
                    {
                        ev.filter = true;
                    }
                    let labels = proc
                        .labels
                        .iter()
                        .map(|l| Value::Str(sc.put(l), Quote::None))
                        .collect::<Vec<_>>();
                    sc.elems.push((Key::Literal("LABELS"), Value::List(labels)));
                }

                if let (true, Some(c)) = (self.settings.enrich_container, &proc.container_info) {
                    let mut ci = Record::default();
                    let r = ci.put(&c.id);
                    ci.elems
                        .push((Key::Literal("ID"), Value::Str(r, Quote::None)));
                    ev.body.insert(CONTAINER_INFO, EventValues::Single(ci));
                }
            }
        }
    }

    /// Do bookkeeping on event, transform, emit it via the provided
    /// output function.
    fn emit_event(&mut self, mut ev: Event) {
        self.done.insert((ev.node.clone(), ev.id));

        self.transform_event(&mut ev);
        if !ev.filter {
            (self.emit_fn)(&ev)
        }
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
        let skip_enriched = self.settings.translate_universal && self.settings.translate_userdb;
        let (node, typ, id, rv) = parse(line, skip_enriched)?;
        let nid = (node.clone(), id);

        // clean out state every EXPIRE_PERIOD
        match self.next_expire {
            Some(t) if t < id.timestamp => {
                self.expire_inflight(id.timestamp);
                self.expire_done(id.timestamp);
                self.processes.expire();
                self.next_expire = Some(id.timestamp + EXPIRE_PERIOD)
            }
            None => self.next_expire = Some(id.timestamp + EXPIRE_PERIOD),
            _ => (),
        };

        if typ == EOE {
            if self.done.contains(&nid) {
                return Err(format!("duplicate event id {}", id).into());
            }
            let ev = self
                .inflight
                .remove(&nid)
                .ok_or(format!("Event id {} for EOE marker not found", &id))?;
            self.emit_event(ev);
        } else if typ.is_multipart() {
            // kernel-level messages
            if !self.inflight.contains_key(&nid) {
                self.inflight.insert(nid.clone(), Event::new(node, id));
            }
            let ev = self.inflight.get_mut(&nid).unwrap();
            match ev.body.get_mut(&typ) {
                Some(EventValues::Single(v)) => v.extend(rv),
                Some(EventValues::Multi(v)) => v.push(rv),
                None => match typ {
                    SYSCALL => {
                        ev.body.insert(typ, EventValues::Single(rv));
                    }
                    EXECVE | PROCTITLE | CWD => {
                        ev.body.insert(typ, EventValues::Single(rv));
                    }
                    _ => {
                        ev.body.insert(typ, EventValues::Multi(vec![rv]));
                    }
                },
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

    pub fn dump_state(&self, mut w: &mut dyn Write) -> Result<(), Box<dyn Error>> {
        serde_json::to_writer(
            &mut w,
            &json!({
                "ts": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                "message": {
                    "type": "dump_state",
                    "label_exe": self.settings.label_exe,
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
            }),
        )?;
        w.write_all(b"\n")?;
        w.flush()?;
        Ok(())
    }
}

impl Drop for Coalesce<'_> {
    fn drop(&mut self) {
        self.expire_inflight(u64::MAX)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    use std::cell::RefCell;
    use std::io::{BufRead, BufReader};
    use std::rc::Rc;

    fn event_to_json(e: &Event) -> String {
        let mut out = vec![];
        serde_json::to_writer(&mut out, e).unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    #[test]
    fn dump_state() -> Result<(), Box<dyn Error>> {
        let mut c = Coalesce::new(|_| {});
        c.initialize()?;
        c.process_line(br#"type=SYSCALL msg=audit(1615114232.375:15558): arch=c000003e syscall=59 success=yes exit=0 a0=63b29337fd18 a1=63b293387d58 a2=63b293375640 a3=fffffffffffff000 items=2 ppid=10883 pid=10884 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm="whoami" exe="/usr/bin/whoami" key=(null)
"#.to_vec())?;
        let mut buf: Vec<u8> = vec![];
        c.dump_state(&mut buf)?;
        println!("{}", String::from_utf8_lossy(&buf));
        Ok(())
    }

    fn strip_enriched<T>(text: T) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        let mut out = vec![];
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

    fn process_record<T>(c: &mut Coalesce, text: T) -> Result<(), Box<dyn Error>>
    where
        T: AsRef<[u8]>,
    {
        for line in BufReader::new(text.as_ref())
            .lines()
            .filter(|line| match line {
                Ok(l) if l.len() == 0 => false,
                Ok(l) if l.starts_with("#") => false,
                _ => true,
            })
        {
            let mut line = line.unwrap().clone();
            line.push('\n');
            c.process_line(line.as_bytes().to_vec())?;
        }
        Ok(())
    }

    #[test]
    fn coalesce() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(Vec::new()));
        let mut c = Coalesce::new(|e: &Event| {
            ec.borrow_mut().push(e.clone());
        });

        process_record(&mut c, include_bytes!("testdata/line-user-acct.txt"))?;
        assert_eq!(
            ec.borrow().last().unwrap().id,
            EventID {
                timestamp: 1615113648981,
                sequence: 15220
            }
        );

        if let Ok(_) = process_record(&mut c, include_bytes!("testdata/line-user-acct.txt")) {
            panic!("failed to detect duplicate entries");
        };

        process_record(&mut c, include_bytes!("testdata/record-execve.txt"))?;
        assert_eq!(
            ec.borrow().last().unwrap().id,
            EventID {
                timestamp: 1615114232375,
                sequence: 15558
            }
        );

        process_record(&mut c, include_bytes!("testdata/record-execve-long.txt"))?;
        assert_eq!(
            ec.borrow().last().unwrap().id,
            EventID {
                timestamp: 1615150974493,
                sequence: 21028
            }
        );

        // recordds do not begin with SYSCALL.
        process_record(&mut c, include_bytes!("testdata/record-login.txt"))?;
        process_record(&mut c, include_bytes!("testdata/record-adjntpval.txt"))?;
        process_record(&mut c, include_bytes!("testdata/record-avc-apparmor.txt"))?;

        Ok(())
    }

    #[test]
    fn duplicate_uids() {
        let ec = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(|e: &Event| *ec.borrow_mut() = Some(e.clone()));
        c.settings.translate_userdb = true;
        c.settings.translate_universal = true;
        process_record(&mut c, include_bytes!("testdata/record-login.txt")).unwrap();
        if let EventValues::Multi(records) = &ec.borrow().as_ref().unwrap().body[&LOGIN] {
            // Check for: pid uid subj old-auid auid tty old-ses ses res UID OLD-AUID AUID
            let l = records[0].elems.len();
            assert!(
                l == 12,
                "expected 12 fields, got {}: {:?}",
                l,
                records[0].into_iter().collect::<Vec<_>>()
            );
        } else {
            panic!("expected EventValues::Multi");
        };
    }

    #[test]
    fn keep_enriched_syscalls() {
        let ec = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(|e: &Event| *ec.borrow_mut() = Some(e.clone()));
        process_record(&mut c, include_bytes!("testdata/record-execve.txt")).unwrap();
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#""ARCH":"x86_64""#));
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#""SYSCALL":"execve""#));
    }

    #[test]
    fn translate_uids() {
        let ec = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(|e: &Event| *ec.borrow_mut() = Some(e.clone()));
        c.settings.translate_userdb = true;
        c.settings.translate_universal = true;
        process_record(
            &mut c,
            strip_enriched(include_bytes!("testdata/record-login.txt")),
        )
        .unwrap();

        if let EventValues::Single(record) = &ec.borrow().as_ref().unwrap().body[&SYSCALL] {
            let mut uids = 0;
            let mut gids = 0;
            for (k, v) in record {
                if k.to_string().ends_with("UID") {
                    uids += 1;
                    assert!(&v == "root", "Got {}={:?}, expected root", k, v);
                }
                if k.to_string().ends_with("GID") {
                    gids += 1;
                    assert!(&v == "root", "Got {}={:?}, expected root", k, v);
                }
            }
            assert!(
                uids == 5 && gids == 4,
                "Got {} uids/{} gids, expected 5/4",
                uids,
                gids
            );
        }

        if let EventValues::Multi(records) = &ec.borrow().as_ref().unwrap().body[&LOGIN] {
            let mut uid = false;
            let mut old_auid = false;
            let mut auid = false;
            // UID="root" OLD-AUID="unset" AUID="root"
            for (k, v) in &records[0] {
                if k == "UID" && &v == "root" {
                    uid = true;
                }
                if k == "OLD-AUID" && &v == "unset" {
                    old_auid = true;
                }
                if k == "AUID" && &v == "root" {
                    auid = true;
                }
            }
            assert!(
                uid,
                "missing UID: {:?}",
                records[0].into_iter().collect::<Vec<_>>()
            );
            assert!(
                old_auid,
                "missing OLD-AUID: {:?}",
                records[0].into_iter().collect::<Vec<_>>()
            );
            assert!(
                auid,
                "missing AUID: {:?}",
                records[0].into_iter().collect::<Vec<_>>()
            );
        } else {
            panic!("expected EventValues::Multi");
        };
    }

    #[test]
    fn key_label() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(|e| {
            *ec.borrow_mut() = Some(e.clone());
        });
        c.settings
            .proc_label_keys
            .insert(Vec::from(&b"software_mgmt"[..]));
        c.settings
            .proc_propagate_labels
            .insert(Vec::from(&b"software_mgmt"[..]));
        process_record(&mut c, include_bytes!("testdata/tree/00.txt"))?;
        {
            assert!(
                event_to_json(ec.borrow().as_ref().unwrap())
                    .contains(r#""LABELS":["software_mgmt"]"#),
                "process gets 'software_mgmt' label from key"
            );
        }

        process_record(&mut c, include_bytes!("testdata/tree/01.txt"))?;
        {
            assert!(
                event_to_json(ec.borrow().as_ref().unwrap())
                    .contains(r#""LABELS":["software_mgmt"]"#),
                "child process inherits 'software_mgmt' label"
            );
        }

        Ok(())
    }

    #[test]
    fn label_exe() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));
        let emitter = |e: &Event| *ec.borrow_mut() = Some(e.clone());
        let lm = LabelMatcher::new(&[("whoami", "recon")])?;

        let mut c = Coalesce::new(emitter);
        c.settings.label_exe = Some(&lm);
        process_record(&mut c, include_bytes!("testdata/record-execve.txt"))?;
        drop(c);
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["recon"]"#));

        let mut c = Coalesce::new(emitter);
        c.settings.label_exe = Some(&lm);
        process_record(
            &mut c,
            strip_enriched(include_bytes!("testdata/record-execve.txt")),
        )?;
        drop(c);
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["recon"]"#));

        Ok(())
    }

    #[test]
    fn filter_key() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));
        let emitter = |e: &Event| *ec.borrow_mut() = Some(e.clone());

        let mut c = Coalesce::new(emitter);
        c.settings
            .filter_keys
            .insert(Vec::from(&b"filter-this"[..]));
        c.settings.filter_keys.insert(Vec::from(&b"this-too"[..]));
        process_record(&mut c, include_bytes!("testdata/record-syscall-key.txt"))?;
        drop(c);
        assert!(ec.borrow().as_ref().is_none());

        let mut c = Coalesce::new(emitter);
        c.settings.filter_null_keys = true;
        process_record(
            &mut c,
            include_bytes!("testdata/record-syscall-nullkey.txt"),
        )?;
        drop(c);
        assert!(ec.borrow().as_ref().is_none());

        let mut c = Coalesce::new(emitter);
        c.settings
            .filter_keys
            .insert(Vec::from(&b"random-filter"[..]));
        process_record(&mut c, include_bytes!("testdata/record-login.txt"))?;
        drop(c);
        assert!(!ec.borrow().as_ref().is_none());

        Ok(())
    }

    #[test]
    fn filter_label() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(|e| {
            *ec.borrow_mut() = Some(e.clone());
        });
        c.settings
            .proc_label_keys
            .insert(Vec::from(&b"software_mgmt"[..]));
        c.settings
            .filter_labels
            .insert(Vec::from(&b"software_mgmt"[..]));
        c.settings
            .proc_propagate_labels
            .insert(Vec::from(&b"software_mgmt"[..]));

        process_record(&mut c, include_bytes!("testdata/tree/00.txt"))?;
        {
            assert!(ec.borrow().as_ref().is_none());
        }

        process_record(&mut c, include_bytes!("testdata/tree/01.txt"))?;
        {
            assert!(ec.borrow().as_ref().is_none());
        }

        process_record(&mut c, include_bytes!("testdata/record-login.txt"))?;
        {
            assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"/usr/sbin/cron"#));
        }

        drop(c);

        Ok(())
    }

    #[test]
    fn strip_long_argv() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(|e| {
            *ec.borrow_mut() = Some(e.clone());
        });

        c.settings.execve_argv_limit_bytes = Some(10000);
        let mut buf = vec![];
        let msgid = "1663143990.204:2148478";
        let npath = 40000;

        buf.extend(
            format!(r#"type=SYSCALL msg=audit({}): arch=c000003e syscall=59 success=yes exit=0 a0=1468e584be18 a1=1468e57f5078 a2=1468e584bd68 a3=7ffc3e352220 items=2 ppid=9264 pid=9279 auid=4294967295 uid=995 gid=992 euid=995 suid=995 fsuid=995 egid=992 sgid=992 fsgid=992 tty=(none) ses=4294967295 comm="find" exe="/usr/bin/find" key=(null)
"#, msgid).bytes());
        buf.extend(
            format!(
                r#"type=EXECVE msg=audit({}): argc={} a0="/usr/bin/find" "#,
                msgid,
                npath + 9
            )
            .bytes(),
        );
        for i in 1..npath {
            if i % 70 == 0 {
                buf.extend(format!("\ntype=EXECVE msg=audit({}): ", msgid).bytes());
            } else {
                buf.push(b' ');
            }
            buf.extend(format!(r#"a{}="/opt/app/redacted/to/protect/the/guilty/output_processing.2022-09-06.{:05}.garbage""#,i,i).bytes());
        }
        // buf.extend(format!("type=EXECVE msg=audit({}):", msgid).bytes());
        for (i, param) in [
            "-type",
            "f",
            "-mtime",
            "+7",
            "-exec",
            "/usr/bin/rm",
            "-f",
            "{}",
            ";",
        ]
        .iter()
        .enumerate()
        {
            buf.extend(format!(r#" a{}="{}""#, npath + i, param).bytes());
        }
        buf.extend(format!("\ntype=EOE msg=audit({}): \n", msgid).bytes());

        process_record(&mut c, &buf)?;
        {
            let output = event_to_json(ec.borrow().as_ref().unwrap());
            assert!(output.len() < 15000);
            assert!(
                output.find(".00020.garbage").is_some(),
                "Can't find start of argv"
            );
            assert!(
                output.find(".39980.garbage").is_some(),
                "Can't find end of argv"
            );
            assert!(
                output.find(".20000.garbage").is_none(),
                "Should not see middle of argv"
            );
        }

        Ok(())
    }

    #[test]
    #[ignore = "bug needs fixing"]
    fn shell_proc_trace() {
        let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));
        let mut c = Coalesce::new(|e| events.borrow_mut().push(e.clone()));

        c.settings.proc_label_keys = [b"test-script".to_vec()].into();
        c.settings.proc_propagate_labels = [b"test-script".to_vec()].into();

        process_record(&mut c, include_bytes!("testdata/shell-proc-trace.txt")).unwrap();

        let events = events.borrow();

        let fork_ev = events
            .iter()
            .find(|e| e.id.to_string() == "1682609045.530:29241")
            .unwrap();
        assert!(event_to_json(&fork_ev).contains(r#""LABELS":["test-script"]"#));
        let script_ev = events
            .iter()
            .find(|e| e.id.to_string() == "1682609045.526:29238")
            .unwrap();
        assert!(event_to_json(&script_ev).contains(r#""LABELS":["test-script"]"#));
        let grep_ev = events
            .iter()
            .find(|e| e.id.to_string() == "1682609045.530:29242")
            .unwrap();
        assert!(event_to_json(&grep_ev).contains(r#""LABELS":["test-script"]"#));
        let echo_ev = events
            .iter()
            .find(|e| e.id.to_string() == "1682609045.530:29244")
            .unwrap();
        assert!(event_to_json(&echo_ev).contains(r#""LABELS":["test-script"]"#));
        let sed_ev = events
            .iter()
            .find(|e| e.id.to_string() == "1682609045.534:29245")
            .unwrap();
        assert!(event_to_json(&sed_ev).contains(r#""LABELS":["test-script"]"#));
    }
}
