use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use faster_hex::hex_string;

use serde_json::json;

use crate::constants::{msg_type::*, ARCH_NAMES, SYSCALL_NAMES};
use crate::label_matcher::LabelMatcher;
use crate::parser::{parse, ParseError};
use crate::proc::{self, ContainerInfo, ProcTable, Process, ProcessKey};
#[cfg(all(feature = "procfs", target_os = "linux"))]
use crate::procfs;
#[cfg(target_os = "linux")]
use crate::sockaddr::SocketAddr;
use crate::types::*;
use crate::userdb::UserDB;

use thiserror::Error;

#[derive(Clone)]
pub struct Settings {
    /// Generate ARGV and ARGV_STR from EXECVE
    pub execve_argv_list: bool,
    pub execve_argv_string: bool,

    pub execve_env: HashSet<Vec<u8>>,
    pub execve_argv_limit_bytes: Option<usize>,
    pub enrich_container: bool,
    pub enrich_pid: bool,
    pub enrich_script: bool,
    pub enrich_uid_groups: bool,

    pub proc_label_keys: HashSet<Vec<u8>>,
    pub proc_propagate_labels: HashSet<Vec<u8>>,

    pub translate_universal: bool,
    pub translate_userdb: bool,
    pub drop_translated: bool,

    pub label_exe: Option<LabelMatcher>,
    pub unlabel_exe: Option<LabelMatcher>,
    pub label_script: Option<LabelMatcher>,
    pub unlabel_script: Option<LabelMatcher>,

    pub filter_keys: HashSet<Vec<u8>>,
    pub filter_labels: HashSet<Vec<u8>>,
    pub filter_null_keys: bool,
    pub filter_raw_lines: regex::bytes::RegexSet,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            execve_argv_list: true,
            execve_argv_string: false,
            execve_env: HashSet::new(),
            execve_argv_limit_bytes: None,
            enrich_container: false,
            enrich_pid: true,
            enrich_script: true,
            enrich_uid_groups: true,
            proc_label_keys: HashSet::new(),
            proc_propagate_labels: HashSet::new(),
            translate_universal: false,
            translate_userdb: false,
            drop_translated: false,
            label_exe: None,
            unlabel_exe: None,
            label_script: None,
            unlabel_script: None,
            filter_keys: HashSet::new(),
            filter_labels: HashSet::new(),
            filter_null_keys: false,
            filter_raw_lines: regex::bytes::RegexSet::empty(),
        }
    }
}

#[derive(Debug, Error)]
pub enum CoalesceError {
    #[error("{0}")]
    Parse(ParseError),
    #[error("duplicate event id {0}")]
    DuplicateEvent(EventID),
    #[error("Event id {0} for EOE marker not found")]
    SpuriousEOE(EventID),
}

/// Coalesce collects Audit Records from individual lines and assembles them to Events
pub struct Coalesce<'a, 'ev> {
    /// Events that are being collected/processed
    inflight: BTreeMap<(Option<Vec<u8>>, EventID), Event<'ev>>,
    /// Event IDs that have been recently processed
    done: HashSet<(Option<Vec<u8>>, EventID)>,
    /// Timestamp for next cleanup
    next_expire: Option<u64>,
    /// Process table built from observing process-related events
    processes: ProcTable,
    /// Output function
    emit_fn: Box<dyn 'a + FnMut(&Event<'ev>)>,
    /// Creadential cache
    userdb: UserDB,

    pub settings: Settings,
}

const EXPIRE_PERIOD: u64 = 1_000;
const EXPIRE_INFLIGHT_TIMEOUT: u64 = 5_000;
const EXPIRE_DONE_TIMEOUT: u64 = 120_000;

/// generate translation of SocketAddr enum to a format similar to
/// what auditd log_format=ENRICHED produces
#[cfg(target_os = "linux")]
fn add_translated_socketaddr(rv: &mut Record, sa: SocketAddr) {
    let mut m: Vec<(Key, Value)> = Vec::with_capacity(5);
    match sa {
        SocketAddr::Local(sa) => {
            m.push(("saddr_fam".into(), "local".into()));
            m.push(("path".into(), sa.path.into()));
        }
        SocketAddr::Inet(sa) => {
            m.push(("saddr_fam".into(), "inet".into()));
            m.push(("addr".into(), format!("{}", sa.ip()).into()));
            m.push(("port".into(), (sa.port() as i64).into()));
        }
        SocketAddr::AX25(sa) => {
            m.push(("saddr_fam".into(), "ax25".into()));
            m.push(("call".into(), Vec::from(sa.call).into()));
        }
        SocketAddr::ATMPVC(sa) => {
            m.push(("saddr_fam".into(), "atmpvc".into()));
            m.push(("itf".into(), (sa.itf as i64).into()));
            m.push(("vpi".into(), (sa.vpi as i64).into()));
            m.push(("vci".into(), (sa.vci as i64).into()));
        }
        SocketAddr::X25(sa) => {
            m.push(("saddr_fam".into(), "x25".into()));
            m.push(("addr".into(), Vec::from(sa.address).into()));
        }
        SocketAddr::IPX(sa) => {
            m.push(("saddr_fam".into(), "ipx".into()));
            m.push((
                "network".into(),
                Value::Number(Number::Hex(sa.network.into())),
            ));
            m.push((
                "node".into(),
                format!(
                    "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    sa.node[0], sa.node[1], sa.node[2], sa.node[3], sa.node[4], sa.node[5]
                )
                .into(),
            ));
            m.push(("port".into(), (sa.port as i64).into()));
            m.push(("type".into(), (sa.typ as i64).into()));
        }
        SocketAddr::Inet6(sa) => {
            m.push(("saddr_fam".into(), "inet6".into()));
            m.push(("addr".into(), format!("{}", sa.ip()).into()));
            m.push(("port".into(), (sa.port() as i64).into()));
            m.push(("flowinfo".into(), (sa.flowinfo() as i64).into()));
            m.push(("scope_id".into(), (sa.scope_id() as i64).into()));
        }
        SocketAddr::Netlink(sa) => {
            m.push(("saddr_fam".into(), "netlink".into()));
            m.push(("pid".into(), (sa.pid as i64).into()));
            m.push((
                "groups".into(),
                Value::Number(Number::Hex(sa.groups.into())),
            ));
        }
        SocketAddr::VM(sa) => {
            m.push(("saddr_fam".into(), "vsock".into()));
            m.push(("cid".into(), (sa.cid as i64).into()));
            m.push(("port".into(), (sa.port as i64).into()));
        }
    };
    rv.push(("SADDRR".into(), Value::Map(m)));
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
#[cfg(all(feature = "procfs", target_os = "linux"))]
fn path_script_name(path: &Record, pid: u32, ppid: u32, cwd: &[u8], exe: &[u8]) -> Option<NVec> {
    use std::{
        ffi::OsStr,
        os::unix::{ffi::OsStrExt, fs::MetadataExt},
        path::{Component, Path, PathBuf},
    };

    let meta = procfs::pid_path_metadata(pid, exe)
        .or_else(|_| procfs::pid_path_metadata(ppid, exe))
        .ok()?;

    let (e_dev, e_inode) = (meta.dev(), meta.ino());

    let mut p_dev: Option<u64> = None;
    let mut p_inode: Option<u64> = None;
    let mut name = None;
    for (k, v) in path {
        if k == "name" {
            if let Value::Str(r, _) = v {
                let mut pb = PathBuf::new();
                let s = Path::new(OsStr::from_bytes(r));
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
            if let Value::Number(Number::Dec(i)) = v {
                p_inode = Some(*i as _);
            }
        } else if k == "dev" {
            if let Value::Str(r, _) = v {
                p_dev = String::from_utf8_lossy(r)
                    .split(|c| c == ':')
                    .filter_map(|part| u64::from_str_radix(part, 16).ok())
                    .collect::<Vec<_>>()
                    .try_into()
                    .ok()
                    .map(|a: [u64; 2]| nix::sys::stat::makedev(a[0], a[1]));
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

/// Create an enriched pid entry in rv.
fn add_record_procinfo(rec: &mut Record, key: &[u8], proc: &Process, include_names: bool) {
    let mut m: Vec<(Key, Value)> = Vec::with_capacity(4);
    match &proc.key {
        ProcessKey::Event(id) => {
            m.push(("EVENT_ID".into(), format!("{id}").into()));
        }
        ProcessKey::Observed { time, pid: _ } => {
            let (sec, msec) = (time / 1000, time % 1000);
            m.push(("START_TIME".into(), format!("{sec}.{msec:03}").into()));
        }
    }
    if include_names {
        if let Some(comm) = &proc.comm {
            m.push(("comm".into(), Value::from(comm.as_slice())));
        }
        if let Some(exe) = &proc.exe {
            m.push(("exe".into(), Value::from(exe.as_slice())));
        }
        if proc.ppid != 0 {
            m.push(("ppid".into(), Value::from(proc.ppid as i64)));
        }
    }

    rec.push((Key::NameTranslated(key.into()), Value::Map(m)));
}

impl<'a, 'ev> Coalesce<'a, 'ev> {
    /// Creates a `Coalsesce`. `emit_fn` is the function that takes
    /// completed events.
    pub fn new<F: 'a + FnMut(&Event<'ev>)>(emit_fn: F) -> Self {
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

    pub fn initialize(&mut self) -> Result<(), proc::ProcError> {
        if self.settings.translate_userdb {
            self.userdb.populate();
        }
        self.processes = ProcTable::from_proc(
            self.settings.label_exe.clone(),
            &self.settings.proc_propagate_labels,
        )?;

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
    fn add_record_userdb(&mut self, rec: &mut Record, key: &Key, value: &Value) -> bool {
        if !self.settings.translate_userdb {
            return false;
        }
        match (key, value) {
            (Key::NameUID(r), Value::Number(Number::Dec(d))) => {
                let translated = if *d == 0xffffffff {
                    "unset".to_string()
                } else if let Some(user) = self.userdb.get_user(*d as u32) {
                    user
                } else {
                    format!("unknown({})", d)
                };
                rec.push((Key::NameTranslated(r.clone()), Value::from(translated)));
                if self.settings.enrich_uid_groups && r.as_slice() == b"uid" {
                    if let Some(names) = self.userdb.get_user_groups(*d as _) {
                        rec.push((
                            Key::Literal("UID_GROUPS"),
                            Value::List(names.iter().map(|n| Value::from(n.as_bytes())).collect()),
                        ));
                    }
                }
                true
            }
            (Key::NameGID(r), Value::Number(Number::Dec(d))) => {
                let translated = if *d == 0xffffffff {
                    "unset".to_string()
                } else if let Some(group) = self.userdb.get_group(*d as u32) {
                    group
                } else {
                    format!("unknown({})", d)
                };
                rec.push((Key::NameTranslated(r.clone()), Value::from(translated)));
                true
            }
            _ => false,
        }
    }

    /// Enrich "pid" entries using `ppid`, `exe`, `ID` (generating
    /// event id) from the shadow process table
    fn enrich_pid(&mut self, rv: &mut Record, k: &Key, v: &Value) {
        if !self.settings.enrich_pid {
            return;
        }
        let name = match &k {
            Key::Common(Common::Pid) => &b"pid"[..],
            Key::Common(Common::PPid) => &b"ppid"[..],
            Key::Name(r) if r.ends_with(b"pid") => r.as_ref(),
            _ => return,
        };
        if let Value::Number(Number::Dec(pid)) = v {
            if let Some(proc) = self.processes.get_or_retrieve(*pid as _) {
                add_record_procinfo(rv, name, proc, true)
            }
        }
    }

    /// Apply uid, gid, pid enrichment to generic records
    fn enrich_generic(&mut self, rv: &mut Record) {
        let mut nrv = Record::default();
        rv.retain(|(k, v)| {
            if self.add_record_userdb(&mut nrv, k, v) {
                if self.settings.drop_translated {
                    return false;
                }
            } else {
                self.enrich_pid(&mut nrv, k, v);
            }
            true
        });
        rv.concat(nrv);
    }

    /// Transform PROCTITLE record
    ///
    /// The flat proctitle field is turned into a list.
    fn transform_proctitle(&mut self, rv: &mut Record) {
        let mut argv = vec![];
        rv.retain(|(k, v)| {
            match (k, v) {
                (k, Value::Str(r, _)) if k == "proctitle" => {
                    argv = r
                        .split(|c| *c == 0)
                        .map(|arg| {
                            // (assumed) safety:
                            // We are adding references to the
                            // same memory regions back to rv.
                            let arg = unsafe {
                                &*std::ptr::slice_from_raw_parts(arg.as_ptr(), arg.len())
                            };
                            Value::Str(arg, Quote::None)
                        })
                        .collect();
                    false
                }
                _ => true,
            }
        });
        if !argv.is_empty() {
            rv.push(("ARGV".into(), Value::List(argv)));
        }
    }

    /// Enrich SOCKADDR record
    fn enrich_sockaddr(&mut self, rv: &mut Record) {
        let mut nrv = Record::default();
        rv.retain(|(k, v)| match (k, v) {
            (k, Value::Str(vr, _q)) if self.settings.translate_universal => {
                if k == "saddr" {
                    #[cfg(target_os = "linux")]
                    if let Ok(sa) = SocketAddr::parse(vr) {
                        add_translated_socketaddr(&mut nrv, sa);
                        return false;
                    }
                } else if k == "SADDR" {
                    return false;
                }
                true
            }
            _ => true,
        });
        rv.concat(nrv);
    }

    /// Enrich SYSCALL record
    ///
    /// Add ARCH, SYSCALL, PID, PPID, SCRIPT, LABELS if appropriate
    fn enrich_syscall(
        &mut self,
        rv: &mut Record,
        arch_sys: (Option<&'static str>, Option<&'static str>),
        current_process: &Option<Process>,
        parent: &Option<Process>,
        script: &Option<NVec>,
        container_info: &mut Option<Record>,
    ) {
        if let (true, (Some(arch), Some(syscall))) = (self.settings.translate_universal, arch_sys) {
            rv.push((Key::Literal("ARCH"), Value::Literal(arch)));
            rv.push((Key::Literal("SYSCALL"), Value::Literal(syscall)));
        }

        if let (true, Some(parent)) = (self.settings.enrich_pid, &parent) {
            add_record_procinfo(rv, b"ppid", parent, true);
        }

        #[cfg(all(feature = "procfs", target_os = "linux"))]
        if let (true, Some(script)) = (self.settings.enrich_script, &script) {
            rv.push((
                Key::Literal("SCRIPT"),
                Value::Str(script.as_slice(), Quote::None),
            ));
        }

        if let Some(proc) = &current_process {
            if self.settings.enrich_pid {
                add_record_procinfo(rv, b"pid", proc, false);
            }

            if !proc.labels.is_empty() {
                let labels = proc
                    .labels
                    .iter()
                    .map(|l| Value::Str(l, Quote::None))
                    .collect::<Vec<_>>();
                rv.push((Key::Literal("LABELS"), Value::List(labels)));
            }

            #[cfg(all(feature = "procfs", target_os = "linux"))]
            if let (true, Some(c)) = (self.settings.enrich_container, &proc.container_info) {
                let mut ci = Record::default();
                ci.push((
                    Key::Literal("ID"),
                    Value::Str(hex_string(&c.id).as_bytes(), Quote::None),
                ));
                *container_info = Some(ci);
            }
        }
    }

    fn transform_execve(&mut self, rv: &mut Record, current_process: &Option<Process>) {
        let mut argv: Vec<Value> = Vec::with_capacity(rv.len() - 1);
        rv.retain(|(k, v)| {
            match k {
                Key::ArgLen(_) => false,
                Key::Arg(i, None) => {
                    let idx = *i as usize;
                    if argv.len() <= idx {
                        argv.resize(idx + 1, Value::Empty);
                    };
                    argv[idx] = v.clone();
                    false
                }
                Key::Arg(i, Some(f)) => {
                    let idx = *i as usize;
                    if argv.len() <= idx {
                        argv.resize(idx + 1, Value::Empty);
                        argv[idx] = Value::Segments(Vec::new());
                    }
                    if let Some(Value::Segments(vs)) = argv.get_mut(idx) {
                        let frag = *f as usize;
                        let r = match v {
                            Value::Str(r, _) => r,
                            _ => todo!(),
                        };
                        if vs.len() <= frag {
                            vs.resize(frag + 1, &[]);
                            let ptr = std::ptr::slice_from_raw_parts(r.as_ptr(), r.len());
                            // (assumed) safety: vs[frag] is only added back to rv
                            vs[frag] = unsafe { &*ptr };
                        }
                    }
                    false
                }
                _ => true,
            }
        });

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
                                Some((args, bytes)) => Some((args + 1, 1 + bytes + (end - start))),
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
            rv.push((Key::Literal("ARGV"), Value::List(argv.clone())));
        }
        // ARGV_STR
        if self.settings.execve_argv_string {
            rv.push((
                Key::Literal("ARGV_STR"),
                Value::StringifiedList(argv.clone()),
            ));
        }

        // ENV
        #[cfg(all(feature = "procfs", target_os = "linux"))]
        if let (Some(proc), false) = (&current_process, self.settings.execve_env.is_empty()) {
            if let Ok(vars) =
                procfs::get_environ(proc.pid, |k| self.settings.execve_env.contains(k))
            {
                let map = vars
                    .iter()
                    .map(|(k, v)| {
                        (
                            Key::Name(NVec::from(k.as_slice())),
                            Value::Str(v, Quote::None),
                        )
                    })
                    .collect();
                rv.push((Key::Literal("ENV"), Value::Map(map)));
            }
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
        let mut key: Option<NVec> = None;

        let mut arch_name: Option<&'static str> = None;
        let mut syscall_name: Option<&'static str> = None;

        let mut syscall_is_exec = false;
        let mut current_process: Option<Process> = None;
        let mut parent: Option<Process> = None;

        if let Some(EventValues::Single(rv)) = ev.body.get_mut(&SYSCALL) {
            let mut proc = Process::default();
            let mut extra = 2; // pid, ppid
            if self.settings.translate_universal {
                extra += 2; // syscall, arch
            }
            if self.settings.translate_userdb {
                extra += 9; // uid, gid
            }
            rv.reserve(extra);
            let mut nrv = Record::default();
            let mut argv = Vec::with_capacity(4);
            rv.retain(|(k, v)| {
                match (k, v) {
                    (Key::Arg(_, None), _) => {
                        // FIXME: check argv length
                        argv.push(v.clone());
                        return false;
                    }
                    (Key::ArgLen(_), _) => return false,
                    (Key::Common(c), Value::Number(n)) => match (c, n) {
                        (Common::Arch, Number::Hex(n)) if arch.is_none() => {
                            arch = Some(*n as u32);
                            if self.settings.translate_universal && self.settings.drop_translated {
                                return false;
                            }
                        }
                        (Common::Syscall, Number::Dec(n)) if syscall.is_none() => {
                            syscall = Some(*n as u32);
                            if self.settings.translate_universal && self.settings.drop_translated {
                                return false;
                            }
                        }
                        (Common::Pid, Number::Dec(n)) => proc.pid = *n as u32,
                        (Common::PPid, Number::Dec(n)) => proc.ppid = *n as u32,
                        _ => (),
                    },
                    (Key::Common(c), Value::Str(r, _)) => match c {
                        Common::Comm => proc.comm = Some((*r).into()),
                        Common::Exe => proc.exe = Some((*r).into()),
                        Common::Key => key = Some((*r).into()),
                        _ => (),
                    },
                    (Key::Name(name), Value::Str(_, _)) => {
                        match name.as_ref() {
                            b"ARCH" | b"SYSCALL" if self.settings.translate_universal => {
                                return false
                            }
                            _ => (),
                        };
                    }
                    _ => {
                        if self.add_record_userdb(&mut nrv, k, v) && self.settings.drop_translated {
                            return false;
                        }
                    }
                };
                true
            });
            rv.push((Key::Literal("ARGV"), Value::List(argv)));
            rv.concat(nrv);

            if let (Some(arch), Some(syscall)) = (arch, syscall) {
                if let Some(an) = ARCH_NAMES.get(&arch) {
                    arch_name = Some(*an);
                    if let Some(sn) = SYSCALL_NAMES
                        .get(*an)
                        .and_then(|syscall_tbl| syscall_tbl.get(&syscall))
                    {
                        syscall_name = Some(sn);

                        // If we are processing an execve or execveat
                        // syscall, we'll create a new Process
                        // instance, assuming that the current process
                        // table entry for ppid holds the parent.
                        //
                        // For non-execve calls, we inspect the
                        // process table for the current pid entry. If
                        // the entry and the syscall do not match, we
                        // assume that we are dealing with a new
                        // process and create a new Process instance.
                        //
                        // If the entry and the syscall match, we keep
                        // using (and possibly updating) the existing
                        // Process entry.
                        syscall_is_exec = sn.contains("execve");
                        parent = self.processes.get_or_retrieve(proc.ppid).cloned();
                        let pr = if !syscall_is_exec {
                            self.processes.get_or_retrieve(proc.pid)
                        } else {
                            None
                        };
                        match pr {
                            Some(pr) if proc.ppid == pr.ppid && proc.exe == pr.exe => {
                                // existing, plausible process in table
                                proc.key = pr.key;
                                proc.parent = pr.parent;
                                proc.labels = pr.labels.clone();
                                #[cfg(all(feature = "procfs", target_os = "linux"))]
                                if self.settings.enrich_container {
                                    proc.container_info = match &pr.container_info {
                                        Some(ci) => Some(ci.clone()),
                                        _ => parent.as_ref().and_then(|p| p.container_info.clone()),
                                    };
                                }
                            }
                            _ => {
                                // first syscall in new process
                                proc.key = ProcessKey::Event(ev.id);
                                if let Some(pa) = &parent {
                                    proc.parent = Some(pa.key);
                                    let propagated_labels = self
                                        .settings
                                        .proc_propagate_labels
                                        .intersection(&pa.labels)
                                        .cloned();
                                    proc.labels.extend(propagated_labels);
                                }
                                #[cfg(all(feature = "procfs", target_os = "linux"))]
                                if self.settings.enrich_container {
                                    let id = procfs::parse_proc_pid_cgroup(proc.pid).ok().flatten();
                                    proc.container_info = match id {
                                        Some(id) => Some(ContainerInfo { id }),
                                        _ => parent.as_ref().and_then(|p| p.container_info.clone()),
                                    };
                                }
                                self.processes.insert(proc.clone());
                            }
                        };

                        if let Some(label_exe) = &self.settings.label_exe {
                            for label in label_exe.matches(&proc.exe.clone().unwrap()) {
                                proc.labels.insert(label.into());
                            }
                        }
                        if let Some(unlabel_exe) = &self.settings.unlabel_exe {
                            for label in unlabel_exe.matches(&proc.exe.clone().unwrap()) {
                                proc.labels.insert(label.into());
                            }
                        }
                    }
                }
            }

            if let Some(key) = &key {
                if self.settings.filter_keys.contains(key.as_ref()) {
                    ev.filter = true;
                }
                if self.settings.proc_label_keys.contains(key.as_ref()) {
                    proc.labels.insert(key.to_vec());
                }
            } else if self.settings.filter_null_keys {
                ev.filter = true;
            }

            current_process = Some(proc);
        }

        if let Some(EventValues::Single(rv)) = ev.body.get_mut(&EXECVE) {
            self.transform_execve(rv, &current_process);
        }

        // Handle script enrichment
        #[cfg(all(feature = "procfs", target_os = "linux"))]
        let script: Option<NVec> = match (self.settings.enrich_script, &self.settings.label_script)
        {
            (false, None) => None,
            _ => match (&current_process, ev.body.get(&PATH), syscall_is_exec) {
                (Some(proc), Some(EventValues::Multi(paths)), true) => {
                    let mut cwd = &b"/"[..];
                    if let Some(EventValues::Single(r)) = ev.body.get(&CWD) {
                        if let Some(Value::Str(rv, _)) = r.get("cwd") {
                            cwd = rv;
                        }
                    };
                    path_script_name(
                        &paths[0],
                        proc.pid,
                        proc.ppid,
                        cwd,
                        &proc.exe.clone().unwrap_or_default(),
                    )
                }
                _ => None,
            },
        };

        #[cfg(all(feature = "procfs", target_os = "linux"))]
        if let (Some(ref mut proc), Some(script)) = (&mut current_process, &script) {
            if let Some(label_script) = &self.settings.label_script {
                for label in label_script.matches(script.as_ref()) {
                    proc.labels.insert(label.into());
                }
            }
            if let Some(unlabel_script) = &self.settings.unlabel_script {
                for label in unlabel_script.matches(script.as_ref()) {
                    proc.labels.remove(label);
                }
            }
        }

        // filter early on labels
        if let Some(proc) = &current_process {
            self.processes.set_labels(&proc.key, &proc.labels);
            if proc
                .labels
                .iter()
                .any(|x| self.settings.filter_labels.contains(x))
            {
                ev.filter = true;
            }
        }

        if ev.filter {
            return;
        }

        // Since the event may have been dropped here, don't
        // manipulate the current process below.
        let current_process = current_process;
        let mut container_info: Option<Record> = None;

        for tv in ev.body.iter_mut() {
            match tv {
                (&SYSCALL, EventValues::Single(rv)) => self.enrich_syscall(
                    rv,
                    (arch_name, syscall_name),
                    &current_process,
                    &parent,
                    &script,
                    &mut container_info,
                ),
                (&EXECVE, EventValues::Single(_)) => {}
                (&SOCKADDR, EventValues::Multi(rvs)) => {
                    rvs.iter_mut().for_each(|rv| self.enrich_sockaddr(rv))
                }
                (&PROCTITLE, EventValues::Single(rv)) => self.transform_proctitle(rv),
                (_, EventValues::Single(rv)) => self.enrich_generic(rv),
                (_, EventValues::Multi(rvs)) => {
                    rvs.iter_mut().for_each(|rv| self.enrich_generic(rv))
                }
            }
        }

        container_info.map(|ci| ev.body.insert(CONTAINER_INFO, EventValues::Single(ci)));
    }

    /// Do bookkeeping on event, transform, emit it via the provided
    /// output function.
    fn emit_event(&mut self, mut ev: Event<'ev>) {
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
    pub fn process_line(&mut self, line: &[u8]) -> Result<(), CoalesceError> {
        let filter_raw = self.settings.filter_raw_lines.is_match(line);

        let skip_enriched = self.settings.translate_universal && self.settings.translate_userdb;
        let (node, typ, id, rv) = parse(line, skip_enriched).map_err(CoalesceError::Parse)?;
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
                return Err(CoalesceError::DuplicateEvent(id));
            }
            let ev = self
                .inflight
                .remove(&nid)
                .ok_or(CoalesceError::SpuriousEOE(id))?;
            self.emit_event(ev);
        } else if typ.is_multipart() {
            // kernel-level messages
            if !self.inflight.contains_key(&nid) {
                self.inflight.insert(nid.clone(), Event::new(node, id));
            }
            let ev = self.inflight.get_mut(&nid).unwrap();
            ev.filter |= filter_raw;
            match ev.body.get_mut(&typ) {
                Some(EventValues::Single(v)) => v.concat(rv),
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
                return Err(CoalesceError::DuplicateEvent(id));
            }
            let mut ev = Event::new(node, id);
            ev.filter |= filter_raw;
            ev.body.insert(typ, EventValues::Single(rv));
            self.emit_event(ev);
        }
        Ok(())
    }

    /// Flush all in-flight event data, including partial events
    pub fn flush(&mut self) {
        self.expire_inflight(u64::MAX);
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

impl Drop for Coalesce<'_, '_> {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::cell::RefCell;
    use std::io::{BufRead, BufReader};
    use std::rc::Rc;

    fn event_to_json(e: &Event) -> String {
        let mut out = vec![];
        crate::json::to_writer(&mut out, e).unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    #[test]
    fn dump_state() -> Result<(), Box<dyn Error>> {
        let mut c = Coalesce::new(|_| {});
        c.initialize()?;
        c.process_line(&br#"type=SYSCALL msg=audit(1615114232.375:15558): arch=c000003e syscall=59 success=yes exit=0 a0=63b29337fd18 a1=63b293387d58 a2=63b293375640 a3=fffffffffffff000 items=2 ppid=10883 pid=10884 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=1 comm="whoami" exe="/usr/bin/whoami" key=(null)
"#[..])?;
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
            c.process_line(line.as_bytes())?;
        }
        Ok(())
    }

    #[test]
    fn coalesce() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(Vec::new()));
        let mut c = Coalesce::new(mk_emit_vec(&ec));

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

        process_record(
            &mut c,
            include_bytes!("testdata/record-anom-promiscuous.txt"),
        )?;
        let output = event_to_json(ec.borrow().last().unwrap());
        assert!(
            output.contains(r#""saddr":"%10%00%00%00%00%00%00%00%00%00%00%00""#),
            "SOCKADDR.saddr blob is encoded correctly"
        );

        // recordds do not begin with SYSCALL.
        process_record(&mut c, include_bytes!("testdata/record-login.txt"))?;
        process_record(&mut c, include_bytes!("testdata/record-adjntpval.txt"))?;
        process_record(&mut c, include_bytes!("testdata/record-avc-apparmor.txt"))?;

        let mut c = Coalesce::new(mk_emit_vec(&ec));
        c.settings.translate_userdb = true;
        c.settings.drop_translated = true;
        process_record(
            &mut c,
            strip_enriched(include_bytes!("testdata/record-execve.txt")),
        )?;
        let gid0name = nix::unistd::Group::from_gid(0.into())
            .unwrap()
            .unwrap()
            .name;
        let output = event_to_json(ec.borrow().last().unwrap());
        println!("{}", output);
        assert!(
            output.contains(r#""UID":"root","#),
            "output contains translated UID"
        );
        assert!(
            output.contains(&format!(r#""EGID":"{gid0name}","#)),
            "output contains translated EGID"
        );
        assert!(
            !output.contains(r#""uid":0,"#),
            "output does not contain raw uid"
        );
        assert!(
            !output.contains(r#""egid":0,"#),
            "output does not contain raw egid"
        );

        Ok(())
    }

    #[test]
    fn duplicate_uids() {
        let ec = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.enrich_uid_groups = false;
        c.settings.enrich_pid = false;
        c.settings.translate_userdb = true;
        c.settings.translate_universal = true;
        process_record(&mut c, include_bytes!("testdata/record-login.txt")).unwrap();
        if let EventValues::Multi(records) = &ec.borrow().as_ref().unwrap().body[&LOGIN] {
            // Check for: pid uid subj old-auid auid tty old-ses ses res UID OLD-AUID AUID
            let l = records[0].len();
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

        let mut c = Coalesce::new(mk_emit(&ec));
        process_record(&mut c, include_bytes!("testdata/record-execve.txt")).unwrap();
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#""ARCH":"x86_64""#));
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#""SYSCALL":"execve""#));
    }

    #[test]
    fn translate_uids() {
        let ec = Rc::new(RefCell::new(None));

        let gid0name = nix::unistd::Group::from_gid(0.into())
            .unwrap()
            .unwrap()
            .name;

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
                    assert!(v == "root", "Got {}={:?}, expected root", k, v);
                }
                if k.to_string().ends_with("GID") {
                    gids += 1;
                    assert!(v == gid0name.as_str(), "Got {}={:?}, expected root", k, v);
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
                if k == "UID" && v == "root" {
                    uid = true;
                }
                if k == "OLD-AUID" && v == "unset" {
                    old_auid = true;
                }
                if k == "AUID" && v == "root" {
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

        let mut c = Coalesce::new(mk_emit(&ec));
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
        let lm = LabelMatcher::new(&[("whoami", "recon")])?;

        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.label_exe = Some(lm.clone());
        process_record(&mut c, include_bytes!("testdata/record-execve.txt"))?;
        drop(c);
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["recon"]"#));

        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.label_exe = Some(lm);
        process_record(
            &mut c,
            strip_enriched(include_bytes!("testdata/record-execve.txt")),
        )?;
        drop(c);
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["recon"]"#));

        Ok(())
    }

    // Returns an emitter function that puts the event into an Option
    fn mk_emit<'c, 'ev: 'c>(
        ec: &'c Rc<RefCell<Option<Event<'ev>>>>,
    ) -> impl FnMut(&Event<'ev>) + 'c {
        return |ev: &Event| {
            if !ev.filter {
                *ec.borrow_mut() = Some(ev.clone());
            }
        };
    }

    // Returns an emitter function that appends the event onto a Vec
    fn mk_emit_vec<'c, 'ev>(ec: &'c Rc<RefCell<Vec<Event<'ev>>>>) -> impl FnMut(&Event<'ev>) + 'c {
        return |ev: &Event| {
            if !ev.filter {
                ec.borrow_mut().push(ev.clone());
            }
        };
    }

    #[test]
    fn filter_key() -> Result<(), Box<dyn Error>> {
        let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));

        let mut c = Coalesce::new(mk_emit_vec(&events));
        c.settings
            .filter_keys
            .insert(Vec::from(&b"filter-this"[..]));
        c.settings.filter_keys.insert(Vec::from(&b"this-too"[..]));
        process_record(&mut c, include_bytes!("testdata/record-syscall-key.txt"))?;
        drop(c);
        assert!(events.borrow().is_empty());

        let mut c = Coalesce::new(mk_emit_vec(&events));
        c.settings.filter_null_keys = true;
        process_record(
            &mut c,
            include_bytes!("testdata/record-syscall-nullkey.txt"),
        )?;
        drop(c);
        assert!(events.borrow().is_empty());

        let mut c = Coalesce::new(mk_emit_vec(&events));
        c.settings
            .filter_keys
            .insert(Vec::from(&b"random-filter"[..]));
        process_record(&mut c, include_bytes!("testdata/record-login.txt"))?;
        drop(c);
        assert!(!events.borrow().is_empty());

        Ok(())
    }

    #[test]
    fn filter_label() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(mk_emit(&ec));
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
    fn filter_raw() {
        let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));

        let mut c = Coalesce::new(mk_emit_vec(&events));
        c.settings.filter_raw_lines = regex::bytes::RegexSet::new(&[
            "^type=SOCKADDR (?:node=\\$*? )?msg=audit\\(\\S*?\\): saddr=01002F7661722F72756E2F6E7363642F736F636B657400",
        ])
        .expect("failed to compile regex");

        process_record(&mut c, include_bytes!("testdata/record-nscd.txt")).unwrap();

        assert!(
            events.borrow().is_empty(),
            "nscd connect event should be filtered"
        )
    }

    #[test]
    fn strip_long_argv() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(mk_emit(&ec));

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
    fn shell_proc_trace() {
        let s1 = Settings {
            proc_label_keys: [b"test-script".to_vec()].into(),
            proc_propagate_labels: [b"test-script".to_vec()].into(),
            ..Settings::default()
        };
        let s2 = Settings {
            filter_keys: [b"fork".to_vec()].into(),
            ..s1.clone()
        };

        for (n, s) in [s1, s2].iter().enumerate() {
            let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));
            let mut c = Coalesce::new(mk_emit_vec(&events));

            c.settings = s.clone();

            println!("Using configuration #{n}");
            process_record(&mut c, include_bytes!("testdata/shell-proc-trace.txt")).unwrap();

            let events = events.borrow();

            let mut ids = vec![
                "1682609045.526:29238",
                "1682609045.530:29242",
                "1682609045.530:29244",
                "1682609045.534:29245",
            ];
            if n == 0 {
                ids.extend([
                    "1682609045.530:29240",
                    "1682609045.530:29241",
                    "1682609045.530:29243",
                ]);
            }

            for id in ids {
                let event = events
                    .iter()
                    .find(|e| e.id.to_string() == id)
                    .expect(&format!("Did not find {id}"));
                assert!(
                    event_to_json(&event).contains(r#""LABELS":["test-script"]"#),
                    "{id} was not labelled correctly."
                );
            }
        }
    }

    #[test]
    fn shell_proc_trace_confusion() {
        let s1 = Settings {
            proc_label_keys: [b"test-script".to_vec()].into(),
            proc_propagate_labels: [b"test-script".to_vec()].into(),
            ..Settings::default()
        };
        let s2 = Settings {
            filter_keys: [b"fork".to_vec()].into(),
            ..s1.clone()
        };

        for (n, s) in [s1, s2].iter().enumerate() {
            let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));
            let mut c = Coalesce::new(mk_emit_vec(&events));

            c.settings = s.clone();

            println!("Using configuration #{n}");
            process_record(
                &mut c,
                include_bytes!("testdata/shell-proc-trace-confusion.txt"),
            )
            .unwrap();

            let events = events.borrow();

            for id in ["1697091525.582:2588684", "1697091526.357:2638035"] {
                let event = events
                    .iter()
                    .find(|e| e.id.to_string() == id)
                    .expect(&format!("Did not find {id}"));
                println!("{}", event_to_json(&event));
            }

            let id = "1697091526.357:2638035";
            let event = events
                .iter()
                .find(|e| e.id.to_string() == id)
                .expect(&format!("Did not find {id}"));
            assert!(
                event_to_json(&event).contains(
                    r#""PPID":{"EVENT_ID":"1697091526.357:2638033","comm":"csh","exe":"/bin/tcsh","ppid":2542}"#),
                "Did not get correct parent for {id}\n\n{}", event_to_json(&event));
            println!("{}", event_to_json(&event));
        }
    }
}
