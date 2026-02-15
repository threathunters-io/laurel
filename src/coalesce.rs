use std::collections::{BTreeMap, HashSet};
use std::fmt::{self, Display};
use std::str::FromStr;

#[cfg(all(feature = "procfs", target_os = "linux"))]
use faster_hex::hex_string;

use linux_audit_parser::*;

use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::constants::{ARCH_NAMES, SYSCALL_NAMES, URING_OPS};
use crate::label_matcher::LabelMatcher;
use crate::proc::{self, ContainerInfo, ProcTable, Process, ProcessKey};
#[cfg(all(feature = "procfs", target_os = "linux"))]
use crate::procfs;
#[cfg(target_os = "linux")]
use crate::sockaddr::{SocketAddr, SocketAddrMatcher};
use crate::types::*;
use crate::userdb::UserDB;

use tinyvec::TinyVec;

use thiserror::Error;

#[derive(
    PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, SerializeDisplay, DeserializeFromStr,
)]
pub struct EventKey(Option<Vec<u8>>, EventID);

impl Display for EventKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EventKey(Some(node), event_id) => {
                let node = String::from_utf8_lossy(node);
                write!(f, "{node}::{event_id}")
            }
            EventKey(None, event_id) => {
                write!(f, "{event_id}")
            }
        }
    }
}

impl FromStr for EventKey {
    type Err = ParseEventIDError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once("::") {
            Some((node, event_id)) => {
                Ok(EventKey(Some(node.as_bytes().to_vec()), event_id.parse()?))
            }
            _ => Ok(EventKey(None, s.parse()?)),
        }
    }
}

#[derive(Clone)]
pub struct Settings {
    /// Generate ARGV and ARGV_STR from EXECVE
    pub execve_argv_list: bool,
    pub execve_argv_string: bool,

    pub execve_env: HashSet<Vec<u8>>,
    pub execve_argv_limit_bytes: Option<usize>,
    pub enrich_container: bool,
    pub enrich_container_info: bool,
    pub enrich_systemd: bool,
    pub enrich_pid: bool,
    pub enrich_script: bool,
    pub enrich_uid_groups: bool,
    pub enrich_prefix: Option<String>,

    pub proc_label_keys: HashSet<Vec<u8>>,
    pub proc_propagate_labels: HashSet<Vec<u8>>,

    pub translate_universal: bool,
    pub translate_userdb: bool,
    pub drop_translated: bool,

    pub label_exe: Option<LabelMatcher>,
    pub unlabel_exe: Option<LabelMatcher>,
    pub label_argv: Option<LabelMatcher>,
    pub unlabel_argv: Option<LabelMatcher>,
    pub label_argv_bytes: usize,
    pub label_argv_count: usize,
    pub label_script: Option<LabelMatcher>,
    pub unlabel_script: Option<LabelMatcher>,

    pub filter_keys: HashSet<Vec<u8>>,
    pub filter_labels: HashSet<Vec<u8>>,
    pub filter_null_keys: bool,
    pub filter_sockaddr: Vec<SocketAddrMatcher>,
    pub filter_raw_lines: regex::bytes::RegexSet,
    pub filter_first_per_process: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            execve_argv_list: true,
            execve_argv_string: false,
            execve_env: HashSet::new(),
            execve_argv_limit_bytes: None,
            enrich_container: false,
            enrich_container_info: false,
            enrich_systemd: false,
            enrich_pid: true,
            enrich_script: true,
            enrich_uid_groups: true,
            enrich_prefix: None,
            proc_label_keys: HashSet::new(),
            proc_propagate_labels: HashSet::new(),
            translate_universal: false,
            translate_userdb: false,
            drop_translated: false,
            label_exe: None,
            unlabel_exe: None,
            label_argv: None,
            unlabel_argv: None,
            label_argv_bytes: 4096,
            label_argv_count: 32,
            label_script: None,
            unlabel_script: None,
            filter_keys: HashSet::new(),
            filter_labels: HashSet::new(),
            filter_null_keys: false,
            filter_sockaddr: vec![],
            filter_raw_lines: regex::bytes::RegexSet::empty(),
            filter_first_per_process: false,
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

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct State<'ev> {
    /// Events that are being collected/processed
    pub inflight: BTreeMap<EventKey, Event<'ev>>,
    /// Event IDs that have been recently processed
    pub done: HashSet<EventKey>,
    /// Process table built from observing process-related events
    pub processes: ProcTable,
    /// Creadential cache
    userdb: UserDB,
}

/// Coalesce collects Audit Records from individual lines and assembles them to Events
pub struct Coalesce<'a, 'ev> {
    /// Serializable state
    state: State<'ev>,
    /// Timestamp for next cleanup
    next_expire: Option<u64>,
    /// Output function
    emit_fn: Box<dyn 'a + FnMut(&Event<'ev>)>,

    pub settings: Settings,
}

const EXPIRE_PERIOD: u64 = 1_000;
const EXPIRE_INFLIGHT_TIMEOUT: u64 = 5_000;
const EXPIRE_DONE_TIMEOUT: u64 = 120_000;

/// generate translation of SocketAddr enum to a format similar to
/// what auditd log_format=ENRICHED produces
#[cfg(target_os = "linux")]
fn add_translated_socketaddr(rv: &mut Body, sa: SocketAddr) {
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
    rv.push(("SADDR".into(), Value::Map(m)));
}

#[derive(Default)]
struct UserGroupIDs {
    uid: Option<u32>, // should not need this
    ids: TinyVec<[(TinyVec<[u8; 8]>, u32); 8]>,
}

impl UserGroupIDs {
    fn collect(&mut self, name: &[u8], id: u32) {
        if name == b"uid" {
            self.uid = Some(id);
        } else {
            self.ids.push((name.into(), id));
        }
    }
    fn get_translated<'a>(
        &'a self,
        userdb: &'a mut UserDB,
    ) -> impl Iterator<Item = (&'a [u8], String)> {
        let uid = self.uid.iter().map(|id| (b"uid".as_slice(), *id));
        let ids = self.ids.iter().map(|(name, id)| (name.as_slice(), *id));

        uid.chain(ids).map(move |(name, id)| {
            let translated = if id == 0xffffffff {
                "unset".to_string()
            } else {
                if name.ends_with(b"uid") {
                    userdb.get_user(id)
                } else if name.ends_with(b"gid") {
                    userdb.get_group(id)
                } else {
                    None
                }
                .unwrap_or(format!("unknown({id})"))
            };
            (name, translated)
        })
    }
}

/// Returns a script name from path if exe's dev / inode don't match
///
/// The executable's device and inode are inspected throguh the
/// /proc/<pid>/root/ symlink. This may fail for
///
/// - very short-lived processes
/// - container setups where the container's filesystem is constructed
///   using fuse-overlayfs (observed with
///   podman+fuse-overlayfs/1.4.0-1 on Debian/buster).
///
/// Some container setups construct filesystem mappings where
/// major(dev) = 0: "Unnamed devices (e.g. non-device mounts)". In
/// this case, no script is returned if exe is found on a device with
/// major(dev) != 0.
///
/// As an extra sanity check, exe is compared with normalized
/// PATH.name. If they are equal, no script is returned.
#[cfg(all(feature = "procfs", target_os = "linux"))]
fn path_script_name(path: &Body, pid: u32, ppid: u32, cwd: &[u8], exe: &[u8]) -> Option<NVec> {
    use nix::sys::stat::{major, makedev};
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
    let mut p_name = None;
    for (k, v) in path {
        if k == "item" && *v != Value::Number(Number::Dec(0)) {
            // Can't determine a script if the first PATH record is
            // missing from the audit log.
            break;
        }
        if k == "name" {
            if let Value::Str(r, _) = v {
                if r.is_empty() {
                    p_name = None;
                    continue;
                }
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
                p_name = Some(NVec::from(tpb.as_os_str().as_bytes()))
            }
        } else if k == "inode" {
            if let Value::Number(Number::Dec(i)) = v {
                p_inode = Some(*i as _);
            }
        } else if k == "dev" {
            if let Value::Str(r, _) = v {
                p_dev = String::from_utf8_lossy(r)
                    .split(':')
                    .filter_map(|part| u64::from_str_radix(part, 16).ok())
                    .collect::<Vec<_>>()
                    .try_into()
                    .ok()
                    .map(|a: [u64; 2]| makedev(a[0], a[1]));
            }
            break;
        }
    }
    match (p_dev, p_inode, p_name) {
        (Some(p_dev), _, _) if major(p_dev) == 0 && major(e_dev) != 0 => None,
        (Some(p_dev), Some(p_inode), _) if (p_dev, p_inode) == (e_dev, e_inode) => None,
        (Some(_), Some(_), Some(p_name)) if p_name != exe => Some(p_name),
        _ => None,
    }
}

impl<'a, 'ev> Coalesce<'a, 'ev> {
    /// Creates a `Coalsesce`. `emit_fn` is the function that takes
    /// completed events.
    pub fn new<F: 'a + FnMut(&Event<'ev>)>(emit_fn: F) -> Self {
        Coalesce {
            state: State::default(),
            next_expire: None,
            emit_fn: Box::new(emit_fn),
            settings: Settings::default(),
        }
    }

    pub fn with_settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    pub fn with_state(mut self, state: State<'ev>) -> Self {
        self.state = state;
        self.state.processes.relabel_all(&self.settings);
        self
    }

    pub fn state(&self) -> &State<'_> {
        &self.state
    }

    pub fn initialize(&mut self) -> Result<(), proc::ProcError> {
        if self.settings.translate_userdb {
            self.state.userdb.populate();
        }
        self.state.processes = ProcTable::from_proc(
            self.settings.label_exe.clone(),
            &self.settings.proc_propagate_labels,
        )?;
        self.state.processes.relabel_all(&self.settings);

        Ok(())
    }

    /// Flush out events
    ///
    /// Called every EXPIRE_PERIOD ms and when Coalesce is destroyed.
    fn expire_inflight(&mut self, now: u64) {
        let event_keys = self
            .state
            .inflight
            .keys()
            .filter(|EventKey(_, id)| id.timestamp + EXPIRE_INFLIGHT_TIMEOUT < now)
            .cloned()
            .collect::<Vec<_>>();
        for event_key in event_keys {
            if let Some(event) = self.state.inflight.remove(&event_key) {
                self.emit_event(event);
            }
        }
    }

    fn expire_done(&mut self, now: u64) {
        let event_keys = self
            .state
            .done
            .iter()
            .filter(|EventKey(_, id)| id.timestamp + EXPIRE_DONE_TIMEOUT < now)
            .cloned()
            .collect::<Vec<_>>();
        for event_key in event_keys {
            self.state.done.remove(&event_key);
        }
    }

    /// Create an enriched pid entry in rv.
    fn add_record_procinfo(&self, rec: &mut Body, name: &[u8], proc: &Process) {
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
        if name != b"pid" {
            if let Some(comm) = &proc.comm {
                m.push(("comm".into(), Value::from(comm.as_slice())));
            }
            if let Some(exe) = &proc.exe {
                m.push(("exe".into(), Value::from(exe.as_slice())));
            }
            if proc.ppid != 0 {
                m.push(("ppid".into(), Value::from(proc.ppid as i64)));
            }
        } else {
            #[cfg(all(feature = "procfs", target_os = "linux"))]
            {
                if let (true, Some(container_info)) =
                    (self.settings.enrich_container, &proc.container_info)
                {
                    let id = hex_string(&container_info.id);
                    m.push((
                        "container".into(),
                        Value::Map(vec![("id".into(), id.into())]),
                    ));
                }

                if let (true, Some(systemd_service)) =
                    (self.settings.enrich_systemd, &proc.systemd_service)
                {
                    m.push((
                        "systemd_service".into(),
                        Value::List(
                            systemd_service
                                .iter()
                                .map(|v| Value::from(v.as_slice()))
                                .collect(),
                        ),
                    ));
                }
            }
        }

        let key = match &self.settings.enrich_prefix {
            Some(s) => Key::Name(NVec::from_iter(s.bytes().chain(name.iter().cloned()))),
            None => Key::NameTranslated(name.into()),
        };
        rec.push((key, Value::Map(m)));
    }

    /// Translates UID, GID and variants, e.g.:
    /// - auid=1000 -> AUID="user"
    /// - ogid=1000 -> OGID="user"
    ///
    /// IDs that can't be resolved are translated into "unknown(n)".
    /// `(uint32)-1` is translated into "unset".
    fn add_record_userdb(&mut self, body: &mut Body, ids: &UserGroupIDs) {
        for (name, translated) in ids.get_translated(&mut self.state.userdb) {
            let key = match &self.settings.enrich_prefix {
                Some(s) => Key::Name(NVec::from_iter(s.bytes().chain((*name).iter().cloned()))),
                None => Key::NameTranslated((*name).into()),
            };
            body.push((key, Value::from(translated.as_bytes())));
        }
    }

    /// Enrich "pid" entries using `ppid`, `exe`, `ID` (generating
    /// event id) from the shadow process table
    fn enrich_pid(&mut self, rv: &mut Body, k: &Key, v: &Value) {
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
            if let Some(proc) = self.state.processes.get_pid(*pid as _) {
                self.add_record_procinfo(rv, name, proc);
            } else if let Some(proc) = self.state.processes.get_or_retrieve(*pid as _).cloned() {
                self.add_record_procinfo(rv, name, &proc)
            }
        }
    }

    /// Apply uid, gid, pid enrichment to generic records
    fn enrich_generic(&mut self, body: &mut Body) {
        let mut nrv = Body::default();
        let mut ids = UserGroupIDs::default();
        body.retain(|(k, v)| {
            match (k, v) {
                (Key::NameUID(name), Value::Number(Number::Dec(n)))
                | (Key::NameGID(name), Value::Number(Number::Dec(n))) => {
                    ids.collect(name, *n as _);
                    if self.settings.drop_translated {
                        return false;
                    }
                }
                _ => self.enrich_pid(&mut nrv, k, v),
            };
            true
        });
        body.extend(nrv);
        if self.settings.translate_userdb {
            self.add_record_userdb(body, &ids);
        }
    }

    /// Transform PROCTITLE record
    ///
    /// The flat proctitle field is turned into a list.
    fn transform_proctitle(&mut self, rv: &mut Body) {
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
    ///
    /// This function also determines whether the record should be filtered
    fn enrich_sockaddr(&mut self, rv: &mut Body, is_filtered: &mut bool) {
        let mut nrv = Body::default();
        rv.retain(|(k, v)| match (k, v) {
            (k, Value::Str(vr, _q)) => {
                if k == "saddr" {
                    #[cfg(target_os = "linux")]
                    if let Ok(sa) = SocketAddr::parse(vr) {
                        // There's no need to enrich saddr entries
                        // that will be dropped, but the raw data
                        // should be kept in case filter.filter-action
                        // is set to "log".
                        if *is_filtered {
                            return true;
                        } else if self.settings.filter_sockaddr.iter().any(|f| f.matches(&sa)) {
                            *is_filtered = true;
                            return true;
                        }
                        if self.settings.translate_universal {
                            add_translated_socketaddr(&mut nrv, sa);
                            return false;
                        } else {
                            return true;
                        }
                    }
                } else if k == "SADDR" && self.settings.translate_universal || *is_filtered {
                    // If we do our own enrichment, drop pre-existing
                    // enriched SOCKADDR.saddr enrichment.
                    return false;
                }
                true
            }
            _ => true,
        });
        rv.extend(nrv);
    }

    /// Enrich URINGOP record
    fn enrich_uringop(&mut self, body: &mut Body) {
        let mut nrv = Body::default();

        let mut ids = UserGroupIDs::default();

        body.retain(|(k, v)| {
            match (k, v) {
                (Key::NameUID(name), Value::Number(Number::Dec(n)))
                | (Key::NameGID(name), Value::Number(Number::Dec(n))) => {
                    ids.collect(name, *n as _);
                    if self.settings.drop_translated {
                        return false;
                    }
                }
                (Key::Name(name), Value::Number(Number::Dec(op)))
                    if self.settings.translate_universal && k == "uring_op" =>
                {
                    if let Some(Some(op_name)) = URING_OPS.get(*op as usize) {
                        nrv.push((Key::NameTranslated(name.clone()), Value::from(*op_name)));
                    }
                }
                _ => {}
            }
            true
        });

        body.extend(nrv);

        if self.settings.translate_userdb {
            self.add_record_userdb(body, &ids);
        }
    }

    /// Enrich SYSCALL record
    ///
    /// Add ARCH, SYSCALL, PID, PPID, SCRIPT, LABELS if appropriate
    fn enrich_syscall(
        &mut self,
        rv: &mut Body,
        process_key: Option<ProcessKey>,
        script: &Option<NVec>,
        container_info: &mut Option<Body>,
    ) {
        #[cfg(all(feature = "procfs", target_os = "linux"))]
        if let (true, Some(script)) = (self.settings.enrich_script, &script) {
            rv.push((
                Key::Literal("SCRIPT"),
                Value::Str(script.as_slice(), Quote::None),
            ));
        }

        if let Some(proc) = process_key.and_then(|k| self.state.processes.get_key(&k)) {
            #[cfg(all(feature = "procfs", target_os = "linux"))]
            if let (true, Some(c)) = (self.settings.enrich_container, &proc.container_info) {
                let mut ci = Body::default();
                ci.push((
                    Key::Literal("ID"),
                    Value::Str(hex_string(&c.id).as_bytes(), Quote::None),
                ));
                *container_info = Some(ci);
            }

            if !proc.labels.is_empty() {
                let labels = proc
                    .labels
                    .iter()
                    .map(|l| Value::Str(l, Quote::None))
                    .collect::<Vec<_>>();
                rv.push((Key::Literal("LABELS"), Value::List(labels)));
            }
        }
    }

    fn transform_execve(&mut self, rv: &mut Body, process_key: Option<ProcessKey>) {
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

        if let Some(process_key) = process_key {
            if self.settings.label_argv_count > 0
                && self.settings.label_argv_bytes > 0
                && (self.settings.label_argv.is_some() || self.settings.unlabel_argv.is_some())
            {
                let mut buf: Vec<u8> = Vec::with_capacity(self.settings.label_argv_bytes);

                for arg in argv.iter().take(self.settings.label_argv_count) {
                    if !buf.is_empty() {
                        buf.push(b' ');
                    }
                    // FIXME TryFrom<&Value> needs to be implemented in linux-audit-parser
                    let b: Vec<u8> = match arg.clone().try_into() {
                        Ok(b) => b,
                        Err(_) => continue,
                    };
                    if buf.len() + b.len() >= self.settings.label_argv_bytes {
                        break;
                    }
                    buf.extend(b);
                }

                if let Some(ref mut proc) = self.state.processes.get_key_mut(&process_key) {
                    if let Some(ref m) = self.settings.label_argv {
                        for label in m.matches(&buf) {
                            proc.labels.insert(label.into());
                        }
                    }

                    if let Some(ref m) = self.settings.unlabel_argv {
                        for label in m.matches(&buf) {
                            proc.labels.remove(label);
                        }
                    }
                }
            }
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
        if let (Some(proc), false) = (
            process_key.and_then(|k| self.state.processes.get_key(&k)),
            self.settings.execve_env.is_empty(),
        ) {
            if let Ok(vars) =
                procfs::get_environ(proc.pid, |k| {
                    self.settings.execve_env.iter().any(|pattern| {
                        if let Some(prefix) = pattern.strip_suffix(b"*") {
                            k.starts_with(prefix)
                        } else {
                            k == pattern.as_slice()
                        }
                    })
                })
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
        #[cfg(all(feature = "procfs", target_os = "linux"))]
        let mut proc = ev
            .process_key
            .as_ref()
            .and_then(|p| self.state.processes.get_key(p).cloned());

        if let Some(EventValues::Single(rv)) = ev.body.get_mut(&MessageType::EXECVE) {
            self.transform_execve(rv, ev.process_key);
        }

        // Handle script enrichment
        // TODO: Look up process per key.
        #[cfg(all(feature = "procfs", target_os = "linux"))]
        let script: Option<NVec> = match (self.settings.enrich_script, &self.settings.label_script)
        {
            (false, None) => None,
            _ => match (&proc, ev.body.get(&MessageType::PATH), ev.is_exec) {
                (Some(proc), Some(EventValues::Multi(paths)), true) => {
                    let mut cwd = &b"/"[..];
                    if let Some(EventValues::Single(r)) = ev.body.get(&MessageType::CWD) {
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
        #[cfg(not(all(feature = "procfs", target_os = "linux")))]
        let script = None;

        #[cfg(all(feature = "procfs", target_os = "linux"))]
        if let (Some(ref mut proc), Some(script)) = (&mut proc, &script) {
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

        if let Some(EventValues::Multi(ref mut rvs)) = ev.body.get_mut(&MessageType::SOCKADDR) {
            for rv in rvs {
                self.enrich_sockaddr(rv, &mut ev.is_filtered)
            }
        }

        if ev.is_filtered {
            return;
        }

        let mut container_info: Option<Body> = None;

        for tv in ev.body.iter_mut() {
            match tv {
                (&MessageType::SYSCALL, EventValues::Single(rv)) => {
                    self.enrich_syscall(rv, ev.process_key, &script, &mut container_info)
                }
                (&MessageType::EXECVE, EventValues::Single(_)) => {}
                (&MessageType::PROCTITLE, EventValues::Single(rv)) => self.transform_proctitle(rv),
                (&MessageType::URINGOP, EventValues::Multi(rvs)) => {
                    rvs.iter_mut().for_each(|rv| self.enrich_uringop(rv))
                }
                (_, EventValues::Single(rv)) => self.enrich_generic(rv),
                (_, EventValues::Multi(rvs)) => {
                    rvs.iter_mut().for_each(|rv| self.enrich_generic(rv))
                }
            }
        }

        if self.settings.enrich_container_info {
            ev.container_info = container_info;
        }
    }

    /// Do bookkeeping on event, transform, emit it via the provided
    /// output function.
    fn emit_event(&mut self, mut ev: Event<'ev>) {
        self.state.done.insert(EventKey(ev.node.clone(), ev.id));

        self.transform_event(&mut ev);
        (self.emit_fn)(&ev)
    }

    /// Early handling of SYSCALL events
    ///
    /// This involves:
    /// - deciding whether the process is known / updating the process table
    ///   - determining a process key for new events
    /// - early handling of process labels based on key, exe
    /// - deciding whether the event should be filtered, avoiding unnecessary
    ///   work for enrichment/transformation
    pub fn handle_syscall(
        &mut self,
        id: EventID,
        body: &mut Body,
        filter_event: &mut bool,
        is_exec: &mut bool,
        process_key: &mut Option<ProcessKey>,
    ) {
        let mut arch: Option<u32> = None;
        let mut syscall: Option<u32> = None;

        let mut pid = 0;
        let mut ppid = 0;

        let mut comm: Option<&[u8]> = None;
        let mut exe: Option<&[u8]> = None;
        let mut key: Option<&[u8]> = None;

        let mut argv = Vec::with_capacity(4);

        let mut ids = UserGroupIDs::default();

        // Filter / collect
        body.retain(|(k, v)| {
            match (k, v) {
                (Key::Arg(_, None), v) => {
                    argv.push(v.clone());
                    return false;
                }
                (Key::ArgLen(_), _) => return false,
                (Key::Common(Common::Arch), Value::Number(Number::Hex(n))) => {
                    arch = Some(*n as u32);
                    return !(self.settings.translate_universal && self.settings.drop_translated);
                }
                (Key::Common(Common::Syscall), Value::Number(Number::Dec(n))) => {
                    syscall = Some(*n as u32);
                    return !(self.settings.translate_universal && self.settings.drop_translated);
                }
                (Key::Common(Common::Pid), Value::Number(Number::Dec(n))) => {
                    pid = *n as u32;
                }
                (Key::Common(Common::PPid), Value::Number(Number::Dec(n))) => {
                    ppid = *n as u32;
                }
                (Key::Common(Common::Comm), Value::Str(s, _)) => comm = Some(*s),
                (Key::Common(Common::Exe), Value::Str(s, _)) => exe = Some(*s),
                (Key::Common(Common::Key), Value::Str(s, _)) => key = Some(*s),
                (Key::NameUID(name), Value::Number(Number::Dec(n)))
                | (Key::NameGID(name), Value::Number(Number::Dec(n))) => {
                    ids.collect(name, *n as _);
                    if self.settings.drop_translated {
                        return false;
                    }
                }
                (Key::Name(name), Value::Str(_, _)) => {
                    match name.as_ref() {
                        b"ARCH" | b"SYSCALL" if self.settings.translate_universal => return false,
                        _ => (),
                    };
                }
                _ => {}
            }
            true
        });
        body.push((Key::Literal("ARGV"), Value::List(argv)));

        // Determine syscall.
        let mut arch_name = None;
        let mut syscall_name = None;
        if let (Some(arch), Some(syscall)) = (arch, syscall) {
            arch_name = ARCH_NAMES.get(&arch);
            if let Some(arch_name) = arch_name {
                syscall_name = SYSCALL_NAMES
                    .get(*arch_name)
                    .and_then(|syscall_tbl| syscall_tbl.get(&syscall));
                if let Some(syscall_name) = syscall_name {
                    if syscall_name.starts_with("execve") {
                        *is_exec = true;
                    }
                }
            }
        }

        let mut labels: HashSet<Vec<u8>> = HashSet::default();

        if let Some(key) = key {
            if self.settings.filter_keys.contains(key) {
                *filter_event = true;
            }
            if self.settings.proc_label_keys.contains(key) {
                labels.insert(key.to_vec());
            }
        } else if self.settings.filter_null_keys {
            *filter_event = true;
        }

        let mut proc = None;
        if !*is_exec {
            // Look up process from our process table, but only use it
            // if it matches the current record. Otherwise assume that
            // this is a new process.
            proc = self
                .state
                .processes
                .get_pid(pid)
                .filter(|p| p.pid == pid && p.ppid == ppid && p.exe.as_deref() == exe)
        }

        let mut first_per_process = false;

        if proc.is_none() {
            first_per_process = true;

            let key = ProcessKey::Event(id);
            let parent_process = self.state.processes.get_or_retrieve(ppid).cloned();
            let parent = parent_process.as_ref().map(|p| p.key);

            self.state.processes.insert(Process {
                key,
                parent,
                pid,
                ppid,
                labels,
                exe: exe.map(Vec::from),
                comm: comm.map(Vec::from),
                ..Process::default()
            });

            self.state.processes.relabel_process(&key, &self.settings);

            #[cfg(all(feature = "procfs", target_os = "linux"))]
            if self.settings.enrich_container || self.settings.enrich_systemd {
                let mut container_info: Option<ContainerInfo> = None;
                let mut systemd_service: Option<Vec<Vec<u8>>> = None;
                let cgroup = procfs::parse_proc_pid_cgroup(pid).ok().flatten();
                if self.settings.enrich_container {
                    container_info = match cgroup {
                        Some(ref path) => {
                            proc::try_extract_container_id(path).map(|id| ContainerInfo { id })
                        }
                        _ => self
                            .state
                            .processes
                            .get_pid(ppid)
                            .and_then(|p| p.container_info.clone()),
                    };
                }
                if self.settings.enrich_systemd {
                    systemd_service = match cgroup {
                        Some(ref path) => proc::try_extract_systemd_service(path),
                        _ => None,
                    };
                }
                let new_proc = self.state.processes.get_key_mut(&key).unwrap();
                new_proc.container_info = container_info;
                new_proc.systemd_service = systemd_service;
            }

            proc = self.state.processes.get_key(&key);
        }

        let proc = proc.unwrap();

        if proc
            .labels
            .intersection(&self.settings.filter_labels)
            .any(|_| true)
        {
            *filter_event = true;
        }

        // TODO: This logic needs to be split.
        if first_per_process && !self.settings.filter_first_per_process {
            *filter_event = false;
        }

        *process_key = Some(proc.key);

        // No point in adding translations / enrichments to record if
        // we are going to filter anyway.
        if *filter_event {
            return;
        }

        if let (Some(arch_name), true) = (arch_name, self.settings.translate_universal) {
            let key = match &self.settings.enrich_prefix {
                Some(s) => Key::Name(NVec::from_iter(s.bytes().chain(b"arch".iter().cloned()))),
                None => Key::Literal("ARCH"),
            };
            body.push((key, Value::Literal(arch_name)));
        }
        if let (Some(syscall_name), true) = (syscall_name, self.settings.translate_universal) {
            let key = match &self.settings.enrich_prefix {
                Some(s) => Key::Name(NVec::from_iter(s.bytes().chain(b"syscall".iter().cloned()))),
                None => Key::Literal("SYSCALL"),
            };
            body.push((key, Value::Literal(syscall_name)));
        }

        if self.settings.enrich_pid {
            self.add_record_procinfo(body, b"pid", proc);
            if let Some(parent_process) = proc
                .parent
                .and_then(|key| self.state.processes.get_key(&key))
            {
                self.add_record_procinfo(body, b"ppid", parent_process);
            }
        }

        if self.settings.translate_userdb {
            self.add_record_userdb(body, &ids);
        }

        if self.settings.enrich_uid_groups {
            if let Some(names) = ids
                .uid
                .and_then(|uid| self.state.userdb.get_user_groups(uid))
            {
                body.push((
                    Key::Literal("UID_GROUPS"),
                    Value::List(names.iter().map(|n| Value::from(n.as_bytes())).collect()),
                ));
            }
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
    pub fn process_line(&mut self, line: &[u8]) -> Result<(), CoalesceError> {
        let mut do_filter = self.settings.filter_raw_lines.is_match(line);

        let skip_enriched = self.settings.translate_universal && self.settings.translate_userdb;
        let mut msg = parse(line, skip_enriched).map_err(CoalesceError::Parse)?;
        let event_key = EventKey(msg.node.clone(), msg.id);

        // clean out state every EXPIRE_PERIOD
        match self.next_expire {
            Some(t) if t < msg.id.timestamp => {
                self.expire_inflight(msg.id.timestamp);
                self.expire_done(msg.id.timestamp);
                self.state.processes.expire();
                self.next_expire = Some(msg.id.timestamp + EXPIRE_PERIOD)
            }
            None => self.next_expire = Some(msg.id.timestamp + EXPIRE_PERIOD),
            _ => (),
        };

        let mut is_exec = false;
        let mut process_key = None;
        if msg.ty == MessageType::SYSCALL {
            self.handle_syscall(
                msg.id,
                &mut msg.body,
                &mut do_filter,
                &mut is_exec,
                &mut process_key,
            );
        }

        if msg.ty == MessageType::EOE {
            if self.state.done.contains(&event_key) {
                return Err(CoalesceError::DuplicateEvent(msg.id));
            }
            let ev = self
                .state
                .inflight
                .remove(&event_key)
                .ok_or(CoalesceError::SpuriousEOE(msg.id))?;
            self.emit_event(ev);
        } else if msg.ty.is_multipart() {
            // kernel-level messages
            if !self.state.inflight.contains_key(&event_key) {
                self.state
                    .inflight
                    .insert(event_key.clone(), Event::new(msg.node, msg.id));
            }
            let ev = self.state.inflight.get_mut(&event_key).unwrap();
            ev.is_filtered |= do_filter;
            ev.is_exec |= is_exec;
            if process_key.is_some() {
                ev.process_key = process_key;
            }

            match ev.body.get_mut(&msg.ty) {
                Some(EventValues::Single(v)) => v.extend(msg.body),
                Some(EventValues::Multi(v)) => v.push(msg.body),
                None => match msg.ty {
                    MessageType::SYSCALL => {
                        ev.body.insert(msg.ty, EventValues::Single(msg.body));
                    }
                    MessageType::EXECVE | MessageType::PROCTITLE | MessageType::CWD => {
                        ev.body.insert(msg.ty, EventValues::Single(msg.body));
                    }
                    _ => {
                        ev.body.insert(msg.ty, EventValues::Multi(vec![msg.body]));
                    }
                },
            };
        } else {
            // user-space messages
            if self.state.done.contains(&event_key) {
                return Err(CoalesceError::DuplicateEvent(msg.id));
            }
            let mut ev = Event::new(msg.node, msg.id);
            ev.is_filtered |= do_filter;
            ev.body.insert(msg.ty, EventValues::Single(msg.body));
            self.emit_event(ev);
        }
        Ok(())
    }

    /// Flush all in-flight event data, including partial events
    pub fn flush(&mut self) {
        self.expire_inflight(u64::MAX);
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
    use std::error::Error;
    use std::io::{BufRead, BufReader};
    use std::rc::Rc;

    fn event_to_json(e: &Event) -> String {
        let mut out = vec![];
        crate::json::to_writer(&mut out, e).unwrap();
        String::from_utf8_lossy(&out).to_string()
    }

    fn find_event<'a>(events: &'a [Event], id: &str) -> Option<Event<'a>> {
        events.iter().find(|e| &e.id == id).cloned()
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
            out.push(b'\n');
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
                Ok(l) if l.is_empty() => false,
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

        if process_record(&mut c, include_bytes!("testdata/line-user-acct.txt")).is_ok() {
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
        println!("{output}");
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
        assert!(
            output.contains(r#"NODE":"work","#),
            "node name is encoded correctly."
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
        if let EventValues::Multi(records) =
            &ec.borrow().as_ref().unwrap().body[&MessageType::LOGIN]
        {
            // Check for: pid uid subj old-auid auid tty old-ses ses res UID OLD-AUID AUID
            let l = records[0].len();
            assert!(
                l == 12,
                "expected 12 fields, got {l}: {:?}",
                records[0].clone().into_iter().collect::<Vec<_>>()
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

        if let EventValues::Single(record) =
            &ec.borrow().as_ref().unwrap().body[&MessageType::SYSCALL]
        {
            let mut uids = 0;
            let mut gids = 0;
            for (k, v) in record {
                if k.to_string().ends_with("UID") {
                    uids += 1;
                    assert!(v == "root", "Got {k}={v:?}, expected root");
                }
                if k.to_string().ends_with("GID") {
                    gids += 1;
                    assert!(v == gid0name.as_str(), "Got {k}={v:?}, expected root");
                }
            }
            assert!(
                uids == 5 && gids == 4,
                "Got {uids} uids/{gids} gids, expected 5/4",
            );
        }

        if let EventValues::Multi(records) =
            &ec.borrow().as_ref().unwrap().body[&MessageType::LOGIN]
        {
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
                records[0].clone().into_iter().collect::<Vec<_>>()
            );
            assert!(
                old_auid,
                "missing OLD-AUID: {:?}",
                records[0].clone().into_iter().collect::<Vec<_>>()
            );
            assert!(
                auid,
                "missing AUID: {:?}",
                records[0].clone().into_iter().collect::<Vec<_>>()
            );
        } else {
            panic!("expected EventValues::Multi");
        };
    }

    #[test]
    fn translate_userdb_execve() {
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
            strip_enriched(include_bytes!("testdata/record-execve.txt")),
        )
        .unwrap();

        let j = event_to_json(ec.borrow().as_ref().unwrap());
        println!("{j}");
        assert!(j.contains(r#""OUID":"root""#));
        assert!(j.contains(&format!(r#""OGID":"{gid0name}""#)));
    }

    #[test]
    fn translate_userdb_ptrace() {
        let ec = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(|e: &Event| *ec.borrow_mut() = Some(e.clone()));
        c.settings.translate_userdb = true;
        c.settings.translate_universal = true;

        process_record(
            &mut c,
            strip_enriched(include_bytes!("testdata/record-ptrace.txt")),
        )
        .unwrap();

        let j = event_to_json(ec.borrow().as_ref().unwrap());
        println!("{j}");
        for u in &[
            "AUID", "UID", "UID", "EUID", "SUID", "FSUID", "EUID", "SUID", "FSUID", "OAUID", "OUID",
        ] {
            assert!(
                j.contains(&format!(r#""{u}":"root"#)),
                "record does not contain {u}"
            );
        }
    }

    #[test]
    fn enrich_uid_groups() {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.translate_userdb = false;
        c.settings.enrich_uid_groups = true;

        process_record(&mut c, include_bytes!("testdata/record-execve.txt")).unwrap();

        assert!(
            event_to_json(ec.borrow().as_ref().unwrap()).contains(r#""UID_GROUPS":["#),
            "enrich.uid_groups is performed regardless of translate.userdb"
        );
    }

    #[test]
    fn enrich_uringop() {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.translate_userdb = true;
        c.settings.translate_universal = true;

        process_record(&mut c, include_bytes!("testdata/record-uringop.txt")).unwrap();

        let output = event_to_json(ec.borrow().as_ref().unwrap());
        println!("{output}");

        assert!(
            output.contains(r#""URING_OP":"openat""#),
            "uring operations should be translated."
        );
        assert!(
            output.contains(r#""UID":"root""#)
                && output.contains(r#""GID":"root""#)
                && output.contains(r#""EUID":"root""#)
                && output.contains(r#""SUID":"root""#)
                && output.contains(r#""FSUID":"root""#)
                && output.contains(r#""EGID":"root""#)
                && output.contains(r#""SGID":"root""#)
                && output.contains(r#""FSGID":"root""#),
            "*uid, *gid should be translated"
        );

        // todo: pid, ppid
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

    #[test]
    fn label_argv() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.label_argv = Some(LabelMatcher::new(&[(
            r#"^\S*java .* -Dweblogic"#,
            "weblogic",
        )])?);

        process_record(&mut c, include_bytes!("testdata/record-weblogic.txt"))?;

        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["weblogic"]"#));

        // Ensure this does not crash with long command lines
        // TODO: check matcher behavior
        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.label_argv = Some(LabelMatcher::new(&[(
            r#"/opt/app/redacted/to/protect/the/guilty/"#,
            "protect-the-guilty",
        )])?);
        let buf = gen_long_find_execve();
        process_record(&mut c, buf)?;
        assert!(event_to_json(ec.borrow().as_ref().unwrap())
            .contains(r#"LABELS":["protect-the-guilty"]"#));

        let mut c = Coalesce::new(mk_emit(&ec));
        c.settings.label_argv = Some(LabelMatcher::new(&[
            (r#"^/bin/echo "#, "echo"), // this should match.
            (r#"aaaaaaaaaa"#, "aaaa"),  // this shouldn't. argv[1] is too long for the buffer.
        ])?);
        process_record(&mut c, include_bytes!("testdata/record-execve-long.txt"))?;
        assert!(event_to_json(ec.borrow().as_ref().unwrap()).contains(r#"LABELS":["echo"]"#));

        Ok(())
    }

    // Returns an emitter function that puts the event into an Option
    fn mk_emit<'c, 'ev: 'c>(
        ec: &'c Rc<RefCell<Option<Event<'ev>>>>,
    ) -> impl FnMut(&Event<'ev>) + 'c {
        |ev: &Event| {
            if !ev.is_filtered {
                *ec.borrow_mut() = Some(ev.clone());
            }
        }
    }

    // Returns an emitter function that appends the event onto a Vec
    fn mk_emit_vec<'c, 'ev>(ec: &'c Rc<RefCell<Vec<Event<'ev>>>>) -> impl FnMut(&Event<'ev>) + 'c {
        |ev: &Event| {
            if !ev.is_filtered {
                ec.borrow_mut().push(ev.clone());
            }
        }
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
        // fist event for process -> don't filter
        assert!(events
            .borrow()
            .iter()
            .any(|e| &e.id == "1628602815.266:2365"));
        assert!(!events
            .borrow()
            .iter()
            .any(|e| &e.id == "1628602815.266:2366"));
        assert!(!events
            .borrow()
            .iter()
            .any(|e| &e.id == "1628602815.266:2367"));

        let mut c = Coalesce::new(mk_emit_vec(&events));
        c.settings.filter_null_keys = true;
        process_record(
            &mut c,
            include_bytes!("testdata/record-syscall-nullkey.txt"),
        )?;
        drop(c);

        // not first event for process -> filter
        assert!(!events
            .borrow()
            .iter()
            .any(|e| &e.id == "1678282381.452:102337"));
        // fist event for process -> don't filter
        assert!(events
            .borrow()
            .iter()
            .any(|e| &e.id == "1678283440.683:225"));

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
        c.settings.filter_first_per_process = true;
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
        for (name, filter) in &[
            ("sockaddr", "^type=SOCKADDR (?:node=\\$*? )?msg=audit\\(\\S*?\\): saddr=01002F7661722F72756E2F6E7363642F736F636B657400"),
            ("syscall", "^type=SYSCALL (?:node=\\$*? )?msg=audit\\(.*?\\): arch=c000003e syscall=42 success=no"),
        ] {
            let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));
            let mut c = Coalesce::new(mk_emit_vec(&events));
            c.settings.filter_raw_lines = regex::bytes::RegexSet::new([
                filter
            ])
                .expect("failed to compile regex");
            c.settings.filter_first_per_process = true;
            process_record(&mut c, include_bytes!("testdata/record-nscd.txt")).unwrap();
            assert!(
                !events
                    .borrow()
                    .iter()
                    .any(|e| &e.id == "1705071450.879:29498378"),
                "nscd connect event should be filtered using {name}"
            )
        }
    }

    #[test]
    fn filter_sockaddr() {
        for filter in &[
            &["127.0.0.1", "::1"][..],
            &["127.0.0.0/8", "::/64"],
            &["127.0.0.1:11211", "[::1]:11211"],
            &["127.0.0.0/8:11211", "[::/64]:11211"],
            &["*:11211"],
        ] {
            {
                let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));
                let mut c = Coalesce::new(mk_emit_vec(&events));
                c.settings.filter_first_per_process = true;
                c.settings.filter_sockaddr = filter.iter().map(|s| s.parse().unwrap()).collect();
                process_record(&mut c, include_bytes!("testdata/record-connect.txt")).unwrap();
                let events = events.borrow();
                println!("{events:?}");
                assert!(!events.iter().any(|e| &e.id == "1723819442.459:2482681"));
                assert!(!events.iter().any(|e| &e.id == "1723819442.459:2482682"));
            }
        }
    }

    fn gen_long_find_execve() -> Vec<u8> {
        let mut buf = vec![];
        let msgid = "1663143990.204:2148478";
        let npath = 40000;

        buf.extend(
            format!(r#"type=SYSCALL msg=audit({msgid}): arch=c000003e syscall=59 success=yes exit=0 a0=1468e584be18 a1=1468e57f5078 a2=1468e584bd68 a3=7ffc3e352220 items=2 ppid=9264 pid=9279 auid=4294967295 uid=995 gid=992 euid=995 suid=995 fsuid=995 egid=992 sgid=992 fsgid=992 tty=(none) ses=4294967295 comm="find" exe="/usr/bin/find" key=(null)
"#).bytes());
        buf.extend(
            format!(
                r#"type=EXECVE msg=audit({msgid}): argc={} a0="/usr/bin/find" "#,
                npath + 9
            )
            .bytes(),
        );
        for i in 1..npath {
            if i % 70 == 0 {
                buf.extend(format!("\ntype=EXECVE msg=audit({msgid}): ").bytes());
            } else {
                buf.push(b' ');
            }
            buf.extend(format!(r#"a{i}="/opt/app/redacted/to/protect/the/guilty/output_processing.2022-09-06.{i:05}.garbage""#).bytes());
        }
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
            buf.extend(format!(r#" a{}="{param}""#, npath + i).bytes());
        }
        buf.extend(format!("\ntype=EOE msg=audit({msgid}): \n").bytes());
        buf
    }

    #[test]
    fn strip_long_argv() -> Result<(), Box<dyn Error>> {
        let ec: Rc<RefCell<Option<Event>>> = Rc::new(RefCell::new(None));

        let mut c = Coalesce::new(mk_emit(&ec));

        c.settings.execve_argv_limit_bytes = Some(10000);
        let buf = gen_long_find_execve();

        process_record(&mut c, &buf)?;
        {
            let output = event_to_json(ec.borrow().as_ref().unwrap());
            assert!(output.len() < 15000);
            assert!(
                output.contains(".00020.garbage"),
                "Can't find start of argv"
            );
            assert!(output.contains(".39980.garbage"), "Can't find end of argv");
            assert!(
                !output.contains(".20000.garbage"),
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
            filter_first_per_process: true,
            ..s1.clone()
        };
        let s3 = Settings {
            filter_first_per_process: false, // default in 0.6.2+
            ..s2.clone()
        };

        for (n, s) in [s1, s2, s3].iter().enumerate() {
            let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));

            println!("Using configuration #{n}");
            for (tn, text) in [
                &include_bytes!("testdata/shell-proc-trace.txt")[..],
                &include_bytes!("testdata/shell-proc-trace-reordered.txt")[..],
            ]
            .iter()
            .enumerate()
            {
                let mut c = Coalesce::new(mk_emit_vec(&events));
                c.settings = s.clone();

                process_record(&mut c, text).unwrap();

                let events = events.borrow();

                let mut present_and_label = vec![
                    "1682609045.526:29238",
                    "1682609045.530:29242",
                    "1682609045.530:29244",
                    "1682609045.534:29245",
                ];
                let mut absent = vec![];
                match n {
                    0 => {
                        present_and_label.extend([
                            "1682609045.530:29239",
                            "1682609045.530:29240",
                            "1682609045.530:29241",
                            "1682609045.530:29243",
                        ]);
                    }
                    1 => {
                        absent.extend([
                            "1682609045.526:29237",
                            "1682609045.530:29239",
                            "1682609045.530:29240",
                            "1682609045.530:29241",
                            "1682609045.530:29243",
                        ]);
                    }
                    2 => {
                        // fork = first event in pid=71506
                        present_and_label.extend(["1682609045.530:29241"]);

                        absent.extend([
                            "1682609045.530:29239",
                            "1682609045.530:29240",
                            "1682609045.530:29243",
                        ]);
                    }
                    _ => {}
                };

                for id in present_and_label {
                    let event =
                        find_event(&events, id).unwrap_or_else(|| panic!("Did not find {id}"));
                    assert!(
                        event_to_json(&event).contains(r#""LABELS":["test-script"]"#),
                        "{id} was not labelled correctly (config {n} test {tn})."
                    );
                }
                for id in absent {
                    if find_event(&events, id).is_some() {
                        panic!("Found {id} though it should have been filtered (config {n} test {tn}).");
                    }
                }
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
                let event = find_event(&events, id).unwrap_or_else(|| panic!("Did not find {id}"));
                println!("{}", event_to_json(&event));
            }

            let id = "1697091526.357:2638035";
            let event = find_event(&events, id).unwrap_or_else(|| panic!("Did not find {id}"));
            assert!(
                event_to_json(&event).contains(
                    r#""PPID":{"EVENT_ID":"1697091526.357:2638033","comm":"csh","exe":"/bin/tcsh","ppid":2542}"#),
                "Did not get correct parent for {id}\n\n{}", event_to_json(&event));
            println!("{}", event_to_json(&event));
        }
    }
    /// Simulate restart + reading state
    ///
    /// After the process table has been primed with a parent process
    /// entry, half an event is read. The state is saved and
    /// transferred into a second Coalesce which reads the second half
    /// of the event. We expect ppid enrichment to work properly.
    #[test]
    fn state() {
        let settings = Settings {
            enrich_script: false,
            enrich_uid_groups: false,
            ..Settings::default()
        };

        let mut saved_state = vec![];

        {
            // coalesce 1 gets half an event
            let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));
            let event_id = EventID::from_str("1740869913.604:3976").expect("Can't parse event ID");
            let mut c = Coalesce::new(mk_emit_vec(&events)).with_state(State {
                processes: ProcTable {
                    current: {
                        let mut m = BTreeMap::new();
                        m.insert(127727, ProcessKey::Event(event_id));
                        m
                    },
                    processes: {
                        let mut m = BTreeMap::new();
                        m.insert(
                            ProcessKey::Event(event_id),
                            Process {
                                key: ProcessKey::Event(event_id),
                                pid: 127727,
                                ppid: 3432,
                                ..Default::default()
                            },
                        );
                        m
                    },
                },
                ..State::default()
            });
            c.settings = settings.clone();

            process_record(
                &mut c,
                br#"type=SYSCALL msg=audit(1740992884.191:7058722): arch=c000003e syscall=59 success="yes" exit=0 a0=56037c8a09b0 a1=7ffe40c717e0 a2=560380740450 a3=fffffffffffffa68 items=3 ppid=127727 pid=1780659 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty="pts10" ses=3 comm="bash" exe="/usr/bin/bash" subj="unconfined" key=null
type=EXECVE msg=audit(1740992884.191:7058722): argc=3 a0="/bin/bash" a1="--noediting" a2="-i"
type=CWD msg=audit(1740992884.191:7058722): cwd="/home/user"
type=PATH msg=audit(1740992884.191:7058722): item=0 name="/bin/bash" inode=393229 dev="fd:01" mode=100755 ouid=0 ogid=0 rdev="00:00" nametype="NORMAL" cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid="0"
"#).expect("Error in parsing first half of event");

            crate::json::to_writer(&mut saved_state, c.state()).expect("cant't serialize state");
        }

        {
            let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));
            let mut c = Coalesce::new(mk_emit_vec(&events)).with_state(
                crate::json::from_reader(std::io::Cursor::new(&saved_state))
                    .expect("can't deserialize state"),
            );

            c.settings = settings;

            process_record(
                &mut c,
                br#"type=PATH msg=audit(1740992884.191:7058722): item=1 name="/bin/bash" inode=393229 dev="fd:01" mode=100755 ouid=0 ogid=0 rdev="00:00" nametype="NORMAL" cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid="0"
type=PATH msg=audit(1740992884.191:7058722): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=401532 dev="fd:01" mode=100755 ouid=0 ogid=0 rdev="00:00" nametype="NORMAL" cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid="0"
type=EOE msg=audit(1740992884.191:7058722):
"#).expect("Error in parsing second half of event");

            let events = events.borrow();
            for event in events.iter() {
                println!("{}", event_to_json(event));
            }

            let id = "1740992884.191:7058722";
            let event = find_event(&events, id).unwrap_or_else(|| panic!("Did not find {id}"));
            assert!(event_to_json(&event).contains(r#"PPID":{"EVENT_ID":"1740869913.604:3976""#));
        }
    }

    #[test]
    fn prelabel() {
        let settings = Settings {
            enrich_script: false,
            enrich_uid_groups: false,
            label_exe: LabelMatcher::new(&[("^/usr/bin/emacs(?:-nox|-pgtk)?", "emacs")]).ok(),
            proc_propagate_labels: [b"emacs".to_vec()].into(),
            ..Settings::default()
        };

        let events: Rc<RefCell<Vec<Event>>> = Rc::new(RefCell::new(vec![]));

        let event_id = EventID::from_str("1740869913.604:3976").expect("Can't parse event ID");
        let mut c = Coalesce::new(mk_emit_vec(&events))
            .with_settings(settings)
            .with_state(State {
                processes: ProcTable {
                    current: {
                        let mut m = BTreeMap::new();
                        m.insert(127727, ProcessKey::Event(event_id));
                        m
                    },
                    processes: {
                        let mut m = BTreeMap::new();
                        m.insert(
                            ProcessKey::Event(event_id),
                            Process {
                                key: ProcessKey::Event(event_id),
                                exe: Some(b"/usr/bin/emacs"[..].into()),
                                comm: Some(b"emacs"[..].into()),
                                pid: 127727,
                                ppid: 3432,
                                ..Default::default()
                            },
                        );
                        m
                    },
                },
                ..State::default()
            });

        process_record(
            &mut c,
            br#"type=SYSCALL msg=audit(1740992884.191:7058722): arch=c000003e syscall=59 success="yes" exit=0 a0=56037c8a09b0 a1=7ffe40c717e0 a2=560380740450 a3=fffffffffffffa68 items=3 ppid=127727 pid=1780659 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty="pts10" ses=3 comm="bash" exe="/usr/bin/bash" subj="unconfined" key=null
type=EXECVE msg=audit(1740992884.191:7058722): argc=3 a0="/bin/bash" a1="--noediting" a2="-i"
type=CWD msg=audit(1740992884.191:7058722): cwd="/home/user"
type=PATH msg=audit(1740992884.191:7058722): item=0 name="/bin/bash" inode=393229 dev="fd:01" mode=100755 ouid=0 ogid=0 rdev="00:00" nametype="NORMAL" cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid="0"
type=PATH msg=audit(1740992884.191:7058722): item=1 name="/bin/bash" inode=393229 dev="fd:01" mode=100755 ouid=0 ogid=0 rdev="00:00" nametype="NORMAL" cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid="0"
type=PATH msg=audit(1740992884.191:7058722): item=2 name="/lib64/ld-linux-x86-64.so.2" inode=401532 dev="fd:01" mode=100755 ouid=0 ogid=0 rdev="00:00" nametype="NORMAL" cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid="0"
type=EOE msg=audit(1740992884.191:7058722):
"#
        ).expect("Error in parsing second half of event");

        let id = "1740992884.191:7058722";
        let events = events.borrow();
        let event = find_event(&events, id).unwrap_or_else(|| panic!("Did not find {id}"));
        println!("{}", event_to_json(&event));
        assert!(event_to_json(&event).contains(r#"LABELS":["emacs"]"#));
    }
}
