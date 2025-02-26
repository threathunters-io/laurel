use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fmt::{self, Display};
use std::iter::Iterator;
use std::str::FromStr;
use std::vec::Vec;

#[cfg(all(feature = "procfs", target_os = "linux"))]
use faster_hex::hex_decode;

use serde::{Deserialize, Serialize};

use serde_with::{DeserializeFromStr, SerializeDisplay};

use thiserror::Error;

use crate::label_matcher::LabelMatcher;

use linux_audit_parser::*;

use crate::coalesce;
#[cfg(all(feature = "procfs", target_os = "linux"))]
use crate::procfs;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ContainerInfo {
    #[serde(with = "faster_hex::nopfx_lowercase")]
    pub id: Vec<u8>,
}

/// Host-unique identifier for processes
#[derive(Clone, Copy, Debug, PartialEq, Eq, DeserializeFromStr, SerializeDisplay)]
pub enum ProcessKey {
    Event(EventID),
    Observed { time: u64, pid: u32 },
}

impl Display for ProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcessKey::Event(id) => {
                write!(f, "id[{id}]")
            }
            ProcessKey::Observed { time: t, pid: p } => {
                write!(f, "ob[{t},{p}]")
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum ParseProcessKeyError {
    #[error("invalid tag")]
    Tag,
    #[error("invalid format")]
    Format,
    #[error("id")]
    ID(ParseEventIDError),
    #[error("int")]
    Int(std::num::ParseIntError),
}

impl FromStr for ProcessKey {
    type Err = ParseProcessKeyError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(s) = s.strip_prefix("id[") {
            let s = s.strip_suffix("]").ok_or(ParseProcessKeyError::Format)?;
            Ok(ProcessKey::Event(
                s.parse().map_err(ParseProcessKeyError::ID)?,
            ))
        } else if let Some(s) = s.strip_prefix("ob[") {
            let s = s.strip_suffix("]").ok_or(ParseProcessKeyError::Format)?;
            let (msec, pid) = s.split_once(",").ok_or(ParseProcessKeyError::Format)?;
            let time = msec.parse().map_err(ParseProcessKeyError::Int)?;
            let pid = pid.parse().map_err(ParseProcessKeyError::Int)?;
            Ok(ProcessKey::Observed { time, pid })
        } else {
            Err(ParseProcessKeyError::Tag)
        }
    }
}

impl Default for ProcessKey {
    fn default() -> Self {
        ProcessKey::Observed { time: 0, pid: 0 }
    }
}

impl Ord for ProcessKey {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Event(s), Self::Event(o)) => s
                .timestamp
                .cmp(&o.timestamp)
                .then_with(|| s.sequence.cmp(&o.sequence)),
            (Self::Observed { time: s, pid: _ }, Self::Event(o)) => {
                s.cmp(&o.timestamp).then(Ordering::Less)
            }
            (Self::Event(s), Self::Observed { time: o, pid: _ }) => {
                s.timestamp.cmp(o).then(Ordering::Greater)
            }
            (Self::Observed { time: st, pid: sp }, Self::Observed { time: ot, pid: op }) => {
                st.cmp(ot).then_with(|| sp.cmp(op))
            }
        }
    }
}

impl PartialOrd for ProcessKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Process {
    /// "primary key", unique per host
    pub key: ProcessKey,
    /// parent's key, if a parent has been recorded.
    pub parent: Option<ProcessKey>,
    /// process ID
    pub pid: u32,
    /// parent's porocess ID
    pub ppid: u32,
    /// path to binary
    #[serde(with = "serde_bytes")]
    pub exe: Option<Vec<u8>>,
    /// process-settable argv[0]
    #[serde(with = "serde_bytes")]
    pub comm: Option<Vec<u8>>,
    /// Labels assigned to process
    pub labels: HashSet<Vec<u8>>,
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    pub container_info: Option<ContainerInfo>,
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    pub systemd_service: Option<Vec<Vec<u8>>>,
}

#[cfg(all(feature = "procfs", target_os = "linux"))]
impl From<procfs::ProcPidInfo> for Process {
    fn from(p: procfs::ProcPidInfo) -> Self {
        Self {
            key: ProcessKey::Observed {
                time: p.starttime,
                pid: p.pid,
            },
            parent: None,
            pid: p.pid,
            ppid: p.ppid,
            labels: HashSet::new(),
            exe: p.exe,
            comm: p.comm,
            container_info: p
                .cgroup
                .as_deref()
                .and_then(try_extract_container_id)
                .map(|id| ContainerInfo { id }),
            systemd_service: p.cgroup.as_deref().and_then(try_extract_systemd_service),
        }
    }
}

#[cfg(all(feature = "procfs", target_os = "linux"))]
fn extract_sha256(buf: &[u8]) -> Option<Vec<u8>> {
    let mut dec = [0u8; 32];
    match buf.len() {
        n if n < 64 => None,
        _ if hex_decode(&buf[buf.len() - 64..], &mut dec).is_ok() => Some(Vec::from(dec)),
        _ if hex_decode(&buf[..64], &mut dec).is_ok() => Some(Vec::from(dec)),
        _ => None,
    }
}

/// Try to determine container ID from cgroup path
#[cfg(all(feature = "procfs", target_os = "linux"))]
pub(crate) fn try_extract_container_id(path: &[u8]) -> Option<Vec<u8>> {
    for fragment in path.split(|&c| c == b'/') {
        let fragment = if fragment.ends_with(&b".scope"[..]) {
            &fragment[..fragment.len() - 6]
        } else {
            fragment
        };
        match extract_sha256(fragment) {
            None => continue,
            Some(id) => return Some(id),
        }
    }
    None
}

/// Try to extract "something.service" fragments from cgroup path
#[cfg(all(feature = "procfs", target_os = "linux"))]
pub(crate) fn try_extract_systemd_service(path: &[u8]) -> Option<Vec<Vec<u8>>> {
    let svc: Vec<_> = path
        .split(|&c| c == b'/')
        .filter_map(|f| f.strip_suffix(&b".service"[..]))
        .map(Vec::from)
        .collect();
    if svc.is_empty() {
        None
    } else {
        Some(svc)
    }
}

impl Process {
    /// Generate a shadow process table entry from /proc/$PID for a given PID
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    pub fn parse_proc(pid: u32) -> Result<Process, ProcError> {
        procfs::parse_proc_pid(pid)
            .map(|p| p.into())
            .map_err(ProcError::ProcFSError)
    }
}

#[derive(Debug, Error)]
pub enum ProcError {
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    #[error("{0}")]
    ProcFSError(procfs::ProcFSError),
}

/// Shadow process table
///
/// This process table replica can be fed with EXECVE-based events or
/// from /proc entries.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ProcTable {
    pub(crate) processes: BTreeMap<ProcessKey, Process>,
    pub(crate) current: BTreeMap<u32, ProcessKey>,
}

impl ProcTable {
    /// Constructs process table from /proc entries
    ///
    /// If label_exe and propagate_labels are supplied, Process labels
    /// based on executable are applied and propagated to children.
    pub fn from_proc(
        label_exe: Option<LabelMatcher>,
        propagate_labels: &HashSet<Vec<u8>>,
    ) -> Result<ProcTable, ProcError> {
        let mut pt = ProcTable {
            processes: BTreeMap::new(),
            current: BTreeMap::new(),
        };

        #[cfg(all(feature = "procfs", target_os = "linux"))]
        {
            for pid in procfs::get_pids().map_err(ProcError::ProcFSError)? {
                // /proc/<pid> access is racy. Ignore errors here.
                if let Ok(mut proc) = Process::parse_proc(pid) {
                    if let (Some(label_exe), Some(exe)) = (&label_exe, &proc.exe) {
                        proc.labels
                            .extend(label_exe.matches(exe).iter().map(|v| Vec::from(*v)));
                    }
                    pt.insert(proc);
                }
            }
            // build parent/child relationships
            for proc in pt.processes.values_mut() {
                if proc.parent.is_none() {
                    proc.parent = pt.current.get(&proc.pid).cloned();
                }
            }
        }

        if let Some(label_exe) = &label_exe {
            for proc in pt.processes.values_mut() {
                if let Some(exe) = &proc.exe {
                    proc.labels
                        .extend(label_exe.matches(exe).into_iter().map(|c| c.into()))
                }
            }
            if !propagate_labels.is_empty() { /* TODO */ }
        }

        Ok(pt)
    }

    pub fn insert(&mut self, proc: Process) {
        let (pid, key) = (proc.pid, proc.key);
        self.processes.insert(proc.key, proc);
        self.current.insert(pid, key);
    }

    /// Retrieves a process by key.
    pub fn get_key(&self, key: &ProcessKey) -> Option<&Process> {
        self.processes.get(key)
    }

    /// Retrieves a mutable process by key.
    pub fn get_key_mut(&mut self, key: &ProcessKey) -> Option<&mut Process> {
        self.processes.get_mut(key)
    }

    /// Retrieves a process by pid.
    pub fn get_pid(&self, pid: u32) -> Option<&Process> {
        self.current.get(&pid).and_then(|pk| self.get_key(pk))
    }

    /// Retrieves a process by pid. If the process is not found in the
    /// shadow process table, an attempt is made to fetch the
    /// information from another source, i.e. /proc.
    pub fn get_or_retrieve(&mut self, pid: u32) -> Option<&Process> {
        #[cfg(all(feature = "procfs", target_os = "linux"))]
        if self.get_pid(pid).is_none() {
            self.insert_from_procfs(pid);
        }
        self.get_pid(pid)
    }

    /// Fetch process information from procfs, insert into shadow
    /// process table.
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    pub fn insert_from_procfs(&mut self, pid: u32) -> Option<&Process> {
        if let Ok(p) = Process::parse_proc(pid) {
            let key = p.key;
            self.insert(p);
            self.processes.get(&key)
        } else {
            None
        }
    }

    /// Remove processes that are no longer running and that were not
    /// parents of currently running processes.
    ///
    /// It should be possible to run this every few seconds without
    /// incurring load.
    #[cfg(all(feature = "procfs", target_os = "linux", not(test)))]
    pub fn expire(&mut self) {
        use std::collections::BTreeSet;

        let mut proc_prune: BTreeSet<ProcessKey> = self.processes.keys().cloned().collect();
        let mut pid_prune: Vec<u32> = vec![];

        let live_processes = match procfs::get_pids() {
            Ok(p) => p,
            Err(_) => return,
        };
        // unmark latest instance in by_pids and all its parents
        for seed_pid in live_processes {
            let mut key = match self.current.get(&seed_pid) {
                None => continue,
                Some(&key) => key,
            };

            // keep all parents of live processes => remove them from
            // the prune list.
            loop {
                if !proc_prune.remove(&key) {
                    break;
                }

                key = match self.processes.get(&key) {
                    Some(Process {
                        pid,
                        parent: Some(parent_key),
                        ..
                    }) if *pid >= 1 => *parent_key,
                    _ => break,
                };
            }
        }
        // remove entries from primary process list
        for key in &proc_prune {
            self.processes.remove(key);
        }
        // remove pidi entries for processes that have disappeared
        for (pid, pk) in &self.current {
            if proc_prune.contains(pk) {
                pid_prune.push(*pid);
            }
        }
        for pid in pid_prune {
            self.current.remove(&pid);
        }
    }

    /// No expire mechanism has been implemented for the case where
    /// there's no procfs support.
    #[cfg(not(all(feature = "procfs", target_os = "linux", not(test))))]
    pub fn expire(&self) {}

    pub fn set_labels(&mut self, key: &ProcessKey, labels: &HashSet<Vec<u8>>) {
        if let Some(p) = self.processes.get_mut(key) {
            p.labels.clone_from(labels);
        }
    }

    /// Apply exe-specific labels to a single process
    pub fn relabel_process(&mut self, pk: &ProcessKey, settings: &coalesce::Settings) {
        let proc = match self.processes.get(pk) {
            Some(p) => p,
            _ => return,
        };
        // inherit
        let mut labels = proc.labels.clone();
        if let Some(parent) = proc.parent.and_then(|pk| self.processes.get(&pk)) {
            labels.extend(
                parent
                    .labels
                    .intersection(&settings.proc_propagate_labels)
                    .cloned(),
            );
        }
        // label, unlabel
        if let (Some(exe), Some(label_exe)) = (&proc.exe, &settings.label_exe) {
            for label in label_exe.matches(exe) {
                labels.insert(label.into());
            }
        }
        if let (Some(exe), Some(unlabel_exe)) = (&proc.exe, &settings.unlabel_exe) {
            for label in unlabel_exe.matches(exe) {
                labels.remove(label);
            }
        }
        self.processes.get_mut(pk).unwrap().labels = labels;
    }

    /// Apply exe-specific labels to all processes in the process table
    ///
    /// This means applying propagate-labels, label-exe, unlabel-exe.
    pub fn relabel_all(&mut self, settings: &coalesce::Settings) {
        // Create an ordering of processes such that every process
        // precedes all its childen
        let mut unseen: BTreeSet<ProcessKey> = self.processes.keys().cloned().collect();
        for pk in &unseen.clone() {
            let mut chain = vec![];
            let mut key = *pk;
            loop {
                chain.push(key);
                unseen.remove(&key);
                key = match self.processes.get(&key).and_then(|proc| proc.parent) {
                    Some(pk) if unseen.contains(&pk) => pk,
                    _ => break,
                };
            }
            for pk in chain.iter().rev() {
                self.relabel_process(pk, &settings);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    #[test]
    fn show_processes() -> Result<(), Box<dyn Error>> {
        let pt = ProcTable::from_proc(None, &HashSet::new())?;
        for p in pt.processes {
            println!("{:?}", &p);
        }
        Ok(())
    }

    #[test]
    fn proc_key_ord() {
        let e1 = ProcessKey::Event(EventID {
            timestamp: 1700000000000,
            sequence: 1000,
        });
        let e2 = ProcessKey::Event(EventID {
            timestamp: 1700000000000,
            sequence: 1001,
        });
        let e3 = ProcessKey::Event(EventID {
            timestamp: 1700000000001,
            sequence: 1002,
        });
        let o1 = ProcessKey::Observed {
            time: 1700000000000,
            pid: 1000,
        };
        let o2 = ProcessKey::Observed {
            time: 1700000000000,
            pid: 1001,
        };
        let o3 = ProcessKey::Observed {
            time: 1700000000001,
            pid: 1002,
        };

        for e in [e1, e2, e3] {
            for o in [o1, o2, o3] {
                assert!(e.cmp(&o).is_ne(), "{e} should not be equal to {o}");
                assert!(o.cmp(&e).is_ne(), "{o} should not be equal to {e}");
            }
        }

        assert!(e1.cmp(&e2).is_lt());
        assert!(e1.cmp(&e3).is_lt());
        assert!(e2.cmp(&e3).is_lt());

        assert!(o1.cmp(&o2).is_lt());
        assert!(o1.cmp(&o3).is_lt());
        assert!(o2.cmp(&o3).is_lt());

        assert!(e1.cmp(&o1).is_gt());
        assert!(e1.cmp(&o2).is_gt());
        assert!(e1.cmp(&o3).is_lt());

        assert!(e2.cmp(&o1).is_gt());
        assert!(e2.cmp(&o2).is_gt());
        assert!(e2.cmp(&o3).is_lt());

        assert!(e3.cmp(&o1).is_gt());
        assert!(e3.cmp(&o2).is_gt());
        assert!(e3.cmp(&o3).is_gt());
    }

    #[test]
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    fn extract_container_id() {
        for (raw, expected) in &[
            (&b""[..], None),
            (&b"0::/init.scope"[..], None),
            (&b"0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-f13b567f07e025055fa9fa2793f44695036e3d412d82d16ee03d72e8b4eb8387.scope/container"[..],
             Some(Vec::from(&b"\xf1\x3b\x56\x7f\x07\xe0\x25\x05\x5f\xa9\xfa\x27\x93\xf4\x46\x95\x03\x6e\x3d\x41\x2d\x82\xd1\x6e\xe0\x3d\x72\xe8\xb4\xeb\x83\x87"[..]))),
            (&b"0::/system.slice/docker-2b45249a1a21d3806efd98e2eb93c7dc319c645a27e7cd85362227becc68ca44.scope"[..],
             Some(Vec::from(&b"\x2b\x45\x24\x9a\x1a\x21\xd3\x80\x6e\xfd\x98\xe2\xeb\x93\xc7\xdc\x31\x9c\x64\x5a\x27\xe7\xcd\x85\x36\x22\x27\xbe\xcc\x68\xca\x44"[..]))),
        ] {
            let got = try_extract_container_id(raw);
            assert_eq!(*expected, got);
        }
    }

    #[test]
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    fn extract_systemd_service() {
        for (raw, expected) in &[
            (&b""[..], None),
            (&b"0::/init.scope"[..], None),
            (
                &b"0::/system.slice/nginx.service"[..],
                Some(vec![b"nginx".to_vec()]),
            ),
            (
                &b"0::/user.slice/user-1000.slice/user@1000.service/app.slice/emacs.service"[..],
                Some(vec![b"user@1000".to_vec(), b"emacs".to_vec()]),
            ),
        ] {
            let got = try_extract_systemd_service(raw);
            assert_eq!(*expected, got);
        }
    }
}
