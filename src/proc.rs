use std::boxed::Box;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::error::Error;
use std::fmt::{self, Display};
use std::iter::Iterator;
use std::vec::Vec;

use serde::{Serialize, Serializer};

use crate::label_matcher::LabelMatcher;
use crate::types::EventID;

#[cfg(all(feature = "procfs", target_os = "linux"))]
use crate::procfs;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ContainerInfo {
    #[serde(with = "faster_hex::nopfx_lowercase")]
    pub id: Vec<u8>,
}

/// Host-unique identifier for processes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl Serialize for ProcessKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&self)
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

#[derive(Clone, Debug, Default, Serialize)]
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
    pub exe: Option<Vec<u8>>,
    /// process-settable argv[0]
    pub comm: Option<Vec<u8>>,
    /// Labels assigned to process
    pub labels: HashSet<Vec<u8>>,
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    pub container_info: Option<ContainerInfo>,
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
            container_info: p.container_id.map(|id| ContainerInfo { id }),
        }
    }
}

impl Process {
    /// Generate a shadow process table entry from /proc/$PID for a given PID
    #[cfg(all(feature = "procfs", target_os = "linux"))]
    pub fn parse_proc(pid: u32) -> Result<Process, Box<dyn Error>> {
        procfs::parse_proc_pid(pid)
            .map(|p| p.into())
            .map_err(|e| e.into())
    }
}

/// Shadow process table
///
/// This process table replica can be fed with EXECVE-based events or
/// from /proc entries.
#[derive(Debug, Default, Serialize)]
pub struct ProcTable {
    processes: BTreeMap<ProcessKey, Process>,
    current: BTreeMap<u32, ProcessKey>,
}

impl ProcTable {
    /// Constructs process table from /proc entries
    ///
    /// If label_exe and propagate_labels are supplied, Process labels
    /// based on executable are applied and propagated to children.
    pub fn from_proc(
        label_exe: Option<LabelMatcher>,
        propagate_labels: &HashSet<Vec<u8>>,
    ) -> Result<ProcTable, Box<dyn Error>> {
        let mut pt = ProcTable {
            processes: BTreeMap::new(),
            current: BTreeMap::new(),
        };

        #[cfg(all(feature = "procfs", target_os = "linux"))]
        {
            for pid in procfs::get_pids()? {
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
        self.processes.insert(proc.key, proc.clone());
        self.current.insert(proc.pid, proc.key);
    }

    /// Retrieves a process by key.
    pub fn get_key(&self, key: &ProcessKey) -> Option<&Process> {
        self.processes.get(key)
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
    #[cfg(all(feature = "procfs", target_os = "linux"))]
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
    #[cfg(not(all(feature = "procfs", target_os = "linux")))]
    pub fn expire(&self) {}

    pub fn set_labels(&mut self, key: &ProcessKey, labels: &HashSet<Vec<u8>>) {
        if let Some(p) = self.processes.get_mut(key) {
            p.labels = labels.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
