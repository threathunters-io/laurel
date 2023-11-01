use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::error::Error;
use std::iter::Iterator;
use std::vec::Vec;

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::label_matcher::LabelMatcher;
use crate::types::{EventID, Number, Record, Value};

#[cfg(feature = "procfs")]
use crate::procfs;

#[derive(Clone, Debug, Default)]
pub struct ContainerInfo {
    pub id: Vec<u8>,
}

#[cfg(feature = "procfs")]
impl ContainerInfo {
    fn parse_proc(pid: u32) -> Result<ContainerInfo, Box<dyn Error>> {
        procfs::parse_proc_pid_cgroup(pid).map(|id| ContainerInfo {
            id: id.unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct Process {
    /// Unix timestamp with millisecond precision
    pub launch_time: u64,
    /// parent process id
    pub ppid: u32,
    pub labels: HashSet<Vec<u8>>,
    /// Event ID containing the event spawning this process entry
    /// (should be EXECVE).
    pub event_id: Option<EventID>,
    pub comm: Option<Vec<u8>>,
    pub exe: Option<Vec<u8>>,
    #[cfg(feature = "procfs")]
    pub container_info: Option<ContainerInfo>,
}

// This is a lossy serializer that is intended to be used for debugging only.
impl Serialize for Process {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(7))?;
        map.serialize_entry("launch_time", &self.launch_time)?;
        map.serialize_entry("ppid", &self.ppid)?;
        map.serialize_entry(
            "labels",
            &self
                .labels
                .iter()
                .map(|v| String::from_utf8_lossy(v))
                .collect::<Vec<_>>(),
        )?;
        map.serialize_entry("event_id", &self.event_id)?;
        map.serialize_entry(
            "comm",
            &self
                .comm
                .clone()
                .map(|v| String::from_utf8_lossy(&v).to_string()),
        )?;
        map.serialize_entry(
            "exe",
            &self
                .exe
                .clone()
                .map(|v| String::from_utf8_lossy(&v).to_string()),
        )?;
        map.end()
    }
}

#[cfg(feature = "procfs")]
impl From<procfs::ProcPidInfo> for Process {
    fn from(p: procfs::ProcPidInfo) -> Self {
        Self {
            launch_time: p.starttime,
            ppid: p.ppid,
            labels: HashSet::new(),
            event_id: None,
            comm: p.comm,
            exe: p.exe,
            container_info: p.container_id.map(|id| ContainerInfo { id }),
        }
    }
}

impl Process {
    /// Generate a shadow process table entry from /proc/$PID for a given PID
    #[cfg(feature = "procfs")]
    pub fn parse_proc(pid: u32) -> Result<Process, Box<dyn Error>> {
        procfs::parse_proc_pid(pid).map(|p| p.into())
    }

    /// Use a processed EXECVE event to generate a shadow process table entry
    pub fn parse_execve(id: &EventID, rsyscall: &Record) -> Result<(u32, Process), Box<dyn Error>> {
        let mut p = Process {
            launch_time: id.timestamp,
            ..Process::default()
        };
        let pid: u32;
        if let Some(v) = rsyscall.get(b"pid") {
            match v.value {
                Value::Number(Number::Dec(n)) => pid = *n as u32,
                _ => return Err("pid field is not numeric".into()),
            }
        } else {
            return Err("pid field not found".into());
        }
        if let Some(v) = rsyscall.get(b"ppid") {
            match v.value {
                Value::Number(Number::Dec(n)) => p.ppid = *n as u32,
                _ => return Err("ppid field is not numeric".into()),
            }
        } else {
            return Err("ppid field not found".into());
        }
        Ok((pid, p))
    }
}

/// Shadow process table
///
/// This process table replica can be fed with EXECVE-based events or
/// from /proc entries.
#[derive(Debug, Default, Serialize)]
pub struct ProcTable {
    pub processes: BTreeMap<u32, Process>,
}

impl ProcTable {
    /// Constructs process table from /proc entries
    ///
    /// If label_exe and propagate_labels are supplied, Process labels
    /// based on executable are applied and propagated to children.
    pub fn from_proc(
        label_exe: Option<&LabelMatcher>,
        propagate_labels: &HashSet<Vec<u8>>,
    ) -> Result<ProcTable, Box<dyn Error>> {
        let mut pt = ProcTable {
            processes: BTreeMap::new(),
        };

        #[cfg(feature = "procfs")]
        for pid in procfs::get_pids()? {
            // /proc/<pid> access is racy. Ignore errors here.
            if let Ok(mut proc) = Process::parse_proc(pid) {
                if let (Some(label_exe), Some(exe)) = (label_exe, &proc.exe) {
                    proc.labels
                        .extend(label_exe.matches(exe).iter().map(|v| Vec::from(*v)));
                }
                pt.processes.insert(pid, proc);
            }
        }

        if label_exe.is_some() {
            // Collect propagated labels from parent processes
            for pid in pt.processes.keys().cloned().collect::<Vec<_>>() {
                let mut collect = BTreeSet::new();
                let mut ppid = pid;
                for _ in 1..64 {
                    if let Some(proc) = pt.get_process(ppid) {
                        collect.extend(proc.labels.intersection(propagate_labels).cloned());
                        ppid = proc.ppid;
                        if ppid <= 1 {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                if let Some(proc) = pt.processes.get_mut(&pid) {
                    proc.labels.extend(collect);
                }
            }
        }

        Ok(pt)
    }

    /// Adds a Process to the process table
    pub fn add_process(
        &mut self,
        pid: u32,
        ppid: u32,
        id: EventID,
        comm: Option<Vec<u8>>,
        exe: Option<Vec<u8>>,
    ) {
        let labels = HashSet::new();
        let launch_time = id.timestamp;
        let event_id = Some(id);
        #[cfg(feature = "procfs")]
        let container_info = ContainerInfo::parse_proc(pid)
            .ok()
            .or_else(|| self.get_process(ppid)?.container_info);

        self.processes.insert(
            pid,
            Process {
                launch_time,
                ppid,
                labels,
                event_id,
                comm,
                exe,
                #[cfg(feature = "procfs")]
                container_info,
            },
        );
    }

    /// Retrieves a process by pid. If the process is not found in the
    /// shadow process table, an attempt is made to fetch the
    /// information from /proc.
    pub fn get_process(&mut self, pid: u32) -> Option<Process> {
        if let Some(p) = self.processes.get(&pid) {
            return Some(p.clone());
        }
        #[cfg(feature = "procfs")]
        if let Ok(p) = Process::parse_proc(pid) {
            self.processes.insert(pid, p.clone());
            return Some(p);
        }

        None
    }

    /// Removes a process from the table
    #[allow(dead_code)]
    pub fn remove_process(&mut self, pid: u32) {
        self.processes.remove(&pid);
    }

    /// Remove processes that are no longer running and that were not
    /// parents of currently running processes.
    ///
    /// It should be possible to run this every few seconds without
    /// incurring load.
    pub fn expire(&mut self) {
        // Expire is a no-op if parsing /proc is not enabled!
        #[cfg(feature = "procfs")]
        {
            // initialize prune list with all known processes
            let mut prune: HashSet<u32> = self.processes.keys().cloned().collect();
            let live_processes = match procfs::get_pids() {
                Ok(p) => p,
                Err(_) => return,
            };
            // remove from prune list all live processes and their
            // parents, excluding pid1
            for seed_pid in live_processes {
                let mut pid = seed_pid;
                while let Some(proc) = self.processes.get(&pid) {
                    if pid <= 1 || !prune.remove(&pid) {
                        break;
                    }
                    pid = proc.ppid;
                }
            }
            prune.iter().for_each(|pid| {
                self.processes.remove(pid);
            });
        }
    }

    pub fn add_label(&mut self, pid: u32, label: &[u8]) {
        if let Some(p) = self.processes.get_mut(&pid) {
            p.labels.insert(label.into());
        }
    }

    pub fn remove_label(&mut self, pid: u32, label: &[u8]) {
        if let Some(p) = self.processes.get_mut(&pid) {
            p.labels.remove(label);
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
}
