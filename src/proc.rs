use std::boxed::Box;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryInto;
use std::error::Error;
use std::fs::{read, read_dir, read_link};
use std::io::{BufRead, BufReader};
use std::iter::Iterator;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::str::FromStr;
use std::vec::Vec;

use lazy_static::lazy_static;
use nix::sys::time::TimeSpec;
use nix::time::{clock_gettime, ClockId};
use nix::unistd::{sysconf, SysconfVar};

use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use crate::label_matcher::LabelMatcher;
use crate::types::{EventID, Number, Record, Value};

lazy_static! {
    /// kernel clock ticks per second
    static ref CLK_TCK: u64
        = sysconf(SysconfVar::CLK_TCK).unwrap().unwrap() as u64;
}

#[derive(Clone, Debug, Default)]
pub struct ContainerInfo {
    pub id: Vec<u8>,
}

fn extract_sha256(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 64 {
        None
    } else if buf[buf.len() - 64..].iter().all(u8::is_ascii_hexdigit) {
        Some(&buf[buf.len() - 64..])
    } else if buf[..64].iter().all(u8::is_ascii_hexdigit) {
        Some(&buf[..64])
    } else {
        None
    }
}

fn parse_proc_pid_cgroup<R>(r: &mut R) -> Result<ContainerInfo, Box<dyn Error>>
where
    R: BufRead,
{
    for line in r.split(b'\n') {
        if line.is_err() {
            continue;
        }
        let line = line.unwrap();
        let dir = line.split(|&c| c == b':').nth(2);
        if dir.is_none() {
            continue;
        }
        for fragment in dir.unwrap().split(|&c| c == b'/') {
            let fragment = if fragment.ends_with(&b".scope"[..]) {
                &fragment[..fragment.len() - 6]
            } else {
                fragment
            };
            match extract_sha256(fragment) {
                None => continue,
                Some(id) => return Ok(ContainerInfo { id: Vec::from(id) }),
            }
        }
    }
    Err("no sha256 sum found".into())
}

impl ContainerInfo {
    fn parse_proc(pid: u32) -> Result<ContainerInfo, Box<dyn Error>> {
        let buf = read(format!("/proc/{}/cgroup", pid))?;
        let mut r = BufReader::new(&*buf);
        parse_proc_pid_cgroup(&mut r)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Process {
    /// Unix timestamp with millisecond precision
    pub launch_time: u64,
    /// parent process id
    pub ppid: u32,
    /// command line
    pub argv: Vec<Vec<u8>>,
    pub labels: HashSet<Vec<u8>>,
    /// Event ID containing the event spawning this process entry
    /// (should be EXECVE).
    pub event_id: Option<EventID>,
    pub comm: Option<Vec<u8>>,
    pub exe: Option<Vec<u8>>,
    pub container_info: Option<ContainerInfo>,
}

// This is a lossy serializer that is intended to be used for debugging only.
impl Serialize for Process {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(7))?;
        map.serialize_entry("launch_time", &self.launch_time)?;
        map.serialize_entry("ppid", &self.ppid)?;
        map.serialize_entry(
            "argv",
            &self
                .argv
                .iter()
                .map(|v| String::from_utf8_lossy(v))
                .collect::<Vec<_>>(),
        )?;
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

impl Process {
    /// Generate a shadow process table entry from /proc/$PID for a given PID
    #[allow(dead_code)]
    pub fn parse_proc(pid: u32) -> Result<Process, Box<dyn Error>> {
        let argv = read(format!("/proc/{}/cmdline", pid))
            .map_err(|e| format!("read /proc/{}/cmdline: {}", pid, e))?
            .split(|c| *c == 0)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_owned())
            .collect::<Vec<_>>();

        let buf = read(format!("/proc/{}/stat", pid))
            .map_err(|e| format!("read /proc/{}/stat: {}", pid, e))?;
        // comm may contain whitespace and ")", skip over it.
        let comm_end = buf
            .iter()
            .enumerate()
            .rfind(|(_, c)| **c == b')')
            .ok_or("end of 'cmd' field not found")?
            .0;
        let stat = &buf[comm_end + 2..]
            .split(|c| *c == b' ')
            .collect::<Vec<_>>();

        let event_id = None;
        let comm = read(format!("/proc/{}/comm", pid))
            .map(|mut s| {
                s.truncate(s.len() - 1);
                s
            })
            .ok();

        let exe = read_link(format!("/proc/{}/exe", pid))
            .map(|p| Vec::from(p.as_os_str().as_bytes()))
            .ok();

        // see proc(5), /proc/[pid]/stat (4)
        let ppid = u32::from_str(String::from_utf8_lossy(stat[1]).as_ref())?;
        // see proc(5), /proc/[pid]/stat (22)
        let starttime = u64::from_str(String::from_utf8_lossy(stat[19]).as_ref())?;

        // Use the boottime-based clock to calculate process start
        // time, convert to Unix-epoch-based-time.
        let proc_boottime = TimeSpec::from(libc::timespec {
            tv_sec: (starttime / *CLK_TCK) as i64,
            tv_nsec: ((starttime % *CLK_TCK) * (1_000_000_000 / *CLK_TCK)) as i64,
        });
        let proc_age = clock_gettime(ClockId::CLOCK_BOOTTIME)
            .map_err(|e| format!("clock_gettime: {}", e))?
            - proc_boottime;
        let launch_time = {
            let lt = clock_gettime(ClockId::CLOCK_REALTIME)
                .map_err(|e| format!("clock_gettime: {}", e))?
                - proc_age;
            (lt.tv_sec() * 1000 + lt.tv_nsec() / 1_000_000) as u64
        };

        let container_info = ContainerInfo::parse_proc(pid).ok();

        let labels = HashSet::new();
        Ok(Process {
            launch_time,
            ppid,
            argv,
            labels,
            event_id,
            comm,
            exe,
            container_info,
        })
    }

    /// Use a processed EXECVE event to generate a shadow process table entry
    #[allow(dead_code)]
    pub fn parse_execve(
        id: &EventID,
        rsyscall: &Record,
        rexecve: &Record,
    ) -> Result<(u32, Process), Box<dyn Error>> {
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
        if let Some(v) = rexecve.get(b"ARGV") {
            p.argv = v.try_into()?;
        } else if let Some(v) = rexecve.get(b"ARGV_STR") {
            p.argv = v.try_into()?;
        } else {
            return Err("ARGV field not found".into());
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
        for entry in read_dir("/proc")
            .map_err(|e| format!("read_dir: /proc: {}", e))?
            .flatten()
        {
            if let Ok(pid) = u32::from_str(entry.file_name().to_string_lossy().as_ref()) {
                // /proc/<pid> access is racy. Ignore errors here.
                if let Ok(mut proc) = Process::parse_proc(pid) {
                    if let (Some(label_exe), Some(exe)) = (label_exe, &proc.exe) {
                        proc.labels
                            .extend(label_exe.matches(exe).iter().map(|v| Vec::from(*v)));
                    }
                    pt.processes.insert(pid, proc);
                }
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
        argv: Vec<Vec<u8>>,
    ) {
        let labels = HashSet::new();
        let launch_time = id.timestamp;
        let event_id = Some(id);
        let container_info = ContainerInfo::parse_proc(pid)
            .ok()
            .or_else(|| self.get_process(ppid)?.container_info);

        self.processes.insert(
            pid,
            Process {
                launch_time,
                ppid,
                argv,
                labels,
                event_id,
                comm,
                exe,
                container_info,
            },
        );
    }

    /// Retrieves a process by pid. If the process is not found in the
    /// shadow process table, an attempt is made to fetch the
    /// information from /proc.
    pub fn get_process(&mut self, pid: u32) -> Option<Process> {
        if let Some(p) = self.processes.get(&pid) {
            Some(p.clone())
        } else {
            match Process::parse_proc(pid) {
                Ok(p) => {
                    self.processes.insert(pid, p.clone());
                    Some(p)
                }
                Err(_) => None,
            }
        }
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
        let mut prune: HashSet<u32> = self.processes.keys().cloned().collect();
        for pid in self.processes.keys() {
            if Path::new(&format!("/proc/{}", pid)).is_dir() {
                let mut pid = *pid;
                while let Some(proc) = self.processes.get(&pid) {
                    if pid <= 1 || !prune.remove(&pid) {
                        break;
                    }
                    pid = proc.ppid;
                }
            }
        }
        prune.iter().for_each(|pid| {
            self.processes.remove(pid);
        });
    }

    pub fn add_label(&mut self, pid: u32, label: &[u8]) {
        if let Some(p) = self.processes.get_mut(&pid) {
            p.labels.insert(label.into());
        }
    }
}

type Environment = Vec<(Vec<u8>, Vec<u8>)>;

/// Returns environment for a given process
pub fn get_environ<F>(pid: u32, pred: F) -> Result<Environment, Box<dyn Error>>
where
    F: Fn(&[u8]) -> bool,
{
    let buf = read(format!("/proc/{}/environ", pid))?;
    let mut res = Vec::new();
    for f in buf.split(|c| *c == 0) {
        let mut kv = f.splitn(2, |c| *c == b'=');
        let k = kv.next().unwrap();
        if pred(k) {
            let v = kv.next().unwrap_or(b"");
            res.push((k.to_owned(), v.to_owned()));
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    #[test]
    fn show_processes() -> Result<(), Box<dyn Error>> {
        let pt = ProcTable::from_proc(None, &HashSet::new())?;
        for p in pt.processes {
            println!("{:?}", &p);
        }
        Ok(())
    }

    #[test]
    fn parse_cgroup() -> Result<(), Box<dyn Error>> {
        for line in &[
            &b"0::/system.slice/docker-47335b04ebb4aefdc353dda62ddd38e5e1e00fc1372f0c8d0138417f0ccb9e6c.scope\n"[..],
            &b"0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-974a75c8cf45648fcc6e718ba92ee1f2034463674f0d5b0c50f5cab041a4cbd6.scope/container\n"[..]
        ]
        {
            let mut r = BufReader::new(*line);
            parse_proc_pid_cgroup(&mut r)
                .map_err(|e| Box::<dyn Error>::from(
                    format!("{}: {}", String::from_utf8_lossy(line), e)))?;
        }
        Ok(())
    }
}
