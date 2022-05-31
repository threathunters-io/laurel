use std::error::Error;
use std::boxed::Box;
use std::fs::{read,read_dir,read_link};
use std::str::FromStr;
use std::convert::TryInto;
use std::iter::Iterator;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::vec::Vec;
use std::collections::{BTreeMap,HashSet};

use lazy_static::lazy_static;
use nix::unistd::{sysconf,SysconfVar};
use nix::time::{clock_gettime,ClockId};
use nix::sys::time::TimeSpec;

use serde::{Serialize,Serializer};
use serde::ser::SerializeMap;

use crate::types::{EventID,Record,Value,Number};

lazy_static! {
    /// kernel clock ticks per second
    static ref CLK_TCK: u64
        = sysconf(SysconfVar::CLK_TCK).unwrap().unwrap() as u64;
}

#[derive(Clone,Debug,Default)]
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
}

// This is a lossy serializer that is intended to be used for debugging only.
impl Serialize for Process {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(7))?;
        map.serialize_entry("launch_time", &self.launch_time)?;
        map.serialize_entry("ppid", &self.ppid)?;
        map.serialize_entry(
            "argv",
            &self.argv.iter().map(|v|String::from_utf8_lossy(v)).collect::<Vec<_>>())?;
        map.serialize_entry(
            "labels",
            &self.labels.iter().map(|v|String::from_utf8_lossy(v)).collect::<Vec<_>>())?;
        map.serialize_entry("event_id", &self.event_id)?;
        map.serialize_entry(
            "comm",
            &self.comm.clone().map(|v|String::from_utf8_lossy(&v).to_string()))?;
        map.serialize_entry(
            "exe",
            &self.exe.clone().map(|v|String::from_utf8_lossy(&v).to_string()))?;
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
        let comm_end = buf.iter().enumerate()
            .rfind(|(_,c)| **c == b')')
            .ok_or("end of 'cmd' field not found")?.0;
        let stat = &buf[comm_end+2..]
            .split(|c| *c == b' ')
            .collect::<Vec<_>>();

        let event_id = None;
        let comm = read(format!("/proc/{}/comm", pid))
            .map(|mut s| { s.truncate(s.len()-1); s })
            .ok();

        let exe = read_link(format!("/proc/{}/exe", pid))
            .map(|p| Vec::from(p.as_os_str().as_bytes()) )
            .ok();

        // see proc(5), /proc/[pid]/stat (4)
        let ppid = u32::from_str(String::from_utf8_lossy(stat[1]).as_ref())?;
        // see proc(5), /proc/[pid]/stat (22)
        let starttime = u64::from_str(String::from_utf8_lossy(stat[19]).as_ref())?;

        // Use the boottime-based clock to calculate process start
        // time, convert to Unix-epoch-based-time.
        let proc_boottime = TimeSpec::from(libc::timespec{
            tv_sec: (starttime / *CLK_TCK) as i64,
            tv_nsec: ((starttime % *CLK_TCK) * (1_000_000_000 / *CLK_TCK)) as i64,
        });
        let proc_age = clock_gettime(ClockId::CLOCK_BOOTTIME)
            .map_err(|e| format!("clock_gettime: {}", e))? - proc_boottime;
        let launch_time = {
            let lt = clock_gettime(ClockId::CLOCK_REALTIME)
                .map_err(|e| format!("clock_gettime: {}", e))? - proc_age;
            (lt.tv_sec() * 1000 + lt.tv_nsec() / 1_000_000) as u64
        };

        let labels = HashSet::new();
        Ok(Process{launch_time, ppid, argv, labels, event_id, comm, exe})
    }

    /// Use a processed EXECVE event to generate a shadow process table entry
    #[allow(dead_code)]
    pub fn parse_execve(id: &EventID, rsyscall: &Record, rexecve: &Record) -> Result<(u32, Process), Box<dyn Error>> {
        let mut p = Process { launch_time: id.timestamp, ..Process::default() };
        let pid: u32;
        if let Some(v) = rsyscall.get(b"pid") {
            match v.value {
                Value::Number(Number::Dec(n)) => pid=*n as u32,
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
#[derive(Debug,Default,Serialize)]
pub struct ProcTable {
    processes: BTreeMap<u32,Process>,
}

impl ProcTable {
    /// Constructs process table from /proc entries
    pub fn from_proc() -> Result<ProcTable,Box<dyn Error>> {
        let mut pt = ProcTable { processes: BTreeMap::new() };
        for entry in read_dir("/proc")
            .map_err(|e| format!("read_dir: /proc: {}", e))?
        {
            if let Ok(entry) = entry {
                if let Ok(pid) = u32::from_str(entry.file_name()
                                               .to_string_lossy()
                                               .as_ref())
                {
                    // /proc/<pid> access is racy. Ignore errors here.
                    if let Ok(proc) = Process::parse_proc(pid) {
                        pt.processes.insert(pid, proc);
                    }
                }
            }
        }
        Ok(pt)
    }

    /// Adds a Process to the process table
    pub fn add_process(&mut self, pid: u32, ppid: u32, id: EventID, comm: Option<Vec<u8>>, exe: Option<Vec<u8>>, argv: Vec<Vec<u8>>) {
        let labels = HashSet::new();
        let launch_time = id.timestamp;
        let event_id = Some(id);
        self.processes.insert(
            pid,
            Process{launch_time, ppid, argv, labels, event_id, comm, exe});
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
                Err(_) => None
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
                        break
                    }
                    pid = proc.ppid;
                }
            }
        }
        prune.iter().for_each(|pid| { self.processes.remove(&pid); } );
    }

    pub fn add_label(&mut self, pid: u32, label: &[u8]) {
        if let Some(p) = self.processes.get_mut(&pid) {
            p.labels.insert(label.into());
        }
    }
}

/// Returns environment for a given process
pub fn get_environ<F: Fn(&[u8]) -> bool>(pid: u32, pred: F) -> Result<Vec<(Vec<u8>,Vec<u8>)>, Box<dyn Error>> {
    let buf = read(format!("/proc/{}/environ", pid))?;
    let mut res = Vec::new();
    for f in buf.split(|c| *c == 0) {
        let mut kv = f.splitn(2, |c| *c == b'=');
        let k = kv.next().unwrap();
        if pred(k) {
            let v = kv.next().or(Some(b"")).unwrap();
            res.push((k.to_owned(), v.to_owned()));
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn show_processes() -> Result<(),Box<dyn Error>> {
        let pt = ProcTable::from_proc()?;
        for p in pt.processes {
            println!("{:?}", &p);
        }
        Ok(())
    }
}
