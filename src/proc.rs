use std::ffi::{OsStr,OsString};
use std::os::unix::ffi::OsStrExt;
use std::error::Error;
use std::boxed::Box;
use std::fs::{read,read_dir};
use std::str::FromStr;
use std::convert::TryInto;
use std::iter::Iterator;
use std::path::Path;
use std::vec::Vec;
use std::collections::{BTreeMap,BTreeSet};

use lazy_static::lazy_static;
use nix::unistd::{sysconf,SysconfVar};
use nix::time::{clock_gettime,ClockId};
use nix::sys::time::TimeSpec;

use serde::{Serialize,Serializer};
use serde::ser::{SerializeStruct};

use crate::types::{EventID,Record,Value,Number};
use crate::quoted_string::ToQuotedString;

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
    pub ppid: u64,
    /// command line
    pub argv: Vec<OsString>
}

impl Serialize for Process {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let mut s = serializer.serialize_struct("Process", 3)?;
        let launch_time = self.launch_time as f64 / 1000.0;
        s.serialize_field("ARGV", &self.argv
                          .iter()
                          .map(|s|s.as_bytes().to_quoted_string())
                          .collect::<Vec<_>>())?;
        s.serialize_field("launch_time", &launch_time)?;
        s.serialize_field("ppid", &self.ppid)?;
        s.end()
    }
}

impl Process {
    /// Generate a shadow process table entry from /proc/$PID for a given PID
    #[allow(dead_code)]
    pub fn parse_proc(pid: u64) -> Result<Process, Box<dyn Error>> {
        let argv = read(format!("/proc/{}/cmdline", pid))
            .map_err(|e| format!("read /proc/{}/cmdline: {}", pid, e))?
            .split(|c| *c == 0)
            .filter(|s|!s.is_empty())
            .map(|s|OsStr::from_bytes(s).to_os_string())
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

        // see proc(5), /proc/[pid]/stat (4)
        let ppid = u64::from_str(String::from_utf8_lossy(stat[1]).as_ref())?;
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

        Ok(Process{launch_time, ppid, argv})
    }

    /// Use a processed EXECVE event to generate a shadow process table entry
    #[allow(dead_code)]
    pub fn parse_execve(id: &EventID, rsyscall: &Record, rexecve: &Record) -> Result<(u64, Process), Box<dyn Error>> {
        let mut p = Process { launch_time: id.timestamp, ..Process::default() };
        let pid: u64;
        if let Some(v) = rsyscall.get(b"pid") {
            match v.value {
                Value::Number(Number::Dec(n)) => pid=*n,
                _ => return Err("pid field is not numeric".into()),
            }
        } else {
            return Err("pid field not found".into());
        }
        if let Some(v) = rsyscall.get(b"ppid") {
            match v.value {
                Value::Number(Number::Dec(n)) => p.ppid = *n,
                _ => return Err("ppid field is not numeric".into()),
            }
        } else {
            return Err("ppid field not found".into());
        }
        match rexecve.get(b"ARGV") {
            Some(v) =>  {
                let l: Vec<Vec<u8>> = v.try_into()?;
                p.argv = l.iter()
                    .map(|elem| OsStr::from_bytes(&elem).into() )
                    .collect::<Vec<OsString>>();
            },
            _ => return Err("ARGV field not found".into()),
        }
        Ok((pid, p))
    }
}

/// Shadow process table
///
/// This process table replica can be fed with EXECVE-based events or
/// from /proc entries.
#[derive(Debug,Default)]
pub struct ProcTable {
    processes: BTreeMap<u64,Process>,
}

impl ProcTable {
    /// Constructs process table from /proc entries
    pub fn from_proc() -> Result<ProcTable,Box<dyn Error>> {
        let mut pt = ProcTable { processes: BTreeMap::new() };
        for entry in read_dir("/proc")
            .map_err(|e| format!("read_dir: /proc: {}", e))?
        {
            if let Ok(entry) = entry {
                if let Ok(pid) = u64::from_str(entry.file_name()
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

    /// Adds a process to the table based on a normalized EXECVE message
    pub fn add_execve(&mut self, id: &EventID, rsyscall: &Record, rexecve: &Record) -> Result<(u64, Process), Box<dyn Error>> {
        let (pid, process) = Process::parse_execve(id, rsyscall, rexecve)?;
        self.processes.insert(pid, process.clone());
        Ok((pid, process))
    }

    /// Retrieves a process by pid. If the process is not found in the
    /// shadow process table, an attempt is made to fetch the
    /// information from /proc.
    pub fn get_process(&mut self, pid: u64) -> Option<Process> {
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
    pub fn remove_process(&mut self, pid: u64) {
        self.processes.remove(&pid);
    }

    /// Remove processes that are no longer running and that were not
    /// parents of currently running processes.
    ///
    /// It should be possible to run this every few seconds without
    /// incurring load.
    pub fn expire(&mut self) {
        let mut prune: BTreeSet<u64> = self.processes.keys().cloned().collect();
        for pid in self.processes.keys() {
            if Path::new(&format!("/proc/{}", pid)).is_dir() {
                let mut pid = *pid;
                loop {
                    if let Some(proc) = self.processes.get(&pid) {
                        prune.remove(&pid);
                        if pid == 0 || pid == proc.ppid {
                            break
                        }
                        pid = proc.ppid;
                    } else {
                        break;
                    }
                }
            }
        }
        prune.iter().for_each(|pid| { self.processes.remove(&pid); } );
    }
}

/// Returns environment for a given process
pub fn get_environ(pid: u64) -> Result<Vec<(Vec<u8>,Vec<u8>)>, Box<dyn Error>> {
    Ok(read(format!("/proc/{}/environ", pid))?
       .split(|c| *c == 0)
       .map(|f| {
           let mut kv = f.splitn(2, |c| *c == b'=');
           (kv.next().unwrap().to_owned(), kv.next().or(Some(b"")).unwrap().to_owned())
       }).collect())
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
