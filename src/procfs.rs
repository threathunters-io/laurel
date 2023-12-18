use std::ffi::OsStr;
use std::fs::{read_dir, read_link, File, Metadata};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::str::FromStr;

use faster_hex::hex_decode;
use lazy_static::lazy_static;
use nix::sys::time::TimeSpec;
use nix::time::{clock_gettime, ClockId};
use nix::unistd::{sysconf, SysconfVar};

use thiserror::Error;

lazy_static! {
    /// kernel clock ticks per second
    static ref CLK_TCK: u64
        = sysconf(SysconfVar::CLK_TCK).unwrap().unwrap() as u64;
}

#[derive(Debug, Error)]
pub enum ProcFSError {
    #[error("can't read /proc/{pid}/(obj): {err}")]
    PidFile {
        pid: u32,
        obj: &'static str,
        err: std::io::Error,
    },
    #[error("can't enumerate processes: {0}")]
    Enum(std::io::Error),
    #[error("can't get field {0}")]
    Field(&'static str),
    #[error("{0}: {1}")]
    Errno(&'static str, nix::errno::Errno),
}

fn slurp_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, std::io::Error> {
    let f = File::open(path)?;
    let mut r = BufReader::with_capacity(1 << 16, f);
    r.fill_buf()?;
    let mut buf = Vec::with_capacity(8192);
    r.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Read contents of file, return buffer.
fn slurp_pid_obj(pid: u32, obj: &'static str) -> Result<Vec<u8>, ProcFSError> {
    let path = format!("/proc/{pid}/{obj}");
    slurp_file(path).map_err(|err| ProcFSError::PidFile { pid, obj, err })
}

type Environment = Vec<(Vec<u8>, Vec<u8>)>;

/// Returns set of environment variables that match pred for a given process
pub fn get_environ<F>(pid: u32, pred: F) -> Result<Environment, ProcFSError>
where
    F: Fn(&[u8]) -> bool,
{
    let buf = slurp_pid_obj(pid, "environ")?;
    let mut res = Vec::new();

    for e in buf.split(|c| *c == 0) {
        let mut kv = e.splitn(2, |c| *c == b'=');
        let k = kv.next().unwrap_or_default();
        if pred(k) {
            let v = kv.next().unwrap_or_default();
            res.push((k.to_owned(), v.to_owned()));
        }
    }
    Ok(res)
}

/// Returns all currently valid process IDs
pub fn get_pids() -> Result<Vec<u32>, ProcFSError> {
    Ok(read_dir("/proc")
        .map_err(ProcFSError::Enum)?
        .flatten()
        .filter_map(|e| u32::from_str(e.file_name().to_string_lossy().as_ref()).ok())
        .collect::<Vec<u32>>())
}

/// Returns file metadata for a path from a process' perspective
pub fn pid_path_metadata(pid: u32, path: &[u8]) -> Result<Metadata, std::io::Error> {
    if path.is_empty() || path[0] != b'/' {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    let mut proc_path = Vec::with_capacity(20 + path.len());
    // unwrap safety: write will not produce an IO error
    write!(proc_path, "/proc/{pid}/root").unwrap();
    proc_path.extend(path);
    std::fs::metadata(OsStr::from_bytes(&proc_path))
}

#[derive(Debug)]
pub(crate) struct ProcPidInfo {
    /// /proc/<pid>/stat field 1
    pub pid: u32,
    /// /proc/<pid>/stat field 4
    pub ppid: u32,
    /// /proc/<pid>/stat field 22, converted to milliseconds since epoch
    pub starttime: u64,
    /// /proc/pid/comm
    pub comm: Option<Vec<u8>>,
    /// /proc/pid/exe
    pub exe: Option<Vec<u8>>,
    /// sha256 from /proc/pid/cgroup
    pub container_id: Option<Vec<u8>>,
}

/// Parses information from /proc entry corresponding to process pid
pub(crate) fn parse_proc_pid(pid: u32) -> Result<ProcPidInfo, ProcFSError> {
    let buf = slurp_pid_obj(pid, "stat")?;
    // comm may contain whitespace and ")", skip over it.
    let pid_end = buf
        .iter()
        .enumerate()
        .find(|(_, c)| **c == b' ')
        .ok_or(ProcFSError::Field("pid"))?
        .0;
    let stat_pid = &buf[..pid_end];

    let comm_end = buf
        .iter()
        .enumerate()
        .rfind(|(_, c)| **c == b')')
        .ok_or(ProcFSError::Field("comm"))?
        .0;
    let stat = &buf[comm_end + 2..]
        .split(|c| *c == b' ')
        .collect::<Vec<_>>();

    let comm = slurp_pid_obj(pid, "comm")
        .map(|mut s| {
            s.truncate(s.len() - 1);
            s
        })
        .ok();

    let exe = read_link(format!("/proc/{}/exe", pid))
        .map(|p| Vec::from(p.as_os_str().as_bytes()))
        .ok();

    let pid = u32::from_str(String::from_utf8_lossy(stat_pid).as_ref())
        .map_err(|_| ProcFSError::Field("pid"))?;
    let ppid = u32::from_str(String::from_utf8_lossy(stat[1]).as_ref())
        .map_err(|_| ProcFSError::Field("ppid"))?;
    let starttime = u64::from_str(String::from_utf8_lossy(stat[19]).as_ref())
        .map_err(|_| ProcFSError::Field("starttime"))?;

    // Use the boottime-based clock to calculate process start
    // time, convert to Unix-epoch-based-time.
    let proc_boottime = TimeSpec::from(libc::timespec {
        tv_sec: (starttime / *CLK_TCK) as _,
        tv_nsec: ((starttime % *CLK_TCK) * (1_000_000_000 / *CLK_TCK)) as _,
    });
    #[cfg(not(target_os = "linux"))]
    let proc_age = TimeSpec::from(std::time::Duration::ZERO);
    #[cfg(target_os = "linux")]
    let proc_age = clock_gettime(ClockId::CLOCK_BOOTTIME)
        .map_err(|e| ProcFSError::Errno("clock_gettime(CLOCK_BOOTTIME)", e))?
        - proc_boottime;
    let starttime = {
        let lt = clock_gettime(ClockId::CLOCK_REALTIME)
            .map_err(|e| ProcFSError::Errno("clock_gettime(CLOCK_REALTIME)", e))?
            - proc_age;
        (lt.tv_sec() * 1000 + lt.tv_nsec() / 1_000_000) as u64
    };

    let container_id = parse_proc_pid_cgroup(pid)?;

    Ok(ProcPidInfo {
        pid,
        ppid,
        starttime,
        comm,
        exe,
        container_id,
    })
}

fn extract_sha256(buf: &[u8]) -> Option<Vec<u8>> {
    let mut dec = [0u8; 32];
    match buf.len() {
        n if n < 64 => None,
        _ if hex_decode(&buf[buf.len() - 64..], &mut dec).is_ok() => Some(Vec::from(dec)),
        _ if hex_decode(&buf[..64], &mut dec).is_ok() => Some(Vec::from(dec)),
        _ => None,
    }
}

/// Parses "container id" (some SHA256 sum) from /proc/pid/cgroup
pub(crate) fn parse_proc_pid_cgroup(pid: u32) -> Result<Option<Vec<u8>>, ProcFSError> {
    parse_cgroup_buf(&slurp_pid_obj(pid, "cgroup")?)
}

fn parse_cgroup_buf(buf: &[u8]) -> Result<Option<Vec<u8>>, ProcFSError> {
    for line in buf.split(|c| *c == b'\n') {
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
                Some(id) => return Ok(Some(id)),
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_self() {
        let pid = std::process::id();
        let proc = parse_proc_pid(pid).expect(&format!("parse entry for {pid}"));
        println!("{:?}", proc);
    }

    #[test]
    fn parse_cgroup() -> Result<(), Box<dyn std::error::Error>> {
        let testdata = br#"0::/system.slice/docker-47335b04ebb4aefdc353dda62ddd38e5e1e00fc1372f0c8d0138417f0ccb9e6c.scope
0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-974a75c8cf45648fcc6e718ba92ee1f2034463674f0d5b0c50f5cab041a4cbd6.scope/container
"#;
        {
            parse_cgroup_buf(testdata).map_err(|e| -> Box<dyn std::error::Error> {
                format!("{}: {}", String::from_utf8_lossy(testdata), e).into()
            })?;
        }
        Ok(())
    }
}
