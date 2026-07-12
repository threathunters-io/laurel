use std::ffi::OsStr;
use std::fs::Metadata;
use std::fs::{read_dir, read_link, File};
use std::io::{BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bstr::ByteSlice;

use lazy_static::lazy_static;
use nix::sys::time::TimeSpec;
use nix::time::{clock_gettime, ClockId};
use nix::unistd::{sysconf, SysconfVar};

use thiserror::Error;

lazy_static! {
    /// kernel clock ticks per second
    pub static ref CLK_TCK: u64
        = sysconf(SysconfVar::CLK_TCK).unwrap().unwrap() as u64;
}

#[derive(Debug, Error)]
pub enum ProcFSError {
    #[error("can't read /proc/{pid}/{obj}: {err}")]
    PidFile {
        pid: u32,
        obj: &'static str,
        err: std::io::Error,
    },
    #[error("can't enumerate processes: {0}")]
    Enum(std::io::Error),
    #[error("can't get field {0}")]
    Field(&'static str),
    #[error("truncated line")]
    Truncated,
    #[error("{0}: {1}")]
    Errno(&'static str, nix::errno::Errno),
}

pub fn slurp_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, std::io::Error> {
    let f = File::open(path)?;
    let mut r = BufReader::with_capacity(1 << 16, f);
    std::io::BufRead::fill_buf(&mut r)?;
    let mut buf = Vec::with_capacity(8192);
    r.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Read contents of file, return buffer.
fn slurp_pid_obj(pid: u32, obj: &'static str) -> Result<Vec<u8>, ProcFSError> {
    let path = format!("/proc/{pid}/{obj}");
    slurp_file(path).map_err(|err| ProcFSError::PidFile { pid, obj, err })
}

pub fn open_pid_exe_meta(pid: u32) -> std::io::Result<File> {
    std::fs::File::open(format!("/proc/{pid}/exe"))
}

pub fn get_pid_exe_link(pid: u32) -> std::io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
}

/// Returns contents of /proc/pid/environ.
///
/// Contents are prefixed with a null byte as required by
/// `env_matcher::EnvMatcher`.
pub fn read_environ_block(pid: u32) -> Result<Vec<u8>, ProcFSError> {
    let obj = "environ";
    let f = BufReader::with_capacity(
        1 << 16,
        File::open(format!("/proc/{pid}/environ")).map_err(|err| ProcFSError::PidFile {
            pid,
            obj,
            err,
        })?,
    );
    let mut combined = [0u8].chain(f);
    let mut res = vec![];
    combined
        .read_to_end(&mut res)
        .map_err(|err| ProcFSError::PidFile { pid, obj, err })?;
    Ok(res)
}

/// Returns all currently valid process IDs
pub fn get_pids() -> Result<impl Iterator<Item = u32>, ProcFSError> {
    Ok(read_dir("/proc")
        .map_err(ProcFSError::Enum)?
        .flatten()
        .filter_map(|e| u32::from_str(e.file_name().to_string_lossy().as_ref()).ok()))
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

/// Reads file contents for a path from a process' perspective
///
/// Uses /proc/{pid}/root/ to access the file through the process's
/// filesystem namespace, which is necessary for containerized processes.
pub fn pid_path_read(pid: u32, path: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    if path.is_empty() || path[0] != b'/' {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    let mut proc_path = Vec::with_capacity(20 + path.len());
    write!(proc_path, "/proc/{pid}/root").unwrap();
    proc_path.extend(path);
    std::fs::read(OsStr::from_bytes(&proc_path))
}

pub struct ProcStat<'a> {
    pub pid: u32,
    pub ppid: u32,
    pub comm: &'a [u8],
    pub starttime: u64,
    pub utime: u64,
    pub stime: u64,
}

pub fn parse_proc_pid_stat(buf: &[u8]) -> Result<ProcStat<'_>, ProcFSError> {
    let (stat_pid, buf) = buf.split_once_str(" ").ok_or(ProcFSError::Field("pid"))?;
    // comm is enclosed with parentheses, but it may contain
    // whitespace and ")", so we go and find the right-most ")".
    let buf = buf.strip_prefix(b"(").ok_or(ProcFSError::Field("comm"))?;
    let comm_end = buf.rfind_byte(b')').ok_or(ProcFSError::Field("comm"))?;

    let mut stat: Vec<&[u8]> = Vec::with_capacity(22);
    stat.extend([stat_pid, &buf[..comm_end]]);
    stat.extend(buf[comm_end + 2..].split_str(" ").take(20));
    if stat.len() < 22 {
        return Err(ProcFSError::Truncated);
    }

    let pid = u32::from_str(&stat[0].to_str_lossy()).map_err(|_| ProcFSError::Field("pid"))?;
    let comm = stat[1];
    let ppid = u32::from_str(&stat[3].to_str_lossy()).map_err(|_| ProcFSError::Field("ppid"))?;
    let starttime =
        u64::from_str(&stat[21].to_str_lossy()).map_err(|_| ProcFSError::Field("starttime"))?;
    let utime = u64::from_str(&stat[13].to_str_lossy()).map_err(|_| ProcFSError::Field("utime"))?;
    let stime = u64::from_str(&stat[14].to_str_lossy()).map_err(|_| ProcFSError::Field("stime"))?;

    Ok(ProcStat {
        pid,
        ppid,
        comm,
        starttime,
        utime,
        stime,
    })
}

#[derive(Debug)]
pub(crate) struct ProcPidInfo {
    /// /proc/<pid>/stat field 1
    pub pid: u32,
    /// /proc/<pid>/stat field 4
    pub ppid: u32,
    /// /proc/<pid>/stat field 22, converted to milliseconds since epoch
    pub starttime: u64,
    /// /proc/<pid>/stat field 2
    pub comm: Vec<u8>,
    /// /proc/pid/exe
    pub exe: Option<Vec<u8>>,
    /// from /proc/$PID/cgroup
    pub cgroup: Option<Vec<u8>>,
    /// derived from NSpid in /proc/$PID/status
    pub is_pid1: bool,
}

/// Parses information from /proc entry corresponding to process pid
pub(crate) fn parse_proc_pid(pid: u32) -> Result<ProcPidInfo, ProcFSError> {
    let buf = slurp_pid_obj(pid, "stat")?;
    let ProcStat {
        pid,
        ppid,
        comm,
        starttime,
        ..
    } = parse_proc_pid_stat(&buf)?;

    let is_pid1 = is_pid1(pid);
    let exe = read_link(format!("/proc/{pid}/exe"))
        .map(|p| Vec::from(p.as_os_str().as_bytes()))
        .ok();

    // Use the boottime-based clock to calculate process start
    // time, convert to Unix-epoch-based-time.
    let proc_boottime = TimeSpec::from(libc::timespec {
        tv_sec: (starttime / *CLK_TCK) as _,
        tv_nsec: ((starttime % *CLK_TCK) * (1_000_000_000 / *CLK_TCK)) as _,
    });
    let proc_age = clock_gettime(ClockId::CLOCK_BOOTTIME)
        .map_err(|e| ProcFSError::Errno("clock_gettime(CLOCK_BOOTTIME)", e))?
        - proc_boottime;
    let starttime = {
        let lt = clock_gettime(ClockId::CLOCK_REALTIME)
            .map_err(|e| ProcFSError::Errno("clock_gettime(CLOCK_REALTIME)", e))?
            - proc_age;
        (lt.tv_sec() as u64) * 1000 + (lt.tv_nsec() as u64) / 1_000_000
    };

    let cgroup = parse_proc_pid_cgroup(pid)?;

    Ok(ProcPidInfo {
        pid,
        ppid,
        starttime,
        comm: comm.to_vec(),
        exe,
        cgroup,
        is_pid1,
    })
}

pub fn is_pid1(pid: u32) -> bool {
    let Ok(buf) = slurp_pid_obj(pid, "status") else {
        return false;
    };
    buf.lines()
        .filter_map(|line| line.strip_prefix(b"NSpid:"))
        .any(|value| value.trim_end().ends_with(b"\t1"))
}

/// Parses path (third field) /proc/pid/cgroup
pub(crate) fn parse_proc_pid_cgroup(pid: u32) -> Result<Option<Vec<u8>>, ProcFSError> {
    parse_cgroup_buf(&slurp_pid_obj(pid, "cgroup")?)
}

fn parse_cgroup_buf(buf: &[u8]) -> Result<Option<Vec<u8>>, ProcFSError> {
    Ok(buf
        .lines()
        .find_map(|l| l.split_str(":").nth(2).map(Vec::from)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_self() {
        let pid = std::process::id();
        let proc = parse_proc_pid(pid).unwrap_or_else(|e| panic!("parse entry for {pid}: {e}"));
        println!("{proc:?}");
    }

    #[test]
    fn parse_stat() {
        let ProcStat { pid, ppid, comm, starttime, utime, stime } = parse_proc_pid_stat(
            br#"925028 (emacs) R 3057 925028 925028 0 -1 4194304 1131624 1579849 3 604 183731 6453 20699 2693 20 0 5 0 22398221 3922935808 191059 18446744073709551615 187652449566720 187652452795816 281474372905056 0 0 0 0 67112960 1535209215 0 0 0 17 2 0 0 0 0 0 187652452866344 187652460555720 187652461281280 281474372910201 281474372910228 281474372910228 281474372911081 0
"#).expect("parse error");
        assert_eq!(pid, 925028);
        assert_eq!(ppid, 3057);
        assert_eq!(comm, "emacs".as_bytes());
        assert_eq!(starttime, 22398221);
        assert_eq!(utime, 183731);
        assert_eq!(stime, 6453);
    }
}
