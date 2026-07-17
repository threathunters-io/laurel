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

use super::*;

lazy_static! {
    /// kernel clock ticks per second
    pub static ref CLK_TCK: u64
        = sysconf(SysconfVar::CLK_TCK).unwrap().unwrap() as u64;
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
    let proc_boottime = TimeSpec::new(
        (starttime / *CLK_TCK) as _,
        ((starttime % *CLK_TCK) * (1_000_000_000 / *CLK_TCK)) as _,
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_self() {
        let pid = std::process::id();
        let proc = parse_proc_pid(pid).unwrap_or_else(|e| panic!("parse entry for {pid}: {e}"));
        println!("{proc:?}");
    }
}
