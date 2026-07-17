use std::str::FromStr;

use bstr::ByteSlice;
use thiserror::Error;

#[cfg(not(test))]
mod io;
#[cfg(not(test))]
pub use io::*;

#[cfg(test)]
mod mock;
#[cfg(test)]
pub use mock::*;

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

#[allow(dead_code)]
fn parse_cgroup_buf(buf: &[u8]) -> Result<Option<Vec<u8>>, ProcFSError> {
    Ok(buf
        .lines()
        .find_map(|l| l.split_str(":").nth(2).map(Vec::from)))
}

#[cfg(test)]
mod tests {
    use super::*;
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
