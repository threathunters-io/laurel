use std::collections::BTreeMap;
use std::fs::{File, Metadata};
use std::path::PathBuf;
use std::sync::Mutex;
use std::{ffi::OsStr, os::unix::ffi::OsStrExt};

use super::*;

#[derive(Default, Clone, Debug)]
struct Process {
    ppid: u32,
    is_pid1: bool,
    exe: Vec<u8>,
}

pub struct Proctable(Mutex<BTreeMap<u32, Process>>);

impl Proctable {
    #[allow(clippy::new_without_default)]
    pub const fn new() -> Self {
        Self(Mutex::new(BTreeMap::new()))
    }
    fn get(&self, pid: &u32) -> Option<Process> {
        self.0.lock().unwrap().get(pid).cloned()
    }
    pub fn list(&self) -> Vec<u32> {
        PROCTABLE.0.lock().unwrap().keys().copied().collect()
    }
    pub fn insert(&self, pid: u32, ppid: u32) {
        let is_pid1 = pid == 1;
        let p = Process {
            ppid,
            is_pid1,
            ..Process::default()
        };
        self.0.lock().unwrap().insert(pid, p);
    }
    pub fn remove(&self, pid: &u32) {
        self.0.lock().unwrap().remove(&pid);
    }
    fn modify(&self, pid: &u32, proc: impl FnOnce(&mut Process)) {
        if let Some(p) = self.0.lock().unwrap().get_mut(pid) {
            proc(p)
        }
    }
    pub fn set_init(&self, pid: u32) {
        self.modify(&pid, |p| p.is_pid1 = true);
    }
    pub fn set_exe(&self, pid: u32, exe: &[u8]) {
        self.modify(&pid, |p| p.exe = exe.to_vec());
    }
    pub fn clear(&self) {
        self.0.lock().unwrap().retain(|_, _| false);
    }
}

pub static PROCTABLE: Proctable = Proctable::new();

pub fn open_pid_exe_meta(_pid: u32) -> std::io::Result<File> {
    File::open("/dev/null")
}

pub fn get_pid_exe_link(pid: u32) -> std::io::Result<PathBuf> {
    PROCTABLE
        .get(&pid)
        .map(|p| OsStr::from_bytes(p.exe.as_slice()).into())
        .ok_or(std::io::ErrorKind::NotFound.into())
}

pub fn read_environ_block(_pid: u32) -> Result<Vec<u8>, ProcFSError> {
    Ok(vec![])
}

pub fn get_pids() -> Result<impl Iterator<Item = u32>, ProcFSError> {
    Ok(PROCTABLE.list().into_iter())
}

pub fn pid_path_metadata(_pid: u32, _path: &[u8]) -> Result<Metadata, std::io::Error> {
    Err(std::io::ErrorKind::NotFound.into())
}

pub(crate) fn parse_proc_pid(pid: u32) -> Result<ProcPidInfo, ProcFSError> {
    println!("pid_parse_proc_pid: {pid}");
    let Process { ppid, is_pid1, exe } = PROCTABLE.get(&pid).ok_or(ProcFSError::PidFile {
        pid,
        obj: "whatever",
        err: std::io::ErrorKind::NotFound.into(),
    })?;
    let comm = b"<mock-process>".to_vec();
    Ok(ProcPidInfo {
        pid,
        ppid,
        is_pid1,
        comm,
        exe: Some(exe),
        cgroup: None,
        starttime: 0,
    })
}

pub fn is_pid1(pid: u32) -> bool {
    PROCTABLE.get(&pid).map(|p| p.is_pid1).unwrap_or_default()
}

pub(crate) fn parse_proc_pid_cgroup(_pid: u32) -> Result<Option<Vec<u8>>, ProcFSError> {
    unimplemented!()
}
