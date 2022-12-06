use posix_acl::{PosixACL, Qualifier, ACL_READ};
use std::ffi::{OsStr, OsString};
use std::fs::{self, remove_file, rename, File, OpenOptions};
use std::io::{Error, ErrorKind, Result, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;

use nix::sys::stat::{fchmod, Mode};
use nix::unistd::Uid;

/// A rotating (log) file writer
///
/// [`FileRotate`] rotates the file after `filesize` bytes have been
/// written to the main file. Up to `num_files` generations of backup
/// files are kept around.
pub struct FileRotate {
    /// The name for the main file. For backup generations, `.1`,
    /// `.2`, `.3` etc. are appended to this file name.
    pub basename: OsString,
    /// When a [`write`] operation causes the main file to reach this
    /// size, a [`FileRotate::rotate`] operation is triggered.
    pub filesize: u64,
    pub generations: u64,
    pub uids: Vec<Uid>,
    file: Option<File>,
    offset: u64,
}

impl FileRotate {
    /// Creates a new [`FileRotate`] instance. This does not involve
    /// any I/O operations; the main file is only created when calling
    /// [`write`].
    pub fn new<P: AsRef<OsStr>>(path: P) -> Self {
        FileRotate {
            basename: OsString::from(path.as_ref()),
            filesize: 0,
            generations: 0,
            uids: vec![],
            file: None,
            offset: 0,
        }
    }

    pub fn with_filesize(mut self, p: u64) -> Self {
        self.filesize = p;
        self
    }
    pub fn with_generations(mut self, p: u64) -> Self {
        self.generations = p;
        self
    }
    pub fn with_uid(mut self, uid: Uid) -> Self {
        self.uids.push(uid);
        self
    }

    /// Closes the main file and performs a backup file rotation
    pub fn rotate(&mut self) -> Result<()> {
        for suffix in (0..self.generations).rev() {
            let mut old = self.basename.clone();
            match suffix {
                0 => (),
                _ => old.push(format!(".{}", suffix)),
            };
            let mut new = self.basename.clone();
            new.push(format!(".{}", suffix + 1));
            if fs::metadata(&old).is_ok() {
                fs::rename(old, new)?;
            }
        }
        self.file = None;
        Ok(())
    }

    /// Opens main file, re-using existing file if prersent.
    ///
    /// If the file does not exist, a new temporary file is crerated,
    /// permissions are adjusted, and it is renamed to the final
    /// destination.
    fn open(&mut self) -> Result<()> {
        let mut acl = PosixACL::new(0o600);
        for uid in &self.uids {
            acl.set(Qualifier::User(uid.as_raw()), ACL_READ);
        }

        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .append(true)
            .open(&self.basename)
        {
            fchmod(f.as_raw_fd(), Mode::from_bits(0o600).unwrap())
                .map_err(|e| Error::new(ErrorKind::Other, e))?;
            acl.write_acl(&self.basename)
                .map_err(|e| Error::new(e.kind(), e))?;

            self.offset = f.seek(SeekFrom::End(0))?;
            self.file = Some(f);
        } else {
            let mut tmp = self.basename.clone();
            tmp.push(".tmp");

            remove_file(&tmp).or_else(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(e),
            })?;

            let f = OpenOptions::new()
                .create_new(true)
                .mode(0o600)
                .write(true)
                .append(true)
                .open(&tmp)?;

            acl.write_acl(&tmp).map_err(|e| Error::new(e.kind(), e))?;

            rename(&tmp, &self.basename)?;

            self.offset = 0;
            self.file = Some(f);
        }
        Ok(())
    }
}

impl Write for FileRotate {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.file.is_none() {
            self.open()?;
        }
        let mut f = self.file.as_ref().unwrap();
        let sz = f.write(buf)?;
        self.offset += sz as u64;
        if self.offset > self.filesize && self.filesize != 0 {
            f.sync_all()?;
            self.rotate()?;
        }
        Ok(sz)
    }
    fn flush(&mut self) -> Result<()> {
        match self.file.as_ref() {
            Some(mut f) => f.flush(),
            None => Ok(()),
        }
    }
}
