use std::ffi::{OsStr, OsString};
use std::fs::{self, remove_file, rename, File, OpenOptions};
use std::io::{Error, Result, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;

use exacl::{setfacl, AclEntry, Perm};

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
    pub users: Vec<String>,
    pub groups: Vec<String>,
    pub other: bool,
    file: Option<File>,
    offset: u64,
}

fn ignore_missing(e: Error) -> Result<()> {
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(e)
    }
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
            users: vec![],
            groups: vec![],
            other: false,
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
    pub fn with_user(mut self, user: &str) -> Self {
        self.users.push(user.into());
        self
    }
    pub fn with_group(mut self, group: &str) -> Self {
        self.groups.push(group.into());
        self
    }
    pub fn with_other(mut self, other: bool) -> Self {
        self.other = other;
        self
    }

    /// Closes the main file and performs a backup file rotation
    pub fn rotate(&mut self) -> Result<()> {
        log::info!("Rotating {}", self.basename.to_string_lossy());
        if self.generations == 0 {
            fs::remove_file(&self.basename).or_else(ignore_missing)?;
            return Ok(());
        }
        for suffix in (0..self.generations).rev() {
            let mut old = self.basename.clone();
            match suffix {
                0 => (),
                _ => old.push(format!(".{suffix}")),
            };
            let mut new = self.basename.clone();
            new.push(format!(".{}", suffix + 1));
            if fs::metadata(&old).is_ok() {
                fs::rename(old, new).or_else(ignore_missing)?;
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
        let mut acl = vec![
            AclEntry::allow_user("", Perm::from_bits_truncate(6), None),
            AclEntry::allow_group("", Perm::from_bits_truncate(4), None),
            #[cfg(any(target_os = "linux", target_os = "freebsd"))]
            AclEntry::allow_other(
                if self.other {
                    Perm::READ
                } else {
                    Perm::empty()
                },
                None,
            ),
        ];
        for user in &self.users {
            acl.push(AclEntry::allow_user(user, Perm::READ, None));
        }
        for group in &self.groups {
            acl.push(AclEntry::allow_group(group, Perm::READ, None));
        }

        if let Ok(mut f) = OpenOptions::new().append(true).open(&self.basename) {
            setfacl(&[&self.basename], &acl, None).map_err(|e| Error::new(e.kind(), e))?;

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
                .append(true)
                .open(&tmp)?;

            setfacl(&[&tmp], &acl, None).map_err(|e| Error::new(e.kind(), e))?;

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
        if self.offset > self.filesize && self.filesize != 0 && buf.last() == Some(&b'\n') {
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

#[cfg(test)]
mod test {
    use super::*;
    use nix::unistd::mkdtemp;
    use std::env::temp_dir;
    #[test]
    fn fresh_file() {
        let td = mkdtemp(&temp_dir().join("laurel-test-XXXXXXXX")).expect("can't create temp dir");
        let mut fr = FileRotate::new(td.join("logfile"));
        fr.rotate().expect("rotate");
        fr.write(b"asdf").expect("write");
        fr.flush().expect("flush");
        std::fs::remove_dir_all(td).expect("remove_dir_all");
    }

    #[test]
    fn existing() {
        let td = mkdtemp(&temp_dir().join("laurel-test-XXXXXXXX")).expect("can't create temp dir");
        std::fs::write(td.join("logfile"), "asdf").expect("setup");
        let mut fr = FileRotate::new(td.join("logfile")).with_generations(3);
        fr.rotate().expect("rotate");
        assert!(
            td.join("logfile.1").exists(),
            "after rotate, logfile.1 should exist"
        );
        assert!(
            !td.join("logfile").exists(),
            "after rotate, logfile should no longer exist"
        );
        fr.write(b"asdf").expect("write");
        fr.flush().expect("flush");
        assert!(
            td.join("logfile").exists(),
            "after rotate+write, logfile should exist"
        );
        std::fs::remove_dir_all(td).expect("remove_dir_all");
    }
}
