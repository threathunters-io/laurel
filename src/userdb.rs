use std::collections::HashMap;
use std::ffi::CStr;

use libc;

fn get_user(uid: u32) -> Option<String> {
    let passwd = unsafe { libc::getpwuid(uid as libc::uid_t) };
    if passwd.is_null() {
        None
    } else {
        let passwd = unsafe { *passwd };
        Some(unsafe { CStr::from_ptr(passwd.pw_name) }.to_string_lossy().to_string())
    }
}

fn get_group(gid: u32) -> Option<String> {
    let group = unsafe { libc::getgrgid(gid as libc::gid_t ) };
    if group.is_null() {
        None
    } else {
        let group = unsafe { *group };
        Some(unsafe { CStr::from_ptr(group.gr_name) }.to_string_lossy().to_string())
    }
}

/// Implementation of a credentials store that caches user and group
/// lookups by uid and gid, respectively.
#[derive(Debug,Default)]
pub struct UserDB {
    pub users: HashMap<u32, (Option<String>, i64)>,
    pub groups: HashMap<u32, (Option<String>, i64)>,
}

fn now() -> i64 { unsafe { libc::time(std::ptr::null_mut()) as i64 } }

impl UserDB {
    pub fn new() -> Self {
        let mut c = UserDB {
            users: HashMap::with_capacity(200),
            groups: HashMap::with_capacity(200),
        };
        // prime cache
        for id in 0..1023 {
            c.get_user(id);
            c.get_group(id);
        }
        c
    }
    pub fn get_user(&mut self, uid: u32) -> Option<String> {
        match self.users.get(&uid) {
            Some((x, t)) if *t >= now() - 1800 => x.clone(),
            Some(_) | None => {
                let user = get_user(uid);
                self.users.insert(uid, (user.clone(), now()));
                user
            }
        }
    }
    pub fn get_group(&mut self, gid: u32) -> Option<String> {
        match self.groups.get(&gid) {
            Some((x, t)) if *t >= now() - 1800 => x.clone(),
            Some(_) | None => {
                let group = get_group(gid);
                self.groups.insert(gid, (group.clone(), now()));
                group
            }
        }
    }
}
