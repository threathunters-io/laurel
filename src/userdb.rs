use std::collections::BTreeMap;
use std::ffi::CString;

use serde::{Deserialize, Serialize};

use tinyvec::TinyVec;

use nix::unistd::{getgrouplist, Gid, Group, Uid, User};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UserEntry {
    name: String,
    primary_gid: u32,
    secondary_gids: TinyVec<[u32; 8]>,
}

fn get_user(uid: u32) -> Option<UserEntry> {
    User::from_uid(Uid::from(uid)).ok()?.map(|user| {
        let name = CString::new(user.name.as_bytes()).unwrap();
        let gids = getgrouplist(&name, user.gid)
            .unwrap_or_else(|_| vec![])
            .into_iter()
            .filter(|gid| *gid != user.gid)
            .map(u32::from)
            .collect();
        UserEntry {
            name: user.name,
            primary_gid: user.gid.into(),
            secondary_gids: gids,
        }
    })
}

fn get_group(gid: u32) -> Option<String> {
    Group::from_gid(Gid::from(gid))
        .ok()?
        .map(|group| group.name)
}

/// Implementation of a credentials store that caches user and group
/// lookups by uid and gid, respectively.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct UserDB {
    users: BTreeMap<u32, (Option<UserEntry>, i64)>,
    groups: BTreeMap<u32, (Option<String>, i64)>,
}

fn now() -> i64 {
    unsafe { libc::time(std::ptr::null_mut()) }
}

impl UserDB {
    pub fn populate(&mut self) {
        for id in 0..1023 {
            if let Some(user) = get_user(id) {
                self.users.insert(id, (Some(user), now()));
            }
            if let Some(group) = get_group(id) {
                self.groups.insert(id, (Some(group), now()));
            }
        }
    }
    fn get_user_entry(&mut self, uid: u32) -> Option<UserEntry> {
        match self.users.get(&uid) {
            Some((entry, t)) if *t >= now() - 1800 => entry.clone(),
            Some(_) | None => {
                let entry = get_user(uid);
                self.users.insert(uid, (entry.clone(), now()));
                entry
            }
        }
    }
    pub fn get_user(&mut self, uid: u32) -> Option<String> {
        self.get_user_entry(uid).map(|user| user.name)
    }
    pub fn get_user_groups(&mut self, uid: u32) -> Option<Vec<String>> {
        let user = self.get_user_entry(uid)?;
        let names = Some(user.primary_gid)
            .into_iter()
            .chain(user.secondary_gids)
            .map(|gid| self.get_group(gid).unwrap_or(format!("#{gid}")))
            .collect();
        Some(names)
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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    /// This is not a real test case, it is just intended for
    /// diagnostic purposes.
    fn userdb() {
        let mut userdb = UserDB::default();
        // Just output info for current user
        let uid = nix::unistd::Uid::current();
        let gid = nix::unistd::Gid::current();
        println!("user for uid {uid}: {:?}", userdb.get_user(uid.into()));
        println!("group for gid {gid}: {:?}", userdb.get_group(gid.into()));
        println!(
            "groups for uid {uid}: {:?}",
            userdb.get_user_groups(uid.into())
        );
    }
}
