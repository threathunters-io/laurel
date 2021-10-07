use libc::S_IFMT;
use nix::unistd::{self, Gid, Uid, User};
use std::error::Error;
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::{fs, fs::Permissions, path::PathBuf};

/// Creates specified log directory with the given owner.
/// In case directory exists it just checks the permissions.
/// Returns an optional report with file path and description, in case permissions of
/// existing directory did not matched the expected ones.
///
/// # Arguments
///
/// * `log_dir`: directory designated for logs
///
pub fn create_log_dir(log_dir: &PathBuf) -> Result<Option<(String, String)>, Box<dyn Error>> {
    if log_dir.exists() {
        return Ok(check_path(&log_dir.to_string_lossy(), 0o755)?);
    } else {
        let euid = Uid::effective();
        let log_owner = User::from_uid(euid)?.ok_or_else(|| format!("uid {} not found", euid))?;

        fs::create_dir_all(log_dir)?;
        unistd::chown(log_dir, Some(log_owner.uid), Some(log_owner.gid))?;
        fs::set_permissions(&log_dir, PermissionsExt::from_mode(0o755))?;
        return Ok(None);
    }
}

/// Checks if the given file respectively directory path sets the expected permissions.
/// Further, it checks the currect owner. The desired owner is root:root.
/// When set otherwise, the file owner is checked against the effective UID.
/// When any mismatches are found, they are fixed.
/// Returns an optional report with file path and description, in case permissions/owner of
/// existing directory did not matched the expected ones.
///
/// # Arguments
///
/// * `f_path`: file or directory path
/// * `expected_st_mode`: the desired st_mode, e.g., 0o40755 that should be checked against
pub fn check_path(
    f_path: &str,
    expected_mode: u32,
) -> Result<Option<(String, String)>, Box<dyn Error>> {
    let f_meta = fs::metadata(f_path)?;
    let mut wrn_msg: String = String::new();

    let euid = Uid::effective();

    // In case the file belongs to root:root everything is fine.
    // In case Laurel is not running as root, the file at least should belong
    // to the user behind the effective uid.
    if (f_meta.st_uid() != 0 || f_meta.st_gid() != 0) && f_meta.st_uid() != euid.as_raw() {
        let usr = User::from_uid(Uid::from_raw(f_meta.st_uid()))
            // We make liberal use of unwrap with User struct throughout this
            // method, since proper error handling was already done, prior
            // calling this method, in main respectively in run_app.
            .unwrap()
            .unwrap();
        let grp = User::from_uid(Uid::from_raw(f_meta.st_gid()))
            .unwrap()
            .unwrap();
        let e_usr = User::from_uid(euid)
            .unwrap()
            .ok_or_else(|| format!("uid {} not found", euid))
            .unwrap();

        wrn_msg.push_str(&format!(
            "Is not owned by user root respectively the running user {}. File owner is {}:{}. ",
            e_usr.name, usr.name, grp.name
        ));
    }
    // In case the owner is not right, try to set it to root. Only try with euid := 0.
    if wrn_msg.len() > 0 {
        match unistd::chown(f_path, Some(euid), Some(Gid::from_raw(0))) {
            Ok(_) => {
                wrn_msg.push_str("Corrected: set owner to root:root. ");
            }
            Err(errno) => {
                // This can happen, for example, when euid != 0, but owner is uid := 0.
                let errmsg = format!("Tried to set owner but failed. Details: {}. ", errno);
                wrn_msg.push_str(&errmsg);
            }
        }
    }

    // S_IFMT is 0o170000 in order to mask mode to a valid st_mode. See man(7) inode for details.
    let expected_st_mode = expected_mode | (S_IFMT & f_meta.st_mode());

    if f_meta.st_mode() != expected_st_mode {
        wrn_msg.push_str(&format!(
            "Permission mismatch for others. Current Mode: {:o}, expected mode: {:o}. ",
            f_meta.st_mode() & 0o777,  // only the simple permission mode
            expected_mode
        ));
        let new_perms = Permissions::from_mode(expected_st_mode);
        match fs::set_permissions(f_path, new_perms) {
            Ok(_) => {
                wrn_msg.push_str("Corrected. Revoked all perms for others. ");
            }
            Err(_) => {}
        }
    }

    if wrn_msg.len() > 0 {
        Ok(Some((String::from(f_path), wrn_msg)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, fs::File};

    #[test]
    fn test_config_permission_mismatch() {
        let config_file_path = "/tmp/laurel_configtest_random5y7xzn5sagkd384jdk.toml";

        // Just to be sure nothing left from previous tests
        match fs::remove_file(config_file_path) {
            Ok(_) => {}
            Err(_) => {}
        }

        let _ = match File::create(config_file_path) {
            Err(reason) => panic!(
                "couldn't create file {}. Reason: {}",
                config_file_path, reason
            ),
            Ok(file) => file,
        };
        fs::set_permissions(config_file_path, Permissions::from_mode(0o644)).unwrap();

        if let Ok(res) = check_path(config_file_path, 0o640) {
            match res {
                Some((f_path, warn_msg)) => {
                    let f_meta = fs::metadata(&f_path).unwrap();
                    fs::remove_file(config_file_path).unwrap();
                    assert_eq!(f_meta.st_mode(), 0o100640);
                    assert_eq!(&f_path, config_file_path);
                    assert_eq!(warn_msg, "Permission mismatch for others. Current Mode: 644, expected mode: 640. Corrected. Revoked all perms for others. ");
                }
                None => {
                    fs::remove_dir(config_file_path).unwrap();
                    panic!("Test setup must be wrong.");
                }
            }
        } else {
            fs::remove_dir(config_file_path).unwrap();
            panic!("Unknown reason :-/");
        }
    }

    #[test]
    fn test_logfolder_permission_mismatch() {
        let log_folder_path = "/tmp/laurel_logfoldertest_random5dfj38vvxa48513";

        // Just to be sure nothing left from previous tests
        match fs::remove_dir(log_folder_path) {
            Ok(_) => {}
            Err(_) => {}
        }

        let _ = match fs::create_dir(log_folder_path) {
            Err(reason) => panic!(
                "Couldn't create folder {}. Reason: {}",
                log_folder_path, reason
            ),
            Ok(file) => file,
        };
        fs::set_permissions(log_folder_path, Permissions::from_mode(0o750)).unwrap();

        if let Ok(res) = check_path(log_folder_path, 0o755) {
            match res {
                Some((f_path, warn_msg)) => {
                    let f_meta = fs::metadata(&f_path).unwrap();
                    fs::remove_dir(log_folder_path).unwrap();
                    assert_eq!(f_meta.st_mode(), 0o40755);
                    assert_eq!(&f_path, log_folder_path);
                    assert_eq!(warn_msg, "Permission mismatch for others. Current Mode: 750, expected mode: 755. Corrected. Revoked all perms for others. ");
                }
                None => {
                    fs::remove_dir(log_folder_path).unwrap();
                    panic!("Test setup must be wrong.");
                }
            }
        } else {
            fs::remove_dir(log_folder_path).unwrap();
            panic!("Unknown reason :-/");
        }
    }

    #[test]
    fn test_config_permission_match() {
        let config_file_path = "/tmp/laurel_configtest_random4829gnaqzd47fj8c928fah.toml";

        // Just to be sure nothing left from previous tests
        match fs::remove_file(config_file_path) {
            Ok(_) => {}
            Err(_) => {}
        }

        let _ = match File::create(config_file_path) {
            Err(reason) => panic!(
                "couldn't create file {}. Reason: {}",
                config_file_path, reason
            ),
            Ok(file) => file,
        };
        fs::set_permissions(config_file_path, Permissions::from_mode(0o640)).unwrap();

        if let Ok(res) = check_path(config_file_path, 0o640) {
            match res {
                Some((_, _)) => {
                    fs::remove_dir(config_file_path).unwrap();
                    panic!("Test failed: the permission were the same, still a warn message was generated.");
                }
                None => {
                    let f_meta = fs::metadata(config_file_path).unwrap();
                    fs::remove_file(config_file_path).unwrap();
                    assert_eq!(f_meta.st_mode(), 0o100640);
                }
            }
        } else {
            fs::remove_dir(config_file_path).unwrap();
            panic!("Unknown reason :-/");
        }
    }
}
