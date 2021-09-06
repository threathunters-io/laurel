//! Laurel is an "audisp" plugin plugins that consume data fed by the
//! the Linux Audit daemon and reformats events as JSON lines.

use getopts::Options;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::io::{self, BufRead, BufWriter, Write};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use nix::unistd::{chown,setresuid,setresgid,User,Uid};

use caps::{Capability, CapSet};
use caps::securebits::set_keepcaps;

use serde::Serialize;
use serde_json::{self,json};

pub mod types;
pub mod parser;
pub mod coalesce;
pub mod proc;
pub mod rotate;
pub mod config;
pub mod constants;

use coalesce::Coalesce;
use rotate::FileRotate;
use config::*;

mod syslog {
    use std::ffi::CString;
    use libc::{syslog,LOG_DAEMON,LOG_CRIT};

    pub fn log_crit(message: &str) {
        let s = CString::new(message).unwrap();
        unsafe { syslog(LOG_CRIT|LOG_DAEMON, s.as_ptr()) };
    }
}
use syslog::log_crit;

#[derive(Default,Serialize)]
struct Stats { lines: u64, events: u64, errors: u64 }

/// Assume non-privileged user while retaining selected capabilities:
///
/// - CAP_DAC_READ_SEARCH is required for reading arbitrary files,
///   e.g. for calculating file hashes
/// - CAP_DAC_READ_SEARCH+CAP_SYS_PTRACE are required for accessing
///   environment variables from arbitrary processes
///   (/proc/$PID/environ).
fn drop_privileges(runas_user: &User) -> Result<(),Box<dyn Error>> {
    set_keepcaps(true)?;

    let uid = runas_user.uid;
    let gid = runas_user.gid;

    setresgid(gid, gid, gid)
        .map_err(|e|format!("setresgid({}): {}", uid, e.to_string()))?;
    setresuid(uid, uid, uid)
        .map_err(|e|format!("setresuid({}): {}", gid, e.to_string()))?;

    let mut capabilities = HashSet::new();
    capabilities.insert(Capability::CAP_SYS_PTRACE);
    capabilities.insert(Capability::CAP_DAC_READ_SEARCH);
    caps::set(None, CapSet::Effective, &capabilities)
        .map_err(|e|format!("set capabilities: {}", e.to_string()))?;

    set_keepcaps(false)?;
    Ok(())
}

struct Logger {
    output: BufWriter<Box<dyn Write>>
}

impl Logger {
    fn log<S: Serialize>(&mut self, message: S) {
        serde_json::to_writer(&mut self.output, &message).unwrap();
        self.output.write(b"\n").unwrap();
        self.output.flush().unwrap();
    }
}

fn run_app() -> Result<(), Box<dyn Error>> {
    let args : Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("c", "config", "configfile", "FILE");
    opts.optflag("h", "help", "help");

    let matches = opts.parse(&args[1..])?;
    if matches.opt_present("h") {
        println!("Usage: {} [ -c configfile ]", args[0]);
        return Ok(());
    }

    let config: Config = match matches.opt_str("c") {
        Some(f_name) => toml::from_slice(&fs::read(&f_name)?)?,
        None => Config::default(),
    };

    let runas_user = match config.user {
        Some(ref username) => User::from_name(username)?
            .ok_or_else(||format!("user {} not found", username))?,
        None => {
            let uid = Uid::effective();
            User::from_uid(uid)?.ok_or_else(||format!("uid {} not found", uid))?
        }
    };

    let dir = config.directory.clone().unwrap_or(Path::new(".").to_path_buf());
    fs::create_dir_all(&dir)?;
    chown(&dir, Some(runas_user.uid), Some(runas_user.gid))?;
    fs::set_permissions(&dir, PermissionsExt::from_mode(0o755))?;

    let mut logger = match &config.auditlog.file {
        p if p.as_os_str() == "-" => Logger { output: BufWriter::new(Box::new(io::stdout())) },
        p if p.has_root() && p.parent() != None => {
            return Err(format!("invalid file directory={} file={}",
                               dir.to_string_lossy(), p.to_string_lossy())
                       .into());
        },
        p => {
            let mut filename = dir.clone();
            filename.push(&p);
            let mut rot = FileRotate::new(filename);
            for user in &config.auditlog.clone().users.unwrap_or(vec!()) {
                rot = rot.with_uid(User::from_name(&user)?
                                   .ok_or_else(||format!("user {} not found", &user))?
                                   .uid);
            }
            if let Some(generations) = &config.auditlog.generations {
                rot = rot.with_generations(*generations);
            }
            if let Some(filesize) = &config.auditlog.size {
                rot = rot.with_filesize(*filesize);
            }
            Logger { output: BufWriter::new(Box::new(rot)) }
        }
    };

    if !Uid::effective().is_root() {
        logger.log(&json!({"warning": "Not dropping privileges -- not running as root"}));
    } else if runas_user.uid.is_root() {
        logger.log(&json!({"warning": "Not dropping privileges -- no user configured"}));
    } else if let Err(e) = drop_privileges(&runas_user) {
        logger.log(&json!({"fatal": e.to_string()}));
        return Err(e);
    }

    // Initial setup is done at this point.

    logger.log(&json!({
        "notice": {
            "program": &args[0],
            "action": "start",
            "euid": Uid::effective().as_raw(),
            "config": &config
        }}));

    let mut coalesce = Coalesce::default();
    coalesce.populate_proc_table()?;
    let mut line: Vec<u8> = Vec::new();
    let mut stats = Stats::default();

    let stdin = io::stdin();
    let mut input = stdin.lock();

    loop {
        line.clear();
        if input.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        stats.lines+=1;
        match coalesce.process_line(line.clone()) {
            Ok(Some(event)) => {
                stats.events += 1;
                logger.log(&event);
            }
            Ok(None) => (),
            Err(e) => {
                stats.errors += 1;
                let line = String::from_utf8_lossy(&line);
                logger.log(&json!({"error": { "message": e.to_string(), "input": &line }}));
                continue
            }
        };
    }

    logger.log(&json!({"notice": { "program": &args[0], "action": "stop", "stats": &stats }}));

    Ok(())
}

pub fn main() {
    let progname = Arc::new(env::args().next().unwrap_or_else(||"(unknown)".to_string()));
    {
        let progname = progname.clone();
        std::panic::set_hook(Box::new(move |panic_info| {
        let payload = panic_info.payload();
        let message = if let Some(s) = payload.downcast_ref::<&str>() {
            s
        } else if let Some(s) = payload.downcast_ref::<String>() {
            &s
        } else {
            "(unknown error)"
        };
        let location = match panic_info.location() {
            Some(l) => format!("{}:{},{}", l.file(), l.line(), l.column()),
            None => "(unknown)".to_string(),
        };
        let e = format!("fatal error '{}' at {}", &message, &location);
        eprintln!("{}: {}", &progname, &e);
        log_crit(&e);
        }));
    }

    match run_app() {
        Ok(_) => (),
        Err(e) => {
            let e = e.to_string();
            eprintln!("{}: {}", &progname, &e);
            log_crit(&e);
            std::process::abort();
        }
    };
}
