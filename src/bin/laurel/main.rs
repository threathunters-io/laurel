//! Laurel is an "audisp" plugin plugins that consume data fed by the
//! the Linux Audit daemon and reformats events as JSON lines.

use getopts::Options;
use std::env;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::ops::AddAssign;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, SystemTime};

use nix::unistd::{chown, execve, Uid, User};
#[cfg(target_os = "linux")]
use nix::unistd::{setresgid, setresuid};

#[cfg(target_os = "linux")]
use caps::{securebits::set_keepcaps, CapSet, Capability};

use serde::Serialize;

use laurel::coalesce::Coalesce;
use laurel::config::{Config, Input, Logfile};
use laurel::logger;
use laurel::rotate::FileRotate;
use laurel::types::Event;

#[derive(Default, Serialize)]
struct Stats {
    lines: u64,
    events: u64,
    errors: u64,
}

// Overload the += operator.
impl AddAssign for Stats {
    fn add_assign(&mut self, other: Self) {
        *self = Self {
            lines: self.lines + other.lines,
            events: self.events + other.events,
            errors: self.errors + other.errors,
        };
    }
}

/// Assume non-privileged user while retaining selected capabilities:
///
/// - CAP_DAC_READ_SEARCH is required for reading arbitrary files,
///   e.g. for calculating file hashes
/// - CAP_DAC_READ_SEARCH+CAP_SYS_PTRACE are required for accessing
///   environment variables from arbitrary processes
///   (/proc/$PID/environ).
#[cfg(target_os = "linux")]
fn drop_privileges(runas_user: &User) -> Result<(), Box<dyn Error>> {
    set_keepcaps(true)?;
    let uid = runas_user.uid;
    let gid = runas_user.gid;
    setresgid(gid, gid, gid).map_err(|e| format!("setresgid({}): {}", gid, e))?;
    setresuid(uid, uid, uid).map_err(|e| format!("setresuid({}): {}", uid, e))?;

    #[cfg(feature = "procfs")]
    {
        let mut capabilities = std::collections::HashSet::new();
        capabilities.insert(Capability::CAP_SYS_PTRACE);
        capabilities.insert(Capability::CAP_DAC_READ_SEARCH);
        caps::set(None, CapSet::Permitted, &capabilities)
            .map_err(|e| format!("set permitted capabilities: {}", e))?;
        caps::set(None, CapSet::Effective, &capabilities)
            .map_err(|e| format!("set effective capabilities: {}", e))?;
        caps::set(None, CapSet::Inheritable, &capabilities)
            .map_err(|e| format!("set inheritable capabilities: {}", e))?;
    }

    set_keepcaps(false)?;
    Ok(())
}

struct Logger {
    prefix: Option<String>,
    output: BufWriter<Box<dyn Write>>,
}

impl Logger {
    fn log<S: Serialize>(&mut self, message: S) {
        if let Some(prefix) = &self.prefix {
            self.output.write_all(prefix.as_bytes()).unwrap();
        }
        serde_json::to_writer(&mut self.output, &message).unwrap();
        self.output.write_all(b"\n").unwrap();
        self.output.flush().unwrap();
    }

    fn new(def: &Logfile, dir: &Path) -> Result<Self, Box<dyn Error>> {
        match &def.file {
            p if p.as_os_str() == "-" => Ok(Logger {
                prefix: def.line_prefix.clone(),
                output: BufWriter::new(Box::new(io::stdout())),
            }),
            p if p.has_root() && p.parent().is_none() => Err(format!(
                "invalid file directory={} file={}",
                dir.to_string_lossy(),
                p.to_string_lossy()
            )
            .into()),
            p => {
                let mut filename = dir.to_path_buf();
                filename.push(p);
                let mut rot = FileRotate::new(filename);
                for user in &def.clone().users.unwrap_or_default() {
                    rot = rot.with_uid(
                        User::from_name(user)?
                            .ok_or_else(|| format!("user {} not found", &user))?
                            .uid,
                    );
                }
                if let Some(generations) = &def.generations {
                    rot = rot.with_generations(*generations);
                }
                if let Some(filesize) = &def.size {
                    rot = rot.with_filesize(*filesize);
                }
                Ok(Logger {
                    prefix: def.line_prefix.clone(),
                    output: BufWriter::new(Box::new(rot)),
                })
            }
        }
    }
}

fn run_app() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("c", "config", "Configuration file", "FILE");
    opts.optflag("d", "dry-run", "Only parse configuration and exit");
    opts.optflag("h", "help", "Print short help text and exit");
    opts.optflag("v", "version", "Print version and exit");

    let matches = opts.parse(&args[1..])?;
    if matches.opt_present("h") {
        println!("{}", opts.usage(&args[0]));
        return Ok(());
    }

    if matches.opt_present("v") {
        println!("{}", laurel::VERSION);
        return Ok(());
    }

    let config: Config = match matches.opt_str("c") {
        Some(f_name) => {
            if fs::metadata(&f_name)
                .map_err(|e| format!("stat {}: {}", &f_name, &e))?
                .permissions()
                .mode()
                & 0o002
                != 0
            {
                return Err(format!("Config file {} must not be world-writable", f_name).into());
            }
            let lines = fs::read(&f_name).map_err(|e| format!("read {}: {}", &f_name, &e))?;
            toml::from_str(
                &String::from_utf8(lines)
                    .map_err(|_| format!("parse: {}: contains invalid UTF-8 sequences", &f_name))?,
            )
            .map_err(|e| format!("parse {}: {}", f_name, e))?
        }
        None => Config::default(),
    };

    // Set up input before dropping privileges.
    let raw_input: Box<dyn Read> = match &config.input {
        // safety: File descriptor 0 is readable. (If it isn't, the
        // first read will cause the appropriate error.) We don't use
        // file descriptor 0 anywhere else.
        Input::Stdin => Box::new(unsafe { std::fs::File::from_raw_fd(0) }),
        Input::Unix(path) => Box::new(
            UnixStream::connect(path)
                .map_err(|e| format!("connect: {}: {}", path.to_string_lossy(), e))?,
        ),
    };

    // std::io::Stdin's buffer is only 8KB, so we construct our own.
    // 1MB ought to be enough for anybody.
    let mut input = BufReader::with_capacity(1 << 20, raw_input);

    let runas_user = match config.user {
        Some(ref username) => {
            User::from_name(username)?.ok_or_else(|| format!("user {} not found", username))?
        }
        None => {
            let uid = Uid::effective();
            User::from_uid(uid)?.ok_or_else(|| format!("uid {} not found", uid))?
        }
    };

    if matches.opt_present("d") {
        println!("Laurel {}: Config ok.", laurel::VERSION);
        return Ok(());
    }

    let dir = config
        .directory
        .clone()
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    if dir.exists() {
        if !dir.is_dir() {
            return Err(format!("{} is not a directory", dir.to_string_lossy()).into());
        }
        if dir
            .metadata()
            .map_err(|e| format!("stat {}: {}", dir.to_string_lossy(), &e))?
            .permissions()
            .mode()
            & 0o002
            != 0
        {
            log::warn!(
                "Base directory {} must not be world-wirtable",
                dir.to_string_lossy()
            );
        }
    } else {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("create_dir: {}: {}", dir.to_string_lossy(), e))?;
    }
    chown(&dir, Some(runas_user.uid), Some(runas_user.gid))
        .map_err(|e| format!("chown: {}: {}", dir.to_string_lossy(), e))?;
    fs::set_permissions(&dir, PermissionsExt::from_mode(0o755))
        .map_err(|e| format!("chmod: {}: {}", dir.to_string_lossy(), e))?;

    let mut debug_logger = if let Some(l) = &config.debug.log {
        Some(Logger::new(l, &dir).map_err(|e| format!("can't create debug logger: {}", e))?)
    } else {
        None
    };
    let mut error_logger = if let Some(def) = &config.debug.parse_error_log {
        let mut filename = dir.clone();
        filename.push(&def.file);
        let mut rot = FileRotate::new(filename);
        for user in &def.clone().users.unwrap_or_default() {
            rot = rot.with_uid(
                User::from_name(user)?
                    .ok_or_else(|| format!("user {} not found", &user))?
                    .uid,
            );
        }
        if let Some(generations) = &def.generations {
            rot = rot.with_generations(*generations);
        }
        if let Some(filesize) = &def.size {
            rot = rot.with_filesize(*filesize);
        }
        Some(rot)
    } else {
        None
    };

    if !Uid::effective().is_root() {
        log::warn!("Not dropping privileges -- not running as root");
    } else if runas_user.uid.is_root() {
        log::warn!("Not dropping privileges -- no user configured");
    } else {
        #[cfg(target_os = "linux")]
        drop_privileges(&runas_user)?;
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = caps::clear(None, CapSet::Ambient) {
        log::warn!("could not set ambient capabilities: {}", e);
    }

    // Initial setup is done at this point.

    log::info!("Started {} running version {}", &args[0], laurel::VERSION);
    log::info!(
        "Running with EUID {} using config {}",
        Uid::effective().as_raw(),
        &config
    );

    let mut coalesce;

    // The two variants produce different types, presumably because
    // they capture different environments.
    let emit_fn_drop;
    let emit_fn_log;

    let mut logger = Logger::new(&config.auditlog, &dir)
        .map_err(|e| format!("can't create audit logger: {}", e))?;

    if let laurel::config::FilterAction::Log = config.filter.filter_action {
        log::info!("Logging filtered audit records");
        let mut filter_logger = Logger::new(&config.filterlog, &dir)
            .map_err(|e| format!("can't create filterlog logger: {}", e))?;
        emit_fn_log = move |e: &Event| {
            if e.filter {
                filter_logger.log(e)
            } else {
                logger.log(e)
            }
        };
        coalesce = Coalesce::new(emit_fn_log);
    } else {
        log::info!("Dropping filtered audit records");
        emit_fn_drop = move |e: &Event| {
            if !e.filter {
                logger.log(e)
            }
        };
        coalesce = Coalesce::new(emit_fn_drop);
    }

    coalesce.settings = config.make_coalesce_settings();
    coalesce.initialize()?;

    let mut line: Vec<u8> = Vec::new();
    let mut stats = Stats::default();
    let mut overall_stats = Stats::default();

    let statusreport_period = config.statusreport_period.map(Duration::from_secs);
    let mut statusreport_last_t = SystemTime::now();

    let dump_state_period = config.debug.dump_state_period.map(Duration::from_secs);
    let mut dump_state_last_t = SystemTime::now();

    let hup = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&hup))?;

    loop {
        if hup.load(Ordering::Relaxed) {
            let buf = input.buffer();
            let lines = buf.split_inclusive(|c| *c == b'\n');
            log::info!("Got SIGHUP.");
            for line in lines {
                if let Err(e) = coalesce.process_line(line.to_vec()) {
                    if let Some(ref mut l) = error_logger {
                        l.write_all(line)
                            .and_then(|_| l.flush())
                            .map_err(|e| format!("write log: {}", e))?;
                    }
                    let line = String::from_utf8_lossy(line).replace('\n', "");
                    log::error!("Error {} processing msg: {}", e, &line);
                }
            }
            coalesce.flush();
            log::info!("Restarting...");
            use std::ffi::CString;
            let argv: Vec<CString> = env::args().map(|a| CString::new(a).unwrap()).collect();
            let env: Vec<CString> = env::vars()
                .map(|(k, v)| CString::new(format!("{}={}", k, v)).unwrap())
                .collect();

            #[cfg(target_os = "linux")]
            {
                let mut capabilities = std::collections::HashSet::new();
                capabilities.insert(Capability::CAP_SYS_PTRACE);
                capabilities.insert(Capability::CAP_DAC_READ_SEARCH);
                if let Err(e) = caps::set(None, CapSet::Ambient, &capabilities) {
                    log::warn!("could not set ambient capabilities: {}", e);
                }
            }
            execve(&argv[0], &argv, &env)?;
        }

        line.clear();
        if input
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("read from stdin: {}", e))?
            == 0
        {
            break;
        }

        stats.lines += 1;
        match coalesce.process_line(line.clone()) {
            Ok(()) => (),
            Err(e) => {
                stats.errors += 1;
                if let Some(ref mut l) = error_logger {
                    l.write_all(&line)
                        .and_then(|_| l.flush())
                        .map_err(|e| format!("write log: {}", e))?;
                }
                let line = String::from_utf8_lossy(&line).replace('\n', "");
                log::error!("Error {} processing msg: {}", e, &line);
                continue;
            }
        };

        // Output status information about Laurel every "statusreport_period_t" time (configurable)
        if let Some(statusreport_period_t) = statusreport_period {
            if statusreport_period_t.as_secs() > 0
                && statusreport_last_t.elapsed()? >= statusreport_period_t
            {
                log::info!("Laurel version {}", laurel::VERSION);
                log::info!(
                    "Parsing stats (until now): processed {} lines {} events with {} errors in total",
                    &stats.lines, &stats.events, &stats.errors );
                log::info!(
                    "Running with EUID {} using config {}",
                    Uid::effective().as_raw(),
                    &config
                );
                overall_stats += stats;
                stats = Stats::default();
                statusreport_last_t = SystemTime::now();
            }
        }

        if let (Some(dl), Some(p)) = (&mut debug_logger, &dump_state_period) {
            if dump_state_last_t.elapsed()? >= *p {
                coalesce
                    .dump_state(&mut dl.output)
                    .map_err(|e| format!("dump state: {}", e))?;
                dump_state_last_t = SystemTime::now();
            }
        }
    }

    // If periodical reports were enabled, stats only contains temporary statistics.
    if let Some(statusreport_period_t) = statusreport_period {
        if statusreport_period_t.as_secs() > 0 {
            stats = overall_stats;
        }
    }

    log::info!(
        "Stopped {} processed {} lines {} events with {} errors in total",
        &args[0],
        &stats.lines,
        &stats.events,
        &stats.errors,
    );

    Ok(())
}

pub fn main() {
    log::set_boxed_logger(Box::<logger::Logger>::default()).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    {
        std::panic::set_hook(Box::new(move |panic_info| {
            let payload = panic_info.payload();
            let message = if let Some(s) = payload.downcast_ref::<&str>() {
                s
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s
            } else {
                "(unknown error)"
            };
            let location = match panic_info.location() {
                Some(l) => format!("{}:{},{}", l.file(), l.line(), l.column()),
                None => "(unknown)".to_string(),
            };
            let e = format!("fatal error '{}' at {}", &message, &location);
            log::error!("{}", &e);
        }));
    }

    match run_app() {
        Ok(_) => (),
        Err(e) => {
            let e = e.to_string();
            log::error!("{}", &e);
            std::process::abort();
        }
    };
}
