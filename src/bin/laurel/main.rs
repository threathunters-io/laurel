//! Laurel is an "audisp" plugin plugins that consume data fed by the
//! the Linux Audit daemon and reformats events as JSON Lines.

use getopts::Options;
use std::env;
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

use anyhow::{anyhow, Context};

use nix::sys::signal::{sigprocmask, SigSet, SigmaskHow::*, Signal::*};
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
fn drop_privileges(runas_user: &User) -> anyhow::Result<()> {
    set_keepcaps(true)?;
    let uid = runas_user.uid;
    let gid = runas_user.gid;
    setresgid(gid, gid, gid).with_context(|| format!("setresgid({gid})"))?;
    setresuid(uid, uid, uid).with_context(|| format!("setresuid({uid})"))?;

    #[cfg(feature = "procfs")]
    {
        let mut capabilities = std::collections::HashSet::new();
        capabilities.insert(Capability::CAP_SYS_PTRACE);
        capabilities.insert(Capability::CAP_DAC_READ_SEARCH);
        caps::set(None, CapSet::Permitted, &capabilities).context("set permitted capabilities")?;
        caps::set(None, CapSet::Effective, &capabilities).context("set effective capabilities")?;
        caps::set(None, CapSet::Inheritable, &capabilities)
            .context("set inheritable capabilities")?;
    }

    set_keepcaps(false)?;
    Ok(())
}

struct Logger {
    prefix: Option<String>,
    output: BufWriter<Box<dyn Write>>,
}

impl Logger {
    fn log<S: Serialize>(&mut self, message: S) -> std::io::Result<()> {
        if let Some(prefix) = &self.prefix {
            self.output.write_all(prefix.as_bytes())?;
        }
        laurel::json::to_writer(&mut self.output, &message)?;
        self.output.write_all(b"\n")?;
        self.output.flush()
    }

    fn new(def: &Logfile, dir: &Path) -> anyhow::Result<Self> {
        match &def.file {
            p if p.as_os_str().to_str().unwrap().starts_with('|') => {
                let command = &p.as_os_str().to_str().unwrap()[1..].trim_start();
                let mut child = std::process::Command::new(command)
                    .stdin(std::process::Stdio::piped())
                    .spawn()
                    .map_err(|e| anyhow!("failed to start process: {}", e))?;
                let stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| anyhow!("failed to open stdin"))?;
                Ok(Logger {
                    prefix: def.line_prefix.clone(),
                    output: BufWriter::new(Box::new(stdin)),
                })
            }
            p if p.as_os_str() == "-" => Ok(Logger {
                prefix: def.line_prefix.clone(),
                output: BufWriter::new(Box::new(io::stdout())),
            }),
            p if p.has_root() && p.parent().is_none() => Err(anyhow!(
                "invalid file directory={} file={}",
                dir.to_string_lossy(),
                p.to_string_lossy()
            )),
            p => {
                let mut filename = dir.to_path_buf();
                filename.push(p);
                let mut rot = FileRotate::new(filename);
                for user in &def.clone().users.unwrap_or_default() {
                    _ = User::from_name(user)?.ok_or_else(|| anyhow!("user {user} not found"))?;
                    rot = rot.with_user(user);
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

fn run_app() -> Result<(), anyhow::Error> {
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
        Some(f) => {
            if fs::metadata(&f)
                .with_context(|| format!("stat {f}"))?
                .permissions()
                .mode()
                & 0o002
                != 0
            {
                return Err(anyhow!("Config file {f} must not be world-writable"));
            }
            let lines = fs::read(&f).with_context(|| format!("Error reading {f}"))?;
            toml::from_str(&String::from_utf8(lines).with_context(|| format!("Error parsing {f}"))?)
                .with_context(|| format!("Error parsing {f}"))?
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
                .with_context(|| format!("Error connecting to {}", path.to_string_lossy()))?,
        ),
    };

    // std::io::Stdin's buffer is only 8KB, so we construct our own.
    // 1MB ought to be enough for anybody.
    let mut input = BufReader::with_capacity(1 << 20, raw_input);

    let runas_user = match config.user {
        Some(ref username) => {
            User::from_name(username)?.ok_or_else(|| anyhow!("user {username} not found"))?
        }
        None => {
            let uid = Uid::effective();
            User::from_uid(uid)?.ok_or_else(|| anyhow!("uid {uid} not found"))?
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
            return Err(anyhow!("{} is not a directory", dir.to_string_lossy()));
        }
        if dir
            .metadata()
            .with_context(|| format!("stat {}", dir.to_string_lossy()))?
            .permissions()
            .mode()
            & 0o002
            != 0
        {
            log::warn!(
                "Base directory {} must not be world-writable",
                dir.to_string_lossy()
            );
        }
    } else {
        fs::create_dir_all(&dir)
            .with_context(|| format!("create_dir: {}", dir.to_string_lossy()))?;
    }
    chown(&dir, Some(runas_user.uid), Some(runas_user.gid))
        .with_context(|| format!("chown: {}", dir.to_string_lossy()))?;
    fs::set_permissions(&dir, PermissionsExt::from_mode(0o755))
        .with_context(|| format!("chmod: {}", dir.to_string_lossy()))?;

    let mut debug_logger = if let Some(l) = &config.debug.log {
        Some(Logger::new(l, &dir).context("can't create debug logger")?)
    } else {
        None
    };
    let mut error_logger = if let Some(def) = &config.debug.parse_error_log {
        let mut filename = dir.clone();
        filename.push(&def.file);
        let mut rot = FileRotate::new(filename);
        for user in &def.clone().users.unwrap_or_default() {
            _ = User::from_name(user)?.ok_or_else(|| anyhow!("user {user} not found"))?;
            rot = rot.with_user(user);
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
        log::warn!("could not set ambient capabilities: {e}");
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

    let mut logger = Logger::new(&config.auditlog, &dir).context("can't create audit logger")?;

    if let laurel::config::FilterAction::Log = config.filter.filter_action {
        log::info!("Logging filtered audit records");
        let mut filter_logger =
            Logger::new(&config.filterlog, &dir).context("can't create filterlog logger")?;
        emit_fn_log = move |e: &Event| {
            if e.filter {
                filter_logger
                    .log(e)
                    .map_err(|e| anyhow!("Error writing to filter log: {e}"))
                    .unwrap();
            } else {
                logger
                    .log(e)
                    .map_err(|e| anyhow!("Error writing to audit log: {e}"))
                    .unwrap();
            }
        };
        coalesce = Coalesce::new(emit_fn_log);
    } else {
        log::info!("Dropping filtered audit records");
        emit_fn_drop = move |e: &Event| {
            if !e.filter {
                logger
                    .log(e)
                    .map_err(|e| anyhow!("Error writing to audit log: {e}"))
                    .unwrap();
            }
        };
        coalesce = Coalesce::new(emit_fn_drop);
    }

    let mut inputlog = if let Some(ref w) = config.debug.inputlog {
        Some(Logger::new(w, &dir).context("can't create inputlog logger")?)
    } else {
        None
    };

    coalesce.settings = config.make_coalesce_settings();
    coalesce.initialize().context("Failed to initialize")?;

    let mut line: Vec<u8> = Vec::new();
    let mut stats = Stats::default();
    let mut overall_stats = Stats::default();

    let statusreport_period = config.statusreport_period.map(Duration::from_secs);
    let mut statusreport_last_t = SystemTime::now();

    let dump_state_period = config.debug.dump_state_period.map(Duration::from_secs);
    let mut dump_state_last_t = SystemTime::now();

    sigprocmask(SIG_UNBLOCK, Some(&SigSet::from_iter([SIGHUP])), None)?;
    let hup = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&hup))?;

    loop {
        if hup.load(Ordering::Relaxed) {
            let buf = input.buffer();
            let lines = buf.split_inclusive(|c| *c == b'\n');
            log::info!("Got SIGHUP.");
            for line in lines {
                if let Err(e) = coalesce.process_line(line) {
                    if let Some(ref mut l) = error_logger {
                        l.write_all(line)
                            .and_then(|_| l.flush())
                            .context("write log")?;
                    }
                    let line = String::from_utf8_lossy(line).replace('\n', "");
                    log::error!("Error {e} processing msg: {line}");
                }
            }
            coalesce.flush();
            log::info!("Restarting...");
            use std::ffi::CString;
            let argv: Vec<CString> = env::args().map(|a| CString::new(a).unwrap()).collect();
            let env: Vec<CString> = env::vars()
                .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
                .collect();

            #[cfg(target_os = "linux")]
            {
                let mut capabilities = std::collections::HashSet::new();
                capabilities.insert(Capability::CAP_SYS_PTRACE);
                capabilities.insert(Capability::CAP_DAC_READ_SEARCH);
                if let Err(e) = caps::set(None, CapSet::Ambient, &capabilities) {
                    log::warn!("could not set ambient capabilities: {e}");
                }
            }
            execve(&argv[0], &argv, &env)?;
        }

        line.clear();
        if input
            .read_until(b'\n', &mut line)
            .context("read from stdin")?
            == 0
        {
            break;
        }

        if let Some(ref mut l) = inputlog {
            l.output.write_all(&line)?;
            l.output.flush()?;
        }

        stats.lines += 1;
        match coalesce.process_line(&line) {
            Ok(()) => (),
            Err(e) => {
                stats.errors += 1;
                if let Some(ref mut l) = error_logger {
                    l.write_all(&line)
                        .and_then(|_| l.flush())
                        .context("write log")?;
                }
                let line = String::from_utf8_lossy(&line).replace('\n', "");
                log::error!("Error {e} processing msg: {line}");
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
                    .map_err(|e| anyhow!("dump state: {e}"))?;
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

    #[cfg(debug_assertions)]
    log::set_max_level(log::LevelFilter::Debug);
    #[cfg(not(debug_assertions))]
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
            log::error!("fatal error '{message}' at {location}");
        }));
    }

    match run_app() {
        Ok(_) => (),
        Err(e) => {
            log::error!("{e:#}");
            std::process::exit(1);
        }
    };
}
