use std::env::args;
use std::ffi::OsStr;
use std::path::PathBuf;

use log;
use simple_logger;
use syslog;

pub struct Logger {
    simple: simple_logger::SimpleLogger,
    syslog: Option<syslog::BasicLogger>,
}

impl Default for Logger {
    fn default() -> Self {
        let cmd: PathBuf = args().next().unwrap_or_else(|| "<laurel>".into()).into();

        let simple = simple_logger::SimpleLogger::new();

        let syslog = syslog::unix(syslog::Formatter3164 {
            facility: syslog::Facility::LOG_DAEMON,
            hostname: None,
            process: cmd
                .file_name()
                .unwrap_or_else(|| OsStr::new(""))
                .to_string_lossy()
                .into(),
            pid: std::process::id(),
        })
        .map(|sl| syslog::BasicLogger::new(sl))
        .ok();

        Logger { simple, syslog }
    }
}

impl log::Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        self.simple.log(record);
        self.syslog.as_ref().map(|l| l.log(record));
    }
    fn flush(&self) {
        self.simple.flush();
        self.syslog.as_ref().map(|l| l.flush());
    }
}
