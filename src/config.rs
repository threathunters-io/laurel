use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::coalesce::Settings;
use crate::label_matcher::LabelMatcher;

#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct Logfile {
    #[serde(default)]
    pub file: PathBuf,
    #[serde(rename = "read-users")]
    pub users: Option<Vec<String>>,
    pub size: Option<u64>,
    pub generations: Option<u64>,
    #[serde(rename = "line-prefix")]
    pub line_prefix: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Debug {
    pub log: Option<Logfile>,
    #[serde(rename = "dump-state-period")]
    pub dump_state_period: Option<u64>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ArrayOrString {
    Array,
    String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transform {
    #[serde(default, rename = "execve-argv")]
    pub execve_argv: HashSet<ArrayOrString>,
    #[serde(default, rename = "execve-argv-limit-bytes")]
    pub execve_argv_limit_bytes: Option<usize>,
}

impl Default for Transform {
    fn default() -> Self {
        let mut execve_argv = HashSet::new();
        execve_argv.insert(ArrayOrString::Array);
        Transform {
            execve_argv,
            execve_argv_limit_bytes: None,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Translate {
    #[serde(default)]
    pub universal: bool,
    #[serde(default, rename = "user-db")]
    pub userdb: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Enrich {
    #[serde(default, rename = "execve-env")]
    pub execve_env: HashSet<String>,
    #[serde(default)]
    pub container: bool,
    pub pid: bool,
}

impl Default for Enrich {
    fn default() -> Self {
        let mut execve_env = HashSet::new();
        execve_env.insert("LD_PRELOAD".into());
        execve_env.insert("LD_LIBRARY_PATH".into());
        Enrich {
            execve_env,
            container: false,
            pid: true,
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct LabelProcess {
    #[serde(default, rename = "label-keys")]
    pub label_keys: HashSet<String>,
    #[serde(default, rename = "label-exe")]
    pub label_exe: Option<LabelMatcher>,
    #[serde(default, rename = "propagate-labels")]
    pub propagate_labels: HashSet<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default, rename = "filter-keys")]
    pub filter_keys: HashSet<String>,
    #[serde(default, rename = "filter-labels")]
    pub filter_labels: HashSet<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub user: Option<String>,
    pub directory: Option<PathBuf>,
    #[serde(default, rename = "statusreport-period")]
    pub statusreport_period: Option<u64>,
    #[serde(default)]
    pub auditlog: Logfile,
    #[serde(default)]
    pub debug: Debug,
    #[serde(default)]
    pub transform: Transform,
    #[serde(default)]
    pub translate: Translate,
    #[serde(default)]
    pub enrich: Enrich,
    #[serde(default, rename = "label-process")]
    pub label_process: LabelProcess,
    #[serde(default)]
    pub filter: Filter,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            user: None,
            directory: Some(".".into()),
            statusreport_period: None,
            auditlog: Logfile {
                file: "audit.log".into(),
                users: None,
                size: Some(10 * 1024 * 1024),
                generations: Some(5),
                line_prefix: None,
            },
            debug: Debug::default(),
            transform: Transform::default(),
            translate: Translate::default(),
            enrich: Enrich::default(),
            label_process: LabelProcess::default(),
            filter: Filter::default(),
        }
    }
}

impl std::fmt::Display for Config {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(
            fmt,
            "(user={} directory={} statusreport-period={} file={} users={} size={} generations={})",
            self.user.clone().unwrap_or_else(|| "n/a".to_string()),
            self.directory
                .clone()
                .unwrap_or_else(|| PathBuf::from("."))
                .display(),
            self.statusreport_period.unwrap_or(0),
            self.auditlog.file.to_string_lossy(),
            self.auditlog
                .users
                .clone()
                .unwrap_or_else(|| vec!["n/a".to_string()])
                .join(","),
            self.auditlog.size.unwrap_or(0),
            self.auditlog.generations.unwrap_or(0)
        )
    }
}

impl Config {
    pub fn make_coalesce_settings(&self) -> Settings {
        Settings {
            execve_argv_list: self.transform.execve_argv.contains(&ArrayOrString::Array),
            execve_argv_string: self.transform.execve_argv.contains(&ArrayOrString::String),
            execve_argv_limit_bytes: self.transform.execve_argv_limit_bytes,
            execve_env: self
                .enrich
                .execve_env
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            enrich_container: self.enrich.container,
            enrich_pid: self.enrich.pid,
            proc_label_keys: self
                .label_process
                .label_keys
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            proc_propagate_labels: self
                .label_process
                .propagate_labels
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            translate_universal: self.translate.universal,
            translate_userdb: self.translate.userdb,
            label_exe: self.label_process.label_exe.as_ref(),
            filter_keys: self
                .filter
                .filter_keys
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            filter_labels: self
                .filter
                .filter_labels
                .iter()
                .map(|s| s.as_bytes().to_vec())
                .collect(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::Path;

    #[test]
    fn simple() {
        let c: Config = toml::de::from_str(
            r#"
user = "somebody"
directory = "/path/to/somewhere"
statusreport-period = 86400
[auditlog]
file = "somefile"
read-users = ["splunk"]
"#,
        )
        .unwrap();
        println!("{:#?}", &c);
        assert_eq!(c.user, Some("somebody".to_string()));
        assert_eq!(
            c.directory,
            Some(Path::new("/path/to/somewhere").to_path_buf())
        );
        assert_eq!(c.statusreport_period, Some(86400));
        assert_eq!(
            c.auditlog,
            Logfile {
                file: Path::new("somefile").to_path_buf(),
                users: Some(vec!["splunk".to_string()]),
                size: None,
                generations: None,
                line_prefix: None,
            }
        );
    }

    #[test]
    fn parse_defaults() {
        toml::de::from_str::<Config>("").unwrap();

        toml::de::from_str::<Config>(
            r#"
[auditlog]
[debug]
[transform]
[translate]
[enrich]
[label-process]
[filter]
"#,
        )
        .unwrap();
    }
}
