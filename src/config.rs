use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{
    de::{self, Deserializer, Visitor},
    Deserialize, Serialize,
};

use crate::coalesce::Settings;
use crate::label_matcher::LabelMatcher;

fn default_state_file() -> Option<PathBuf> {
    Some(Path::new("state").into())
}

fn deserialize_state_file<'de, D>(d: D) -> Result<Option<PathBuf>, D::Error>
where
    D: Deserializer<'de>,
{
    match PathBuf::deserialize(d)? {
        p if p == PathBuf::default() => Ok(None),
        p => Ok(Some(p)),
    }
}

const fn default_state_max_age() -> u64 {
    60
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Statefile {
    #[serde(
        default = "default_state_file",
        deserialize_with = "deserialize_state_file"
    )]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub generations: u64,
    #[serde(rename = "max-age")]
    #[serde(default = "default_state_max_age")]
    pub max_age: u64,
    #[serde(rename = "write-state-period")]
    pub write_state_period: Option<u64>,
}

impl Default for Statefile {
    fn default() -> Self {
        Self {
            file: default_state_file(),
            generations: 0,
            max_age: default_state_max_age(),
            write_state_period: None,
        }
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Logfile {
    #[serde(default)]
    pub file: PathBuf,
    #[serde(rename = "read-users")]
    pub users: Option<Vec<String>>,
    #[serde(rename = "read-groups")]
    pub groups: Option<Vec<String>>,
    #[serde(default, rename = "read-other")]
    pub other: bool,
    pub size: Option<u64>,
    pub generations: Option<u64>,
    #[serde(rename = "line-prefix")]
    pub line_prefix: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct Debug {
    pub inputlog: Option<Logfile>,
    #[serde(rename = "parse-error-log")]
    pub parse_error_log: Option<Logfile>,
}

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ArrayOrString {
    Array,
    String,
}

fn execve_argv_default() -> HashSet<ArrayOrString> {
    let mut execve_argv = HashSet::new();
    execve_argv.insert(ArrayOrString::Array);
    execve_argv
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transform {
    #[serde(default = "execve_argv_default", rename = "execve-argv")]
    pub execve_argv: HashSet<ArrayOrString>,
    #[serde(default, rename = "execve-argv-limit-bytes")]
    pub execve_argv_limit_bytes: Option<usize>,
}

impl Default for Transform {
    fn default() -> Self {
        Transform {
            execve_argv: execve_argv_default(),
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
    #[serde(default, rename = "drop-raw")]
    pub drop_raw: bool,
}

fn execve_env_default() -> HashSet<String> {
    let mut execve_env = HashSet::new();
    execve_env.insert("LD_PRELOAD".into());
    execve_env.insert("LD_LIBRARY_PATH".into());
    execve_env
}

fn true_value() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Enrich {
    #[serde(default = "execve_env_default", rename = "execve-env")]
    pub execve_env: HashSet<String>,
    #[serde(default = "true_value")]
    pub container: bool,
    #[serde(default)]
    pub container_info: bool,
    #[serde(default = "true_value")]
    pub systemd: bool,
    #[serde(default = "true_value")]
    pub pid: bool,
    #[serde(default = "true_value")]
    pub script: bool,
    #[serde(default = "true_value", rename = "uid-groups")]
    pub uid_groups: bool,
    #[serde(default)]
    pub prefix: Option<String>,
}

impl Default for Enrich {
    fn default() -> Self {
        Enrich {
            execve_env: execve_env_default(),
            container: true,
            container_info: false,
            systemd: true,
            pid: true,
            script: true,
            uid_groups: true,
            prefix: None,
        }
    }
}

fn default_32() -> usize {
    32
}
fn default_4096() -> usize {
    4096
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct LabelProcess {
    #[serde(default, rename = "label-keys")]
    pub label_keys: HashSet<String>,
    #[serde(default, rename = "label-exe")]
    pub label_exe: Option<LabelMatcher>,
    #[serde(default, rename = "unlabel-exe")]
    pub unlabel_exe: Option<LabelMatcher>,
    #[serde(default, rename = "label-argv")]
    pub label_argv: Option<LabelMatcher>,
    #[serde(default, rename = "unlabel-argv")]
    pub unlabel_argv: Option<LabelMatcher>,
    #[serde(default = "default_4096", rename = "label-argv-bytes")]
    pub label_argv_bytes: usize,
    #[serde(default = "default_32", rename = "label-argv-count")]
    pub label_argv_count: usize,
    #[serde(default, rename = "label-script")]
    pub label_script: Option<LabelMatcher>,
    #[serde(default, rename = "unlabel-script")]
    pub unlabel_script: Option<LabelMatcher>,
    #[serde(default, rename = "propagate-labels")]
    pub propagate_labels: HashSet<String>,
}

#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    #[default]
    #[serde(alias = "Drop")]
    Drop,
    #[serde(alias = "Log")]
    Log,
}

pub(crate) mod regex_set {
    use regex::bytes::RegexSet;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S>(v: &RegexSet, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        v.patterns().to_vec().serialize(s)
    }
    pub(crate) fn deserialize<'de, D>(d: D) -> Result<RegexSet, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<String> = Deserialize::deserialize(d)?;
        RegexSet::new(v).map_err(serde::de::Error::custom)
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct Filter {
    #[serde(default, rename = "filter-keys")]
    pub filter_keys: HashSet<String>,
    #[serde(default, rename = "filter-labels")]
    pub filter_labels: HashSet<String>,
    #[serde(default, rename = "filter-raw-lines", with = "regex_set")]
    pub filter_raw_lines: regex::bytes::RegexSet,
    #[serde(default, rename = "filter-null-keys")]
    pub filter_null_keys: bool,
    #[serde(default, rename = "filter-action")]
    pub filter_action: FilterAction,
    #[serde(default = "true_value", rename = "keep-first-per-process")]
    pub keep_first_per_process: bool,
}

#[derive(Debug, Serialize, Default)]
pub enum Input {
    #[default]
    Stdin,
    Unix(PathBuf),
}

impl std::fmt::Display for Input {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Input::Stdin => write!(fmt, "stdin"),
            Input::Unix(p) => write!(fmt, "unix:{}", p.to_string_lossy()),
        }
    }
}

impl<'de> Deserialize<'de> for Input {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(InputVisitor {})
    }
}

struct InputVisitor {}

impl Visitor<'_> for InputVisitor {
    type Value = Input;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "an input specification string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if s == "stdin" {
            Ok(Input::Stdin)
        } else if let Some(s) = s.strip_prefix("unix:") {
            let p = Path::new(s).to_path_buf();
            Ok(Input::Unix(p))
        } else {
            Err(de::Error::custom("unrecognized input specification"))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub user: Option<String>,
    pub directory: Option<PathBuf>,
    #[serde(default)]
    pub input: Input,
    #[serde(default, rename = "statusreport-period")]
    pub statusreport_period: Option<u64>,
    #[serde(default)]
    pub marker: Option<String>,
    #[serde(default)]
    pub state: Statefile,
    #[serde(default)]
    pub auditlog: Logfile,
    #[serde(default)]
    pub filterlog: Logfile,
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
            input: Input::Stdin,
            statusreport_period: None,
            marker: None,
            state: Statefile {
                file: Some("state".into()),
                generations: 3,
                max_age: 60,
                write_state_period: None,
            },
            auditlog: Logfile {
                file: "audit.log".into(),
                size: Some(10 * 1024 * 1024),
                generations: Some(5),
                ..Logfile::default()
            },
            filterlog: Logfile {
                file: "filtered.log".into(),
                size: Some(10 * 1024 * 1024),
                generations: Some(5),
                ..Logfile::default()
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
            "({}user={} directory={} statusreport-period={} file={} users={} size={} generations={})",
            self.marker.as_ref().map(|m| format!("marker={m} ")).unwrap_or("".to_string()),
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
            enrich_container_info: self.enrich.container_info,
            enrich_systemd: self.enrich.systemd,
            enrich_pid: self.enrich.pid,
            enrich_script: self.enrich.script,
            enrich_uid_groups: self.enrich.uid_groups,
            enrich_prefix: self.enrich.prefix.clone(),
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
            drop_translated: self.translate.drop_raw,
            label_exe: self.label_process.label_exe.clone(),
            unlabel_exe: self.label_process.unlabel_exe.clone(),
            label_argv: self.label_process.label_argv.clone(),
            unlabel_argv: self.label_process.unlabel_argv.clone(),
            label_argv_bytes: self.label_process.label_argv_bytes,
            label_argv_count: self.label_process.label_argv_count,
            label_script: self.label_process.label_script.clone(),
            unlabel_script: self.label_process.unlabel_script.clone(),
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
            filter_null_keys: self.filter.filter_null_keys,
            filter_raw_lines: self.filter.filter_raw_lines.clone(),
            filter_first_per_process: !self.filter.keep_first_per_process,
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
[state]
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
                ..Logfile::default()
            }
        );
        assert_eq!(
            c.state,
            Statefile {
                file: Some(Path::new("state").into()),
                ..Statefile::default()
            }
        );
    }

    #[test]
    fn parse_defaults() {
        let cfg_default = toml::de::from_str::<Config>("").unwrap();
        println!("{}", toml::to_string(&cfg_default).unwrap());

        println!("--------------------");

        let cfg_empty_sections = toml::de::from_str::<Config>(
            r#"
[auditlog]
[filterlog]
[state]
[debug]
[transform]
[translate]
[enrich]
[label-process]
[filter]
"#,
        )
        .unwrap();
        println!("{}", toml::to_string(&cfg_empty_sections).unwrap());

        // FIXME This does not work because HashSet ordering is not stable.
        // assert!(toml::to_string(&cfg_default) == toml::to_string(&cfg_empty_sections));
    }

    #[test]
    fn statefile() {
        let cfg: Config = toml::de::from_str(
            r#"
[state] 
file = ""
"#,
        )
        .expect("toml parse error");
        assert_eq!(cfg.state.file, None);
    }
}
