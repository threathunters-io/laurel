use std::path::PathBuf;
use std::collections::HashSet;

use serde::{Serialize,Deserialize};

#[derive(Clone,Debug,Serialize,Deserialize,PartialEq)]
pub struct Logfile {
    pub file: PathBuf,
    #[serde(rename="read-users")]
    pub users: Option<Vec<String>>,
    pub size: Option<u64>,
    pub generations: Option<u64>,
}

#[derive(PartialEq,Eq,Debug,Serialize,Deserialize,Hash)]
#[serde(rename_all = "lowercase")]
pub enum ArrayOrString { Array, String }

#[derive(Debug,Serialize,Deserialize)]
pub struct Transform {
    #[serde(rename="execve-argv")] #[serde(default)]
    pub execve_argv: HashSet<ArrayOrString>
}

impl Default for Transform {
    fn default() -> Self {
        let mut execve_argv = HashSet::new();
        execve_argv.insert(ArrayOrString::Array);
        Transform { execve_argv }
    }
}

#[derive(Debug,Default,Serialize,Deserialize)]
pub struct Translate {
    pub universal: bool,
    #[serde(rename="user-db")]
    pub userdb: bool,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct Enrich {
    #[serde(rename="execve-env")] #[serde(default)]
    pub execve_env: HashSet<String>
}

impl Default for Enrich {
    fn default() -> Self {
        let mut execve_env = HashSet::new();
        execve_env.insert("LD_PRELOAD".into());
        execve_env.insert("LD_LIBRARY_PATH".into());
        Enrich { execve_env }
    }
}

#[derive(Default,Debug,Serialize,Deserialize)]
pub struct LabelProcess {
    #[serde(rename="label-keys")]
    pub label_keys: HashSet<String>,
    #[serde(rename="propagate-labels")]
    pub propagate_labels: HashSet<String>,
}

#[derive(Default,Debug,Serialize,Deserialize)]
pub struct Filter {}

#[derive(Debug,Serialize,Deserialize)]
pub struct Config {
    pub user: Option<String>,
    pub directory: Option<PathBuf>,
    #[serde(rename="statusreport-period")] #[serde(default)]
    pub statusreport_period: Option<u64>,
    pub auditlog: Logfile,
    pub debuglog: Option<Logfile>,
    #[serde(default)]
    pub transform: Transform,
    #[serde(default)]
    pub translate: Translate,
    #[serde(default)]
    pub enrich: Enrich,
    #[serde(default,rename="label-process")]
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
                size: None,
                generations: None,
            },
            debuglog: None,
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
        write!(fmt, "(user={} directory={} statusreport-period={} file={} users={} size={} generations={})",
               self.user.clone().unwrap_or("n/a".to_string()),
               self.directory.clone().unwrap_or_else(||PathBuf::from(".")).display(),
               self.statusreport_period.unwrap_or(0),
               self.auditlog.file.to_string_lossy(),
               self.auditlog.users.clone().unwrap_or(vec!["n/a".to_string()]).join(","),
               self.auditlog.size.unwrap_or(10*1024*1024),
               self.auditlog.generations.unwrap_or(5)
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::Path;

    #[test]
    fn simple() {
        let c: Config = toml::de::from_str(r#"
user = "somebody"
directory = "/path/to/somewhere"
statusreport-period = 86400
[auditlog]
file = "somefile"
read-users = ["splunk"]
"#).unwrap();
        println!("{:#?}", &c);
        assert_eq!(c.user, Some("somebody".to_string()));
        assert_eq!(c.directory, Some(Path::new("/path/to/somewhere").to_path_buf()));
        assert_eq!(c.statusreport_period, Some(86400));
        assert_eq!(c.auditlog, Logfile{
            file: Path::new("somefile").to_path_buf(),
            users: Some(vec!["splunk".to_string()]),
            size: None, generations: None,
        });
    }
}
