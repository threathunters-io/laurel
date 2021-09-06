use std::path::PathBuf;

use serde::{Serialize,Deserialize};

#[derive(Clone,Debug,Serialize,Deserialize,PartialEq)]
pub struct Logfile {
    pub file: PathBuf,
    #[serde(rename="read-users")]
    pub users: Option<Vec<String>>,
    pub size: Option<u64>,
    pub generations: Option<u64>,
}

#[derive(Debug,Serialize,Deserialize)]
pub struct Config {
    pub user: Option<String>,
    pub directory: Option<PathBuf>,
    pub auditlog: Logfile,
    pub debuglog: Option<Logfile>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            user: None,
            directory: Some(".".into()),
            auditlog: Logfile {
                file: "audit.log".into(),
                users: None,
                size: None,
                generations: None,
            },
            debuglog: None,
        }
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
[auditlog]
file = "somefile"
read-users = ["splunk"]
"#).unwrap();
        println!("{:#?}", &c);
        assert_eq!(c.user, Some("somebody".to_string()));
        assert_eq!(c.directory, Some(Path::new("/path/to/somewhere").to_path_buf()));
        assert_eq!(c.auditlog, Logfile{
            file: Path::new("somefile").to_path_buf(),
            users: Some(vec!["splunk".to_string()]),
            size: None, generations: None,
        });
    }
}
