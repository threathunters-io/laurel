use aho_corasick::{AhoCorasick, Input};
use itertools::chain;
use std::iter::once;

#[derive(Clone)]
pub struct EnvMatcher(AhoCorasick);

/// EnvMatcher is an Aho-Corasick-based multi-string matcher for
/// environment variables that supports both exact and prefix
/// matching.
impl EnvMatcher {
    /// Constructs an `EnvMatcher`. `exact` and `prefix` contain byte
    /// strings for exact and prefix matches, respectively.
    pub fn new<I1, I2, V1, V2>(exact: I1, prefix: I2) -> Self
    where
        I1: std::iter::IntoIterator<Item = V1>,
        I2: std::iter::IntoIterator<Item = V2>,
        V1: AsRef<[u8]>,
        V2: AsRef<[u8]>,
    {
        // A `=` is appended to variable names that have to match exactly.
        // Nothing is appended to variable names for prefix matches.
        // All variable names are prefixed with a `\0`. The
        // environment block has to start with a null byte for this
        // readon.
        let match_strings = Vec::from_iter(chain(
            exact.into_iter().map(|search_term| {
                Vec::from_iter(chain!(once(&0), search_term.as_ref(), once(&b'=')).cloned())
            }),
            prefix
                .into_iter()
                .map(|search_term| Vec::from_iter(chain(once(&0), search_term.as_ref()).cloned())),
        ));

        Self(AhoCorasick::builder().build(match_strings).unwrap())
    }

    /// Applies matcher to environment block read from
    /// `/proc/$PID/environ` and prepended with a null byte. Returns name/value pairs.
    pub fn find_in_env_block<'a>(&self, block: &'a [u8]) -> Vec<(&'a [u8], &'a [u8])> {
        let input = Input::new(block);
        let mut res = vec![];
        for m in self.0.find_iter(input) {
            let mut key = m.range();
            // Strip leading '\0' at beginning of key
            key.start += 1;
            // Find '=', '\0'
            let offset = key.start.max(key.end - 1);
            let rest = &block[offset..block.len()];
            let (mut eq_pos, mut null_pos) = (None, None);
            for pos in memchr::memchr2_iter(b'\0', b'=', rest) {
                if rest[pos] == b'=' {
                    if eq_pos.is_none() {
                        eq_pos = Some(pos);
                    }
                } else {
                    if eq_pos.is_some() {
                        null_pos = Some(pos);
                    }
                    break;
                }
            }
            // If '\0' or end-of-buffer is found before '=', ignore
            // the broken variable declaration.
            let (Some(eq_pos), Some(null_pos)) = (eq_pos, null_pos) else {
                continue;
            };
            key.end = offset + eq_pos;
            let value = key.end + 1..offset + null_pos;
            res.push((&block[key], &block[value]));
        }
        res
    }
}

#[cfg(test)]
mod test {
    use super::*;

    lazy_static::lazy_static! {
        pub static ref PROC_ENV: Vec<u8> = br#"
USER=user
XDG_SEAT=seat0
XDG_SESSION_TYPE=wayland
XCURSOR_SIZE=24
HOME=/home/user
MOZ_ENABLE_WAYLAND=1
SWAYSOCK=/run/user/1000/sway-ipc.1000.3483.sock
DESKTOP_SESSION=sway
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
MOZ_GMP_PATH=/var/lib/widevine/gmp-widevinecdm/system-installed
WAYLAND_DISPLAY=wayland-1
LOGNAME=user
XDG_SESSION_CLASS=user
USERNAME=user
XDG_SESSION_ID=2
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
GDM_LANG=en_US.UTF-8
XDG_RUNTIME_DIR=/run/user/1000
DISPLAY=:0
LANG=en_US.UTF-8
XDG_CURRENT_DESKTOP=sway
XDG_SESSION_DESKTOP=sway
SSH_AUTH_SOCK=/run/user/1000/openssh_agent
SHELL=/bin/bash
GDMSESSION=sway
QT_ACCESSIBILITY=1
GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1
XDG_VTNR=2
PWD=/home/user
I3SOCK=/run/user/1000/sway-ipc.1000.3483.sock
TERM=foot
COLORTERM=truecolor
LD_PRELOAD=/dev/null
=
"#
        .into_iter()
        .map(|c| if *c == b'\n' { 0 } else { *c })
        .collect();
    }

    #[test]
    fn simple_matches() {
        let matcher = EnvMatcher::new(["LD_PRELOAD", "LD_LIBRARY_PATH"], ["XDG_"]);
        let env = matcher.find_in_env_block(&PROC_ENV);
        println!(
            "{:?}",
            env.iter()
                .map(|(k, v)| (String::from_utf8_lossy(k), String::from_utf8_lossy(v)))
                .collect::<Vec<_>>()
        );

        assert!(env.contains(&("LD_PRELOAD".as_bytes(), "/dev/null".as_bytes())));

        assert!(env.contains(&("XDG_CURRENT_DESKTOP".as_bytes(), "sway".as_bytes())));
        assert!(env.contains(&("XDG_RUNTIME_DIR".as_bytes(), "/run/user/1000".as_bytes())));
        assert!(env.contains(&("XDG_SEAT".as_bytes(), "seat0".as_bytes())));
        assert!(env.contains(&("XDG_SESSION_CLASS".as_bytes(), "user".as_bytes())));
        assert!(env.contains(&("XDG_SESSION_DESKTOP".as_bytes(), "sway".as_bytes())));
        assert!(env.contains(&("XDG_SESSION_ID".as_bytes(), "2".as_bytes())));
        assert!(env.contains(&("XDG_SESSION_TYPE".as_bytes(), "wayland".as_bytes())));
        assert!(env.contains(&("XDG_VTNR".as_bytes(), "2".as_bytes())));
    }

    #[test]
    fn empty_key() {
        let empty: &[&str] = &[];
        let matcher = EnvMatcher::new([""], empty);
        let env = matcher.find_in_env_block(&PROC_ENV);
        assert!(!env.is_empty());
        assert!(env.contains(&("".as_bytes(), "".as_bytes())));
    }

    #[test]
    fn empty_prefix() {
        let empty: &[&str] = &[];
        let matcher = EnvMatcher::new(empty, [""]);
        let env = matcher.find_in_env_block(&PROC_ENV);
        assert!(!env.is_empty());
        assert!(env.contains(&("".as_bytes(), "".as_bytes())));
    }
}
