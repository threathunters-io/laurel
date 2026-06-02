use aho_corasick::{AhoCorasick, Anchored, Input, StartKind};
use tinyvec::TinyVec;

#[derive(Clone)]
pub struct EnvMatcher(AhoCorasick);

impl Default for EnvMatcher {
    fn default() -> Self {
        let empty: &[&[u8]] = &[];
        Self(
            AhoCorasick::builder()
                .start_kind(StartKind::Anchored)
                .build(empty)
                .unwrap(),
        )
    }
}

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
        let match_strings = Vec::from_iter(
            exact
                .into_iter()
                .map(|s| {
                    let mut v = Vec::from(s.as_ref());
                    v.push(b'=');
                    v
                })
                .chain(prefix.into_iter().map(|s| Vec::from(s.as_ref()))),
        );

        Self(
            AhoCorasick::builder()
                .start_kind(StartKind::Anchored)
                .build(match_strings)
                .unwrap(),
        )
    }

    /// Retrurns true if matcher recocnizes `key`.
    ///
    /// Note: The equals sisgn `=` cannot be part of keys.
    pub fn matches(&self, key: &[u8]) -> bool {
        let mut key = TinyVec::<[u8; 32]>::from(key);
        key.push(b'=');
        self.0
            .find(Input::new(&key).anchored(Anchored::Yes))
            .is_some()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn simple_matches() {
        let matcher = EnvMatcher::new(["LD_PRELOAD", "LD_LIBRARY_PATH"], ["XDG_"]);
        assert!(matcher.matches(b"XDG_"));
        assert!(matcher.matches(b"XDG_foo"));
        assert!(matcher.matches(b"XDG_bar"));
        assert!(!matcher.matches(b"nomatch_XDG_"));
        assert!(matcher.matches(b"LD_PRELOAD"));
        assert!(!matcher.matches(b"nomatch_LD_PRELOAD"));
        assert!(!matcher.matches(b"LD_PRELOAD_nomatch"));
        assert!(!matcher.matches(b"nomatch"));
    }

    #[test]
    fn default() {
        let matcher = EnvMatcher::default();
        assert!(!matcher.matches(b"nomatch"));
        assert!(!matcher.matches(b""));
    }
}
