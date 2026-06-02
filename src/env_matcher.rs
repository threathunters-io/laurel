use std::collections::HashSet;

#[derive(Clone, Default)]
pub struct EnvMatcher {
    exact: HashSet<Vec<u8>>,
    prefix: Vec<Vec<u8>>,
}

/// EnvMatcher is a naïve multi-string matcher that supports both
/// exact and prefix matching.
impl EnvMatcher {
    pub fn new<I, V>(exact: I, prefix: I) -> Self
    where
        I: std::iter::IntoIterator<Item = V>,
        V: Into<Vec<u8>>,
    {
        let exact: HashSet<Vec<u8>> = exact.into_iter().map(|i| i.into()).collect();
        let prefix: Vec<Vec<u8>> = prefix.into_iter().map(|i| i.into()).collect();

        Self { exact, prefix }
    }

    pub fn matches(&self, key: &[u8]) -> bool {
        self.exact.contains(key) || self.prefix.iter().any(|p| key.starts_with(p))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn simple_matches() {
        let matcher = EnvMatcher::new(vec!["LD_PRELOAD", "LD_LIBRARY_PATH"], vec!["XDG_"]);
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
