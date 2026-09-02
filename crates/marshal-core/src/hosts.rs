//! Host matching for the denylist and allowlist layers.
//!
//! Domain patterns are matched label-wise rather than with a general glob, because a glob's
//! `*` happily crosses `.` and would silently make `*.example.com` match
//! `evil.com.example.com.attacker.net` under a careless implementation. The semantics here
//! are deliberately narrow:
//!
//! * `example.com` matches exactly that host.
//! * `*.example.com` matches any **strict** subdomain — `api.example.com`,
//!   `a.b.example.com` — but *not* the apex `example.com`. Listing the apex is a separate,
//!   deliberate act.
//!
//! Matching is case-insensitive and tolerant of a trailing dot (`example.com.` is the same
//! host).

use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

/// A compiled set of domain patterns and CIDR blocks.
#[derive(Debug, Default, Clone)]
pub struct HostMatcher {
    exact: Vec<String>,
    suffix: Vec<String>,
    cidrs: Vec<IpNet>,
}

/// Why a host matched, so the audit trail can name the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchKind {
    Exact(String),
    Subdomain(String),
    Cidr(String),
}

impl MatchKind {
    pub fn rule(&self) -> String {
        match self {
            MatchKind::Exact(p) => p.clone(),
            MatchKind::Subdomain(p) => format!("*.{p}"),
            MatchKind::Cidr(p) => p.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("invalid CIDR {cidr:?}: {source}")]
    Cidr {
        cidr: String,
        #[source]
        source: ipnet::AddrParseError,
    },
    #[error("invalid domain pattern {pattern:?}: {reason}")]
    Domain { pattern: String, reason: &'static str },
}

impl HostMatcher {
    pub fn new(
        domains: impl IntoIterator<Item = impl AsRef<str>>,
        cidrs: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, PatternError> {
        let mut m = HostMatcher::default();

        for d in domains {
            let raw = d.as_ref();
            let pattern = normalise(raw);
            if let Some(rest) = pattern.strip_prefix("*.") {
                if rest.is_empty() || rest.contains('*') {
                    return Err(PatternError::Domain {
                        pattern: raw.to_owned(),
                        reason: "`*.` must be followed by a literal domain",
                    });
                }
                m.suffix.push(rest.to_owned());
            } else if pattern.contains('*') {
                return Err(PatternError::Domain {
                    pattern: raw.to_owned(),
                    reason: "`*` is only supported as a leading `*.` label",
                });
            } else if pattern.is_empty() {
                return Err(PatternError::Domain {
                    pattern: raw.to_owned(),
                    reason: "empty pattern",
                });
            } else {
                m.exact.push(pattern);
            }
        }

        for c in cidrs {
            let raw = c.as_ref();
            let net = IpNet::from_str(raw)
                .map_err(|source| PatternError::Cidr { cidr: raw.to_owned(), source })?;
            m.cidrs.push(net);
        }

        Ok(m)
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty() && self.cidrs.is_empty()
    }

    /// Match the *authority* host as written by the client.
    ///
    /// CIDRs are only consulted when the host is an IP literal. A hostname that would resolve
    /// into an allowed CIDR deliberately does **not** match: deciding policy on a resolved
    /// address would mean the allowlist and the eventual connect could see different answers,
    /// which is precisely the DNS-rebinding gap the upstream guard exists to close. The guard
    /// checks resolved addresses; this checks what the client asked for.
    pub fn matches(&self, host: &str) -> Option<MatchKind> {
        let host = normalise(host);

        if let Ok(ip) = host.parse::<IpAddr>() {
            return self
                .cidrs
                .iter()
                .find(|net| net.contains(&ip))
                .map(|net| MatchKind::Cidr(net.to_string()));
        }

        if let Some(p) = self.exact.iter().find(|p| **p == host) {
            return Some(MatchKind::Exact(p.clone()));
        }

        self.suffix
            .iter()
            .find(|base| is_strict_subdomain(&host, base))
            .map(|base| MatchKind::Subdomain(base.clone()))
    }
}

/// Lower-case and drop a single trailing dot.
fn normalise(host: &str) -> String {
    let h = host.trim().trim_end_matches('.');
    h.to_ascii_lowercase()
}

/// True when `host` is a subdomain of `base` with at least one extra label.
fn is_strict_subdomain(host: &str, base: &str) -> bool {
    host.len() > base.len()
        && host.ends_with(base)
        && host.as_bytes()[host.len() - base.len() - 1] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(domains: &[&str], cidrs: &[&str]) -> HostMatcher {
        HostMatcher::new(domains.iter(), cidrs.iter()).unwrap()
    }

    #[test]
    fn exact_match_is_case_and_dot_insensitive() {
        let m = m(&["Example.COM"], &[]);
        assert!(m.matches("example.com").is_some());
        assert!(m.matches("EXAMPLE.com.").is_some());
        assert!(m.matches("api.example.com").is_none());
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_apex() {
        let m = m(&["*.example.com"], &[]);
        assert!(m.matches("api.example.com").is_some());
        assert!(m.matches("a.b.example.com").is_some());
        assert!(m.matches("example.com").is_none(), "apex must be listed separately");
    }

    #[test]
    fn wildcard_does_not_match_a_lookalike_suffix() {
        let m = m(&["*.example.com"], &[]);
        // The dangerous cases: a glob whose `*` crossed `.` would let these through.
        assert!(m.matches("notexample.com").is_none());
        assert!(m.matches("example.com.attacker.net").is_none());
        assert!(m.matches("evil-example.com").is_none());
    }

    #[test]
    fn cidrs_only_apply_to_ip_literals() {
        let m = m(&[], &["10.0.0.0/8"]);
        assert!(m.matches("10.1.2.3").is_some());
        assert!(m.matches("11.0.0.1").is_none());
        // A hostname is never matched against a CIDR, even if it would resolve into one.
        assert!(m.matches("internal.example.com").is_none());
    }

    #[test]
    fn ipv6_literals_match() {
        let m = m(&[], &["fd00::/8"]);
        assert!(m.matches("fd00::1").is_some());
        assert!(m.matches("2001:db8::1").is_none());
    }

    #[test]
    fn bad_patterns_are_rejected() {
        assert!(HostMatcher::new(["ex*ample.com"], Vec::<&str>::new()).is_err());
        assert!(HostMatcher::new(Vec::<&str>::new(), ["not-a-cidr"]).is_err());
    }
}
