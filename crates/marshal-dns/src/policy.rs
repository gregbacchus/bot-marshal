//! What a name should resolve to.
//!
//! Kept free of the DNS library so the interesting decisions can be tested as a function of
//! a name rather than through a socket.

use std::collections::BTreeMap;
use std::net::IpAddr;

use marshal_policy::HostMatcher;

/// How to answer a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The proxy's own address, so the connection comes to us. The default, and the point of
    /// the mode.
    Proxy(IpAddr),
    /// A fixed answer from config.
    Static(Vec<IpAddr>),
    /// Ask the real resolver and return what it says.
    ///
    /// For names the proxy has no business intercepting — internal services, and anything
    /// whose traffic is not HTTP and so cannot be policed usefully anyway.
    Passthrough,
}

#[derive(Debug)]
pub struct DnsPolicy {
    proxy_ip: IpAddr,
    passthrough: HostMatcher,
    records: BTreeMap<String, Vec<IpAddr>>,
}

impl DnsPolicy {
    pub fn new(
        proxy_ip: IpAddr,
        passthrough: &[String],
        records: impl IntoIterator<Item = (String, Vec<IpAddr>)>,
    ) -> Result<Self, marshal_policy::PatternError> {
        Ok(Self {
            proxy_ip,
            passthrough: HostMatcher::new(passthrough, Vec::<&str>::new())?,
            records: records.into_iter().map(|(name, ips)| (normalise(&name), ips)).collect(),
        })
    }

    pub fn proxy_ip(&self) -> IpAddr {
        self.proxy_ip
    }

    /// Decide how to answer.
    ///
    /// Static records win over everything, including passthrough: they are the operator
    /// saying explicitly what a name means, and anything that could override that would make
    /// them unreliable. Passthrough then wins over interception, so the default — send it to
    /// the proxy — applies to everything not deliberately excluded.
    pub fn answer(&self, name: &str) -> Answer {
        let name = normalise(name);

        if let Some(ips) = self.records.get(&name) {
            return Answer::Static(ips.clone());
        }
        if self.passthrough.matches(&name).is_some() {
            return Answer::Passthrough;
        }
        Answer::Proxy(self.proxy_ip)
    }
}

/// Lower-case and drop the trailing dot DNS names carry.
fn normalise(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> DnsPolicy {
        DnsPolicy::new(
            "10.16.0.1".parse().unwrap(),
            &["*.internal.corp".to_string(), "localhost".to_string()],
            [("db.example.com".to_string(), vec!["10.0.0.5".parse().unwrap()])],
        )
        .unwrap()
    }

    #[test]
    fn everything_resolves_to_the_proxy_by_default() {
        assert_eq!(policy().answer("api.github.com"), Answer::Proxy("10.16.0.1".parse().unwrap()));
    }

    #[test]
    fn passthrough_names_go_to_the_real_resolver() {
        let p = policy();
        assert_eq!(p.answer("db.internal.corp"), Answer::Passthrough);
        assert_eq!(p.answer("localhost"), Answer::Passthrough);
        // The wildcard does not cover the apex, matching the allowlist's semantics.
        assert_eq!(p.answer("internal.corp"), Answer::Proxy("10.16.0.1".parse().unwrap()));
    }

    #[test]
    fn static_records_win_over_passthrough_and_interception() {
        // An operator stating what a name means must not be overridden by a broader rule.
        let p = DnsPolicy::new(
            "10.16.0.1".parse().unwrap(),
            &["*.example.com".to_string()],
            [("db.example.com".to_string(), vec!["10.0.0.5".parse().unwrap()])],
        )
        .unwrap();
        assert_eq!(p.answer("db.example.com"), Answer::Static(vec!["10.0.0.5".parse().unwrap()]));
        assert_eq!(p.answer("other.example.com"), Answer::Passthrough);
    }

    #[test]
    fn names_are_matched_without_case_or_the_trailing_dot() {
        // Queries arrive fully qualified with a trailing dot; config is written without one.
        let p = policy();
        assert_eq!(p.answer("DB.Example.COM."), Answer::Static(vec!["10.0.0.5".parse().unwrap()]));
        assert_eq!(p.answer("DB.Internal.Corp."), Answer::Passthrough);
    }
}
