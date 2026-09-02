//! Which requests reach the judge.

use marshal_config::layer::JudgeScope;
use marshal_core::HostMatcher;

#[derive(Debug)]
pub struct CompiledScope {
    hosts: HostMatcher,
    methods: Vec<String>,
}

impl CompiledScope {
    pub fn compile(scopes: &[JudgeScope]) -> Result<Vec<Self>, marshal_core::PatternError> {
        scopes
            .iter()
            .map(|s| {
                let domains: Vec<&str> = s.host.as_deref().into_iter().collect();
                let cidrs: Vec<&str> = s.cidr.as_deref().into_iter().collect();
                Ok(Self {
                    hosts: HostMatcher::new(domains, cidrs)?,
                    methods: s.methods.iter().map(|m| m.to_ascii_uppercase()).collect(),
                })
            })
            .collect()
    }

    fn matches(&self, host: &str, method: &str) -> bool {
        self.hosts.matches(host).is_some()
            && (self.methods.is_empty() || self.methods.iter().any(|m| m == method))
    }
}

/// Whether any configured scope covers this request.
pub fn governs(scopes: &[CompiledScope], host: &str, method: &str) -> bool {
    scopes.iter().any(|s| s.matches(host, method))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(yaml: &str) -> Vec<CompiledScope> {
        let raw: Vec<JudgeScope> = serde_yaml_ng::from_str(yaml).unwrap();
        CompiledScope::compile(&raw).unwrap()
    }

    #[test]
    fn matches_host_and_method() {
        let s = scope("- host: \"api.github.com\"\n  methods: [\"POST\", \"DELETE\"]");
        assert!(governs(&s, "api.github.com", "POST"));
        assert!(governs(&s, "api.github.com", "DELETE"));
        assert!(!governs(&s, "api.github.com", "GET"));
        assert!(!governs(&s, "other.example.com", "POST"));
    }

    #[test]
    fn an_empty_methods_list_matches_every_method() {
        let s = scope("- host: \"api.github.com\"");
        assert!(governs(&s, "api.github.com", "GET"));
        assert!(governs(&s, "api.github.com", "DELETE"));
    }

    #[test]
    fn method_matching_is_case_insensitive() {
        let s = scope("- host: \"api.github.com\"\n  methods: [\"post\"]");
        assert!(governs(&s, "api.github.com", "POST"));
    }
}
