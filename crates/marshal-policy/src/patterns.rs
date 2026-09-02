//! Named credential patterns for the DLP layer.
//!
//! These detect a *real* credential heading out through the boundary — the inverse of secret
//! injection. If an agent has scraped an AWS key off the filesystem and is posting it to a
//! host the allowlist happens to permit, no amount of destination filtering helps.
//!
//! The patterns are deliberately conservative. A false positive blocks legitimate work and
//! trains people to disable the layer, which costs more than the marginal catch is worth; a
//! false negative is one detection among several. Each is anchored to a vendor-documented
//! prefix rather than to entropy, for the same reason.

use regex::Regex;

/// A named detector.
#[derive(Debug)]
pub struct Pattern {
    pub name: &'static str,
    pub description: &'static str,
    regex: Regex,
}

impl Pattern {
    pub fn is_match(&self, haystack: &str) -> bool {
        self.regex.is_match(haystack)
    }
}

/// Build the named pattern, or `None` if the name is unknown.
pub fn builtin(name: &str) -> Option<Pattern> {
    let (description, source) = match name {
        "aws-access-key" => ("AWS access key ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        "github-pat" => (
            "GitHub personal access, OAuth, app or refresh token",
            r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        ),
        "github-fine-grained" => {
            ("GitHub fine-grained personal access token", r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")
        }
        "slack-token" => ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
        "openai-key" => ("OpenAI API key", r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "anthropic-key" => ("Anthropic API key", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        "google-api-key" => ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "stripe-key" => ("Stripe secret key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        "private-key-pem" => (
            "PEM-encoded private key",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
        ),
        "jwt" => (
            "JSON Web Token",
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        ),
        _ => return None,
    };

    Some(Pattern {
        name: leak_name(name),
        description,
        // The expressions are compile-time constants; a failure here is a bug, not input.
        regex: Regex::new(source).expect("builtin pattern must compile"),
    })
}

/// Every builtin name, for error messages and documentation.
pub fn builtin_names() -> &'static [&'static str] {
    &[
        "aws-access-key",
        "github-pat",
        "github-fine-grained",
        "slack-token",
        "openai-key",
        "anthropic-key",
        "google-api-key",
        "stripe-key",
        "private-key-pem",
        "jwt",
    ]
}

/// Resolve a configured name to the `'static` spelling used in diagnostics.
fn leak_name(name: &str) -> &'static str {
    builtin_names().iter().find(|n| **n == name).copied().unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(pattern: &str, text: &str) -> bool {
        builtin(pattern).unwrap().is_match(text)
    }

    #[test]
    fn every_advertised_name_builds() {
        for name in builtin_names() {
            assert!(builtin(name).is_some(), "{name}");
        }
        assert!(builtin("no-such-pattern").is_none());
    }

    #[test]
    fn detects_real_looking_credentials() {
        assert!(matches("aws-access-key", "AKIAIOSFODNN7EXAMPLE"));
        assert!(matches("github-pat", &format!("ghp_{}", "a".repeat(36))));
        assert!(matches("github-fine-grained", &format!("github_pat_{}", "b".repeat(30))));
        assert!(matches("openai-key", &format!("sk-{}", "c".repeat(32))));
        assert!(matches("anthropic-key", &format!("sk-ant-{}", "d".repeat(32))));
        assert!(matches("google-api-key", &format!("AIza{}", "e".repeat(35))));
        assert!(matches("stripe-key", &format!("sk_live_{}", "f".repeat(24))));
        assert!(matches("slack-token", "xoxb-1234567890-abcdefghij"));
        assert!(matches("private-key-pem", "-----BEGIN RSA PRIVATE KEY-----"));
        assert!(matches("private-key-pem", "-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn does_not_fire_on_ordinary_text() {
        // False positives train people to switch the layer off, which costs more than the
        // marginal detection is worth.
        for text in [
            "the quick brown fox jumps over the lazy dog",
            "AKIA is a prefix", // no 16-char body
            "ghp_short",        // too short
            "sk-abc",           // too short
            "https://api.github.com/repos/o/r",
            "Authorization: Bearer marshal-github-placeholder",
        ] {
            for name in builtin_names() {
                assert!(!matches(name, text), "{name} fired on {text:?}");
            }
        }
    }

    #[test]
    fn the_proxy_placeholder_is_never_flagged() {
        // Placeholders are meant to travel; flagging them would make injection unusable
        // alongside DLP.
        for name in builtin_names() {
            assert!(!matches(name, "marshal-github-placeholder"));
            assert!(!matches(name, "proxy-openai-abc123"));
        }
    }
}
