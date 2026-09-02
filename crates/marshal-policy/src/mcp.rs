//! Model Context Protocol policy: which tools an agent may call, and with what arguments.
//!
//! # Why this needs its own layer
//!
//! To a host allowlist, every MCP call looks identical — one POST to one endpoint. The
//! interesting distinction is entirely in the body: `search_repositories` and
//! `delete_repository` are the same request as far as any layer above this one can tell.
//!
//! # Filtering `tools/list` matters as much as blocking `tools/call`
//!
//! Blocking a denied call produces an error the agent has to interpret and route around,
//! which for an LLM-driven agent means retries, creative workarounds, and noise. Removing the
//! tool from `tools/list` means the agent never forms the intent in the first place. Both are
//! implemented, and the filtering is the one that makes the agent behave well.

use marshal_config::layer::{McpArgConstraint, McpServer, McpTool};
use regex::Regex;

use crate::hosts::HostMatcher;

#[derive(Debug, thiserror::Error)]
pub enum McpConfigError {
    #[error("tool name pattern {pattern:?}: {source}")]
    ToolPattern {
        pattern: String,
        #[source]
        source: globset::Error,
    },

    #[error("constraint on `{path}`: invalid regex {regex:?}: {source}")]
    ConstraintRegex {
        path: String,
        regex: String,
        #[source]
        source: Box<regex::Error>,
    },

    #[error("host pattern: {0}")]
    Host(#[from] crate::hosts::PatternError),
}

/// Why a call was refused, phrased for the agent that made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The tool is not listed for this server at all.
    UnknownTool,
    /// The tool is listed, but an argument constraint did not hold.
    ConstraintFailed { path: String, detail: String },
}

impl Refusal {
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::UnknownTool => "mcp_tool_not_permitted",
            Refusal::ConstraintFailed { .. } => "mcp_argument_not_permitted",
        }
    }
}

#[derive(Debug)]
struct CompiledConstraint {
    path: String,
    equals: Option<serde_json::Value>,
    one_of: Option<Vec<serde_json::Value>>,
    matches: Option<Regex>,
}

#[derive(Debug)]
struct CompiledTool {
    pattern: String,
    matcher: globset::GlobMatcher,
    when: Vec<CompiledConstraint>,
}

#[derive(Debug)]
struct CompiledServer {
    hosts: HostMatcher,
    tools: Vec<CompiledTool>,
}

/// The compiled MCP policy for one profile.
#[derive(Debug)]
pub struct McpPolicy {
    servers: Vec<CompiledServer>,
}

impl McpPolicy {
    pub fn compile(servers: &[McpServer]) -> Result<Self, McpConfigError> {
        let mut compiled = Vec::new();
        for server in servers {
            let domains: Vec<String> = server.rules.iter().filter_map(|r| r.host.clone()).collect();
            let cidrs: Vec<String> = server.rules.iter().filter_map(|r| r.cidr.clone()).collect();

            compiled.push(CompiledServer {
                hosts: HostMatcher::new(&domains, &cidrs)?,
                tools: server.tools.iter().map(compile_tool).collect::<Result<Vec<_>, _>>()?,
            });
        }
        Ok(Self { servers: compiled })
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Whether this policy has anything to say about `host`.
    pub fn governs(&self, host: &str) -> bool {
        self.servers.iter().any(|s| s.hosts.matches(host).is_some())
    }

    /// May `tool` be called on `host` with `arguments`?
    ///
    /// Default-deny: a host this policy governs permits only the tools it lists. A host it
    /// does not govern is not this layer's business and passes.
    pub fn check_call(
        &self,
        host: &str,
        tool: &str,
        arguments: Option<&serde_json::Value>,
    ) -> Result<(), Refusal> {
        let mut governed = false;
        for server in &self.servers {
            if server.hosts.matches(host).is_none() {
                continue;
            }
            governed = true;
            for candidate in &server.tools {
                if !candidate.matcher.is_match(tool) {
                    continue;
                }
                match check_constraints(candidate, arguments) {
                    Ok(()) => return Ok(()),
                    // Keep looking: another entry may name the same tool with constraints
                    // this call does satisfy. Only report a failure if nothing matches.
                    Err(refusal) => {
                        if self.no_other_match(host, tool, arguments, candidate) {
                            return Err(refusal);
                        }
                    }
                }
            }
        }

        if governed { Err(Refusal::UnknownTool) } else { Ok(()) }
    }

    fn no_other_match(
        &self,
        host: &str,
        tool: &str,
        arguments: Option<&serde_json::Value>,
        skip: &CompiledTool,
    ) -> bool {
        !self.servers.iter().any(|server| {
            server.hosts.matches(host).is_some()
                && server.tools.iter().any(|c| {
                    !std::ptr::eq(c, skip)
                        && c.matcher.is_match(tool)
                        && check_constraints(c, arguments).is_ok()
                })
        })
    }

    /// Whether a tool should appear in a filtered `tools/list`.
    ///
    /// Argument constraints are not applied here: a tool whose use is conditional is still
    /// worth advertising, since the condition depends on arguments the agent has not chosen
    /// yet. Hiding it would make a legitimately usable tool invisible.
    pub fn tool_is_visible(&self, host: &str, tool: &str) -> bool {
        let mut governed = false;
        for server in &self.servers {
            if server.hosts.matches(host).is_none() {
                continue;
            }
            governed = true;
            if server.tools.iter().any(|c| c.matcher.is_match(tool)) {
                return true;
            }
        }
        !governed
    }
}

fn compile_tool(tool: &McpTool) -> Result<CompiledTool, McpConfigError> {
    Ok(CompiledTool {
        pattern: tool.name.clone(),
        matcher: globset::Glob::new(&tool.name)
            .map_err(|source| McpConfigError::ToolPattern { pattern: tool.name.clone(), source })?
            .compile_matcher(),
        when: tool.when.iter().map(compile_constraint).collect::<Result<Vec<_>, _>>()?,
    })
}

fn compile_constraint(c: &McpArgConstraint) -> Result<CompiledConstraint, McpConfigError> {
    Ok(CompiledConstraint {
        path: c.path.clone(),
        equals: c.equals.clone(),
        one_of: c.one_of.clone(),
        matches: c.matches.as_ref().map(|r| Regex::new(r)).transpose().map_err(|source| {
            McpConfigError::ConstraintRegex {
                path: c.path.clone(),
                regex: c.matches.clone().unwrap_or_default(),
                source: Box::new(source),
            }
        })?,
    })
}

fn check_constraints(
    tool: &CompiledTool,
    arguments: Option<&serde_json::Value>,
) -> Result<(), Refusal> {
    for constraint in &tool.when {
        let value = arguments.and_then(|a| lookup(a, &constraint.path));

        let Some(value) = value else {
            return Err(Refusal::ConstraintFailed {
                path: constraint.path.clone(),
                detail: format!(
                    "`{}` requires argument `{}`, which was not supplied",
                    tool.pattern, constraint.path
                ),
            });
        };

        if let Some(expected) = &constraint.equals
            && value != expected
        {
            return Err(Refusal::ConstraintFailed {
                path: constraint.path.clone(),
                detail: format!("`{}` must equal {}", constraint.path, render(expected)),
            });
        }

        if let Some(allowed) = &constraint.one_of
            && !allowed.contains(value)
        {
            return Err(Refusal::ConstraintFailed {
                path: constraint.path.clone(),
                detail: format!(
                    "`{}` must be one of {}",
                    constraint.path,
                    allowed.iter().map(render).collect::<Vec<_>>().join(", ")
                ),
            });
        }

        if let Some(pattern) = &constraint.matches {
            let text = value.as_str().map(|s| s.to_owned()).unwrap_or_else(|| value.to_string());
            if !pattern.is_match(&text) {
                return Err(Refusal::ConstraintFailed {
                    path: constraint.path.clone(),
                    detail: format!("`{}` must match /{}/", constraint.path, pattern.as_str()),
                });
            }
        }
    }
    Ok(())
}

/// Resolve a dotted path into a JSON value.
fn lookup<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.').try_fold(value, |acc, segment| acc.get(segment))
}

fn render(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => format!("`{s}`"),
        other => format!("`{other}`"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(yaml: &str) -> McpPolicy {
        let servers: Vec<McpServer> = serde_yaml_ng::from_str(yaml).unwrap();
        McpPolicy::compile(&servers).unwrap()
    }

    const GITHUB: &str = r#"
- rules: [{ host: "mcp.example.com" }]
  tools:
    - name: "search_*"
    - name: "create_issue"
      when:
        - path: owner
          equals: gregbacchus
    - name: "update_file"
      when:
        - path: repo
          in: ["bot-marshal", "notes"]
        - path: path
          matches: '^src/'
"#;

    #[test]
    fn unlisted_tools_are_denied_by_default() {
        let p = policy(GITHUB);
        assert_eq!(
            p.check_call("mcp.example.com", "delete_repository", None),
            Err(Refusal::UnknownTool)
        );
    }

    #[test]
    fn glob_patterns_cover_a_family_of_tools() {
        let p = policy(GITHUB);
        assert!(p.check_call("mcp.example.com", "search_repositories", None).is_ok());
        assert!(p.check_call("mcp.example.com", "search_code", None).is_ok());
        assert!(p.check_call("mcp.example.com", "searchless", None).is_err());
    }

    #[test]
    fn argument_constraints_are_enforced() {
        let p = policy(GITHUB);
        let ok = serde_json::json!({ "owner": "gregbacchus", "title": "x" });
        assert!(p.check_call("mcp.example.com", "create_issue", Some(&ok)).is_ok());

        let wrong = serde_json::json!({ "owner": "someone-else" });
        let err = p.check_call("mcp.example.com", "create_issue", Some(&wrong)).unwrap_err();
        assert!(matches!(err, Refusal::ConstraintFailed { .. }));
    }

    #[test]
    fn a_missing_required_argument_is_a_refusal_not_a_pass() {
        // Treating an absent argument as "constraint not applicable" would let a call
        // through by simply omitting the field the constraint guards.
        let p = policy(GITHUB);
        let err = p
            .check_call("mcp.example.com", "create_issue", Some(&serde_json::json!({})))
            .unwrap_err();
        assert!(matches!(err, Refusal::ConstraintFailed { .. }), "{err:?}");
    }

    #[test]
    fn all_constraints_must_hold() {
        let p = policy(GITHUB);
        let both = serde_json::json!({ "repo": "bot-marshal", "path": "src/main.rs" });
        assert!(p.check_call("mcp.example.com", "update_file", Some(&both)).is_ok());

        // Right repo, wrong path.
        let one = serde_json::json!({ "repo": "bot-marshal", "path": "README.md" });
        assert!(p.check_call("mcp.example.com", "update_file", Some(&one)).is_err());

        // Wrong repo, right path.
        let other = serde_json::json!({ "repo": "secrets", "path": "src/main.rs" });
        assert!(p.check_call("mcp.example.com", "update_file", Some(&other)).is_err());
    }

    #[test]
    fn dotted_paths_reach_into_nested_arguments() {
        let p = policy(
            r#"
- rules: [{ host: "h" }]
  tools:
    - name: "deploy"
      when:
        - path: target.environment
          equals: staging
"#,
        );
        let staging = serde_json::json!({ "target": { "environment": "staging" } });
        assert!(p.check_call("h", "deploy", Some(&staging)).is_ok());

        let prod = serde_json::json!({ "target": { "environment": "production" } });
        assert!(p.check_call("h", "deploy", Some(&prod)).is_err());
    }

    #[test]
    fn hosts_this_policy_does_not_govern_are_left_alone() {
        // Another layer's business. Denying here would make the MCP layer a second, silent
        // allowlist.
        let p = policy(GITHUB);
        assert!(p.check_call("other.example.com", "anything", None).is_ok());
        assert!(!p.governs("other.example.com"));
        assert!(p.governs("mcp.example.com"));
    }

    #[test]
    fn visibility_ignores_argument_constraints() {
        // A conditionally usable tool is still worth advertising: the condition depends on
        // arguments the agent has not chosen yet, so hiding it would make a legitimately
        // usable tool invisible.
        let p = policy(GITHUB);
        assert!(p.tool_is_visible("mcp.example.com", "create_issue"));
        assert!(!p.tool_is_visible("mcp.example.com", "delete_repository"));
        assert!(p.tool_is_visible("elsewhere.example.com", "delete_repository"));
    }

    #[test]
    fn several_entries_for_one_tool_are_alternatives() {
        // Two entries naming the same tool should mean "either is acceptable", not "the
        // first one that fails decides".
        let p = policy(
            r#"
- rules: [{ host: "h" }]
  tools:
    - name: "write"
      when: [{ path: repo, equals: a }]
    - name: "write"
      when: [{ path: repo, equals: b }]
"#,
        );
        assert!(p.check_call("h", "write", Some(&serde_json::json!({"repo": "a"}))).is_ok());
        assert!(p.check_call("h", "write", Some(&serde_json::json!({"repo": "b"}))).is_ok());
        assert!(p.check_call("h", "write", Some(&serde_json::json!({"repo": "c"}))).is_err());
    }
}
