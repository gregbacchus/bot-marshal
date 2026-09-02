//! CEL expressions over the request and the evidence gathered so far.
//!
//! CEL rather than a general scripting language because it is not Turing-complete: an
//! expression cannot loop, recurse, or block, so a bad rule cannot hang the request path. On a
//! proxy that every outbound request passes through, that guarantee is worth more than the
//! expressiveness it costs.

use cel::{Context, Program, Value};
use marshal_config::layer::Outcome;
use marshal_core::{
    CostClass, Evidence, FailureMode, PolicyLayer, Reason, RequestContext, Result, Verdict,
};

/// One compiled expression and what a true result means.
#[derive(Debug)]
pub struct Rule {
    pub source: String,
    pub program: Program,
    pub verdict: Outcome,
    pub annotate: Vec<String>,
}

#[derive(Debug)]
pub struct Rules {
    rules: Vec<Rule>,
}

// `expression` rather than `source`: thiserror treats a field named `source` as the error
// cause and requires it to implement `Error`.
#[derive(Debug, thiserror::Error)]
#[error("rule {index} (`{expression}`) failed to compile: {message}")]
pub struct RuleCompileError {
    pub index: usize,
    pub expression: String,
    pub message: String,
}

impl Rules {
    /// Compile at startup, so a malformed expression is a config error rather than a
    /// surprise on the first request that reaches it.
    pub fn compile(
        specs: impl IntoIterator<Item = (String, Outcome, Vec<String>)>,
    ) -> std::result::Result<Self, RuleCompileError> {
        let mut rules = Vec::new();
        for (index, (source, verdict, annotate)) in specs.into_iter().enumerate() {
            let program = Program::compile(&source).map_err(|e| RuleCompileError {
                index,
                expression: source.clone(),
                message: e.to_string(),
            })?;
            rules.push(Rule { source, program, verdict, annotate });
        }
        Ok(Self { rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

/// Build the variables an expression can see.
///
/// Only derived facts are exposed — method, host, path, header *names*, and the accumulated
/// evidence. Header and query *values* are deliberately absent: a rule that could read them
/// could also copy a credential into a flag or an error message, which would put it in the
/// audit trail. Matching on values is the DLP layer's job, and it reports findings without
/// quoting them.
fn build_context(cx: &RequestContext, ev: &Evidence) -> Context<'static> {
    let mut ctx = Context::default();

    let header_names: Vec<String> =
        cx.headers.keys().map(|k| k.as_str().to_ascii_lowercase()).collect();

    let req = serde_json::json!({
        "method": cx.method.as_str(),
        "host": cx.authority.host,
        "port": cx.authority.port,
        "path": cx.uri.path(),
        "has_query": cx.uri.query().is_some(),
        "headers": header_names,
    });

    let flags: Vec<String> = ev.flags.iter().map(|f| f.0.clone()).collect();
    let evidence = serde_json::json!({ "facts": ev.facts, "flags": flags });

    ctx.add_variable_from_value("req", to_cel(&req));
    ctx.add_variable_from_value("ev", to_cel(&evidence));
    ctx
}

fn to_cel(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => n
            .as_i64()
            .map(Value::Int)
            .or_else(|| n.as_f64().map(Value::Float))
            .unwrap_or(Value::Null),
        serde_json::Value::String(s) => Value::String(std::sync::Arc::new(s.clone())),
        serde_json::Value::Array(items) => {
            Value::List(std::sync::Arc::new(items.iter().map(to_cel).collect()))
        }
        serde_json::Value::Object(map) => {
            let entries: std::collections::HashMap<cel::objects::Key, Value> = map
                .iter()
                .map(|(k, v)| {
                    (cel::objects::Key::String(std::sync::Arc::new(k.clone())), to_cel(v))
                })
                .collect();
            Value::Map(cel::objects::Map { map: std::sync::Arc::new(entries) })
        }
    }
}

#[async_trait::async_trait]
impl PolicyLayer for Rules {
    fn name(&self) -> &str {
        "rules"
    }

    fn needs_request(&self) -> bool {
        true
    }

    fn cost(&self) -> CostClass {
        CostClass::Cheap
    }

    fn on_error(&self) -> FailureMode {
        FailureMode::Deny
    }

    async fn evaluate(&self, cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        let ctx = build_context(cx, ev);
        let mut ev = ev.clone();

        for rule in &self.rules {
            let matched = match rule.program.execute(&ctx) {
                Ok(Value::Bool(b)) => b,
                Ok(other) => {
                    // A rule that does not answer yes or no cannot be acted on. Treating that
                    // as "no match" would silently disable it.
                    return Err(marshal_core::Error::Layer {
                        layer: "rules".into(),
                        source: format!(
                            "expression `{}` produced {other:?}, but a rule must evaluate to \
                             a boolean",
                            rule.source
                        )
                        .into(),
                    });
                }
                Err(e) => {
                    return Err(marshal_core::Error::Layer {
                        layer: "rules".into(),
                        source: format!("evaluating `{}`: {e}", rule.source).into(),
                    });
                }
            };

            if !matched {
                continue;
            }

            for flag in &rule.annotate {
                ev.flag(flag.as_str());
            }

            let reason = Reason::new(
                "rules",
                "rule_matched",
                format!("expression `{}` matched", rule.source),
            )
            .with_rule(rule.source.clone());

            match rule.verdict {
                Outcome::Allow => return Ok(Verdict::Allow(reason)),
                Outcome::Deny => return Ok(Verdict::Deny(reason)),
                // A `pass` rule exists to annotate: it records a flag a later layer can use
                // and keeps evaluating.
                Outcome::Pass => continue,
            }
        }

        Ok(Verdict::Pass(ev))
    }
}
