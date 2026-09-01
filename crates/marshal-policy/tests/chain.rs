//! Chain semantics: ordering, the terminal default, and evidence flowing forward.
//!
//! These three properties are the whole contract of the design, so they are tested against
//! the runner rather than against individual layers.

use std::sync::Arc;

use marshal_config::model::Config;
use marshal_core::{
    Action, BodyHandle, CostClass, DenyingDecider, Evidence, IngressMode, PolicyLayer, Reason,
    RequestContext, Result, SessionId, Verdict,
};
use marshal_policy::build_chain;

fn cfg(yaml: &str) -> Config {
    serde_yaml_ng::from_str(yaml).expect("test config parses")
}

fn request(host: &str) -> RequestContext {
    RequestContext {
        session: SessionId::new("test"),
        profile: Arc::from("p"),
        ingress: IngressMode::Explicit,
        client_addr: "127.0.0.1:1234".parse().unwrap(),
        authority: marshal_core::Authority { host: host.to_owned(), port: 443 },
        method: http::Method::GET,
        uri: "/".parse().unwrap(),
        headers: http::HeaderMap::new(),
        body: BodyHandle::Empty,
        evidence: Evidence::new(),
    }
}

const BOTH: &str = r#"
profiles:
  p:
    default_action: deny
    policy:
      - layer: denylist
        deny: { domains: ["blocked.example.com"] }
      - layer: allowlist
        allow: { domains: ["blocked.example.com", "ok.example.com"] }
        on_match: allow
        on_miss: pass
"#;

#[tokio::test]
async fn denylist_before_allowlist_wins() {
    let c = cfg(BOTH);
    let chain = build_chain(&c, "p", Arc::new(DenyingDecider)).unwrap();

    // The host is on BOTH lists. The denylist is first, so it decides — precedence comes
    // from ordering, not from a special rule.
    let out = chain.evaluate(&request("blocked.example.com")).await;
    assert_eq!(out.action, Action::Deny);
    assert_eq!(out.reason.layer, "denylist");

    // The allowlist still works for hosts the denylist ignores.
    let out = chain.evaluate(&request("ok.example.com")).await;
    assert_eq!(out.action, Action::Allow);
    assert_eq!(out.reason.layer, "allowlist");
}

#[tokio::test]
async fn all_pass_falls_through_to_default_action() {
    let c = cfg(BOTH);
    let chain = build_chain(&c, "p", Arc::new(DenyingDecider)).unwrap();

    let out = chain.evaluate(&request("unknown.example.com")).await;
    assert_eq!(out.action, Action::Deny);
    assert_eq!(out.reason.layer, "default_action", "the terminal default must decide");
    assert_eq!(out.reason.code, "default_deny");

    // Every layer that ran is in the trail, in order.
    let names: Vec<_> = out.evidence.trail.iter().map(|o| o.layer.as_str()).collect();
    assert_eq!(names, ["denylist", "allowlist"]);
    assert!(out.evidence.trail.iter().all(|o| o.verdict == "pass"));
}

#[tokio::test]
async fn default_allow_requires_no_layer_to_agree() {
    let c = cfg(r#"
profiles:
  p:
    default_action: allow
    i_understand_this_is_allow_by_default: true
    policy:
      - layer: denylist
        deny: { domains: ["blocked.example.com"] }
"#);
    let chain = build_chain(&c, "p", Arc::new(DenyingDecider)).unwrap();

    let out = chain.evaluate(&request("anything.example.com")).await;
    assert_eq!(out.action, Action::Allow);
    assert_eq!(out.reason.code, "default_allow");

    // The denylist still bites first.
    let out = chain.evaluate(&request("blocked.example.com")).await;
    assert_eq!(out.action, Action::Deny);
}

/// A layer that records a fact, so the next layer can be shown to see it.
#[derive(Debug)]
struct Recorder;

#[async_trait::async_trait]
impl PolicyLayer for Recorder {
    fn name(&self) -> &str {
        "recorder"
    }
    fn cost(&self) -> CostClass {
        CostClass::Trivial
    }
    async fn evaluate(&self, _cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        let mut ev = ev.clone();
        ev.record("recorder.saw", "yes");
        ev.flag("Recorded");
        Ok(Verdict::Pass(ev))
    }
}

/// Allows only if the previous layer's flag is present.
#[derive(Debug)]
struct RequiresFlag;

#[async_trait::async_trait]
impl PolicyLayer for RequiresFlag {
    fn name(&self) -> &str {
        "requires-flag"
    }
    fn cost(&self) -> CostClass {
        CostClass::Cheap
    }
    async fn evaluate(&self, _cx: &RequestContext, ev: &Evidence) -> Result<Verdict> {
        if ev.has_flag("Recorded") && ev.fact("recorder.saw").is_some() {
            Ok(Verdict::Allow(Reason::new("requires-flag", "saw_evidence", "evidence arrived")))
        } else {
            Ok(Verdict::Deny(Reason::new("requires-flag", "no_evidence", "evidence was lost")))
        }
    }
}

#[tokio::test]
async fn evidence_from_one_layer_reaches_the_next() {
    use marshal_core::Decision;
    let chain = marshal_policy::Chain::new(
        "p",
        vec![Arc::new(Recorder), Arc::new(RequiresFlag)],
        Decision::Deny,
        Arc::new(DenyingDecider),
    );

    let out = chain.evaluate(&request("example.com")).await;
    assert_eq!(out.action, Action::Allow, "layer 2 must see what layer 1 recorded");
    assert_eq!(out.reason.code, "saw_evidence");

    // And the evidence survives into the audit record.
    assert!(out.evidence.has_flag("Recorded"));
    assert_eq!(out.evidence.fact("recorder.saw").unwrap(), "yes");
}

#[tokio::test]
async fn unimplemented_layer_is_an_error_not_a_silent_skip() {
    let c = cfg(r#"
profiles:
  p:
    default_action: deny
    policy:
      - layer: judge
        provider: { type: anthropic, model: m, api_key_env: K }
        prompt: "x"
"#);
    // A config naming a layer we cannot run must fail loudly: silently dropping it would
    // yield a chain more permissive than the one written.
    let err = build_chain(&c, "p", Arc::new(DenyingDecider)).unwrap_err();
    assert!(err.to_string().contains("judge"), "{err}");
}

#[tokio::test]
async fn extends_inherits_the_parent_chain() {
    let c = cfg(r#"
profiles:
  base:
    default_action: deny
    policy:
      - layer: allowlist
        allow: { domains: ["ok.example.com"] }
        on_match: allow
        on_miss: pass
  child:
    extends: base
"#);
    let chain = build_chain(&c, "child", Arc::new(DenyingDecider)).unwrap();
    assert_eq!(chain.layer_names(), ["allowlist"]);
    assert_eq!(chain.evaluate(&request("ok.example.com")).await.action, Action::Allow);
}
