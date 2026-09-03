//! Chain semantics: ordering, the terminal default, and evidence flowing forward.
//!
//! These three properties are the whole contract of the design, so they are tested against
//! the runner rather than against individual layers.

use std::sync::Arc;

use marshal_config::model::Config;
use marshal_core::{
    Action, BodyHandle, CostClass, DenyingDecider, Evidence, Identity, IngressMode, PolicyLayer,
    Reason, RequestContext, Result, Verdict,
};
use marshal_policy::{build_chain, build_request_transforms, build_response_transforms};

fn cfg(yaml: &str) -> Config {
    serde_yaml_ng::from_str(yaml).expect("test config parses")
}

fn request(host: &str) -> RequestContext {
    RequestContext {
        identity: Identity::new("test"),
        profile: Arc::from("p"),
        ingress: IngressMode::Explicit,
        phase: marshal_core::Phase::Request,
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
profile:
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
    let chain = build_chain(&c, "p", &c.profile, Arc::new(DenyingDecider)).unwrap();

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
    let chain = build_chain(&c, "p", &c.profile, Arc::new(DenyingDecider)).unwrap();

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
profile:
  default_action: allow
  i_understand_this_is_allow_by_default: true
  policy:
    - layer: denylist
      deny: { domains: ["blocked.example.com"] }
"#);
    let chain = build_chain(&c, "p", &c.profile, Arc::new(DenyingDecider)).unwrap();

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
profile:
  default_action: deny
  policy:
    - layer: judge
      provider: { type: anthropic, model: m, api_key_env: K }
      prompt: "x"
"#);
    // A config naming a layer we cannot run must fail loudly: silently dropping it would
    // yield a chain more permissive than the one written.
    let err = build_chain(&c, "p", &c.profile, Arc::new(DenyingDecider)).unwrap_err();
    assert!(err.to_string().contains("judge"), "{err}");
}

#[tokio::test]
async fn unimplemented_response_transform_is_also_an_error() {
    // Same rule as an unimplemented policy layer. A response served untransformed is not
    // what the operator asked for, and silently doing so would let a `redact` that never
    // runs leak a credential the proxy itself injected.
    let c = cfg(r#"
profile:
  default_action: deny
  response_transforms:
    body:
      - transform: redact
        patterns: ["github-pat"]
"#);
    let err = build_chain(&c, "p", &c.profile, Arc::new(DenyingDecider)).unwrap_err();
    assert!(err.to_string().contains("redact"), "{err}");
}

#[tokio::test]
async fn a_profile_naming_a_transform_bundle_resolves_it() {
    // `transforms:` is populated by `load()` from `transforms_path` — not part of the YAML
    // document itself — so it's set directly here rather than parsed.
    use marshal_config::model::{
        HeaderAllowlist, RequestTransforms, ResponseTransforms, TransformBundle,
    };

    let mut c = cfg(r#"
profile:
  default_action: deny
  transforms: shared
"#);
    c.transforms.insert(
        "shared".to_owned(),
        TransformBundle {
            request_transforms: RequestTransforms {
                headers: Some(HeaderAllowlist { allow: vec!["accept".into()] }),
                set_headers: Default::default(),
                secrets: vec![],
            },
            response_transforms: ResponseTransforms {
                headers: Some(HeaderAllowlist { allow: vec!["content-type".into()] }),
                body: vec![],
            },
        },
    );

    let p = marshal_policy::resolve_profile(&c, &c.profile).unwrap();
    assert_eq!(p.request_transforms.headers.unwrap().allow, ["accept"]);
    assert_eq!(p.response_transforms.headers.unwrap().allow, ["content-type"]);
}

#[tokio::test]
async fn configured_request_headers_are_added_or_replaced() {
    let c = cfg(r#"
profile:
  default_action: deny
  request_transforms:
    set_headers:
      Accept: application/json
      X-Marshal-Mode: enforced
"#);
    let transforms = build_request_transforms(&c, "p", &c.profile).unwrap();
    let mut req = request("api.example.com");
    req.headers.insert("x-marshal-mode", "old-value".parse().unwrap());

    for transform in transforms {
        transform.apply(&mut req).await.unwrap();
    }

    assert_eq!(req.headers["accept"], "application/json");
    assert_eq!(req.headers["x-marshal-mode"], "enforced");
}

#[tokio::test]
async fn response_limit_truncates_at_a_utf8_boundary_within_the_budget() {
    let c = cfg(r#"
profile:
  default_action: deny
  response_transforms:
    body:
      - transform: limit
        max_bytes: 10
        on_oversize:
          action: truncate
          method: utf8
          marker: "[cut]"
"#);
    build_chain(&c, "p", &c.profile, Arc::new(DenyingDecider)).unwrap();
    let transforms = build_response_transforms(&c, "p", &c.profile).unwrap();
    let mut response = marshal_core::ResponseParts {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: BodyHandle::Buffered(bytes::Bytes::from_static("éééééé".as_bytes())),
    };

    for transform in transforms {
        transform.apply(&request("api.example.com"), &mut response).await.unwrap();
    }

    let BodyHandle::Buffered(body) = response.body else { panic!("response was not buffered") };
    assert_eq!(body, "éé[cut]");
    assert!(body.len() <= 10);
    assert_eq!(response.headers["x-marshal-response-limited"], "truncate");
    assert_eq!(response.headers[http::header::CONTENT_LENGTH], body.len().to_string());
}

#[tokio::test]
async fn response_limit_can_fail_with_a_small_structured_response() {
    let c = cfg(r#"
profile:
  default_action: deny
  response_transforms:
    body:
      - transform: limit
        max_bytes: 4
        on_oversize: { action: fail }
"#);
    let transforms = build_response_transforms(&c, "p", &c.profile).unwrap();
    let mut response = marshal_core::ResponseParts {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: BodyHandle::Buffered(bytes::Bytes::from_static(b"too long")),
    };

    transforms[0].apply(&request("api.example.com"), &mut response).await.unwrap();

    assert_eq!(response.status, http::StatusCode::BAD_GATEWAY);
    assert_eq!(response.headers["x-marshal-response-limited"], "fail");
    let BodyHandle::Buffered(body) = response.body else { panic!("response was not buffered") };
    let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(error["error"], "response_too_large");
    assert_eq!(error["max_bytes"], 4);
}

#[tokio::test]
async fn response_limit_can_replace_an_oversized_body_and_preserve_its_status() {
    let c = cfg(r#"
profile:
  default_action: deny
  response_transforms:
    body:
      - transform: limit
        max_bytes: 32
        on_oversize:
          action: replace
          body: "omitted"
"#);
    let transforms = build_response_transforms(&c, "p", &c.profile).unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CONTENT_ENCODING, "gzip".parse().unwrap());
    let mut response = marshal_core::ResponseParts {
        status: http::StatusCode::CREATED,
        headers,
        body: BodyHandle::Buffered(bytes::Bytes::from(vec![b'x'; 33])),
    };

    transforms[0].apply(&request("api.example.com"), &mut response).await.unwrap();

    assert_eq!(response.status, http::StatusCode::CREATED);
    assert_eq!(response.headers["x-marshal-response-limited"], "replace");
    assert!(!response.headers.contains_key(http::header::CONTENT_ENCODING));
    let BodyHandle::Buffered(body) = response.body else { panic!("response was not buffered") };
    assert_eq!(body, "omitted");
}

#[tokio::test]
async fn byte_truncation_is_exact_and_in_limit_responses_are_unchanged() {
    let c = cfg(r#"
profile:
  default_action: deny
  response_transforms:
    body:
      - transform: limit
        max_bytes: 6
        on_oversize:
          action: truncate
          method: bytes
          marker: "[x]"
"#);
    let transforms = build_response_transforms(&c, "p", &c.profile).unwrap();
    let mut oversized = marshal_core::ResponseParts {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: BodyHandle::Buffered(bytes::Bytes::copy_from_slice("ééé!".as_bytes())),
    };
    transforms[0].apply(&request("api.example.com"), &mut oversized).await.unwrap();
    let BodyHandle::Buffered(body) = oversized.body else { panic!("response was not buffered") };
    assert_eq!(&body[..], &[0xc3, 0xa9, 0xc3, b'[', b'x', b']']);

    let mut within_limit = marshal_core::ResponseParts {
        status: http::StatusCode::OK,
        headers: http::HeaderMap::new(),
        body: BodyHandle::Buffered(bytes::Bytes::from_static(b"123456")),
    };
    transforms[0].apply(&request("api.example.com"), &mut within_limit).await.unwrap();
    assert!(!within_limit.headers.contains_key("x-marshal-response-limited"));
    let BodyHandle::Buffered(body) = within_limit.body else { panic!("response was not buffered") };
    assert_eq!(body, "123456");
}
