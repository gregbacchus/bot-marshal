//! Live LLM-router acceptance: deferred CONNECT, mapped-origin guard/connect, request dialect
//! translation, credential stripping, and response translation through the actual MITM path.

mod support;

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{
    AuditSink, DenyingDecider, RequestResponder, RequestTransform, ResponseTransform,
};
use marshal_llm::LlmRouter;
use marshal_policy::{HostMatcher, build_chain};
use marshal_proxy::mitm::TlsEngine;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn connect_named(
    proxy: std::net::SocketAddr,
    host: &str,
    ca_pem: &str,
) -> hyper::client::conn::http1::SendRequest<TestBody> {
    let mut tcp = tokio::net::TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"), "{head:?}");

    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).unwrap();
    let tls =
        tokio_rustls::TlsConnector::from(client_config(ca_pem)).connect(name, tcp).await.unwrap();
    let (sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

#[tokio::test]
async fn openai_client_routes_to_anthropic_origin_and_gets_openai_response() {
    let pki = test_pki();
    let origin = start_tls_upstream(&pki).await;
    let generated = marshal_tls::CertificateAuthority::generate("LLM router proxy CA", 30).unwrap();
    let proxy_ca_pem = generated.cert_pem.clone();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 16, 72));
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let yaml = format!(
        r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: {{ domains: ["llm.test"] }}
      on_match: allow
      on_miss: pass
  request_transforms:
    llm_router:
      listen: [{{ dialect: openai, hosts: ["llm.test"] }}]
      models:
        smart:
          model: "claude-origin"
          dialect: anthropic
          host: "127.0.0.1"
          port: {}
"#,
        origin.port()
    );
    let cfg: Config = serde_yaml_ng::from_str(&yaml).unwrap();
    let chain = build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap();
    let router =
        Arc::new(LlmRouter::new(cfg.profile.request_transforms.llm_router.clone().unwrap()));
    let runtime = runtime_with_responders(
        chain,
        engine,
        HostMatcher::default(),
        vec![Arc::clone(&router) as Arc<dyn RequestTransform>],
        vec![Arc::clone(&router) as Arc<dyn ResponseTransform>],
        vec![router as Arc<dyn RequestResponder>],
    );
    let audit: Arc<dyn AuditSink> = Arc::new(JsonSink::new(tokio::io::sink()));
    let server = Server::new(
        ServerConfig { listen: vec!["127.0.0.1:0".into()], unix_socket: None },
        handle(runtime),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        audit,
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |address| {
                let _ = tx.take().unwrap().send(address);
            })
            .await;
    });

    let mut client = connect_named(rx.await.unwrap(), "llm.test", &proxy_ca_pem).await;
    let request_body = serde_json::to_vec(&serde_json::json!({
        "model": "smart",
        "messages": [
            {"role": "system", "content": "be brief"},
            {"role": "user", "content": "hello"}
        ],
        "max_tokens": 32
    }))
    .unwrap();
    let request = hyper::Request::builder()
        .method("POST")
        .uri("https://llm.test/v1/chat/completions")
        .header("host", "llm.test")
        .header("content-type", "application/json")
        .header("authorization", "Bearer must-not-reach-origin")
        .body(Full::new(bytes::Bytes::from(request_body)).map_err(std::io::Error::other).boxed())
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(document["object"], "chat.completion");
    assert_eq!(document["model"], "smart");
    assert_eq!(document["choices"][0]["message"]["content"], "routed hello");
}

#[tokio::test]
async fn system_one_client_reaches_mapped_origin_and_gets_native_answers() {
    let pki = test_pki();
    let origin = start_tls_upstream(&pki).await;
    let generated = marshal_tls::CertificateAuthority::generate("LLM router proxy CA", 30).unwrap();
    let proxy_ca_pem = generated.cert_pem.clone();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 16, 72));
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let yaml = format!(
        r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: {{ domains: ["llm.test"] }}
      on_match: allow
      on_miss: pass
  request_transforms:
    llm_router:
      listen: [{{ dialect: system_one, hosts: ["llm.test"] }}]
      models:
        smart:
          model: "decision-origin"
          dialect: system_one
          host: "127.0.0.1"
          port: {}
"#,
        origin.port()
    );
    let cfg: Config = serde_yaml_ng::from_str(&yaml).unwrap();
    let chain = build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap();
    let router =
        Arc::new(LlmRouter::new(cfg.profile.request_transforms.llm_router.clone().unwrap()));
    let runtime = runtime_with_responders(
        chain,
        engine,
        HostMatcher::default(),
        vec![Arc::clone(&router) as Arc<dyn RequestTransform>],
        vec![Arc::clone(&router) as Arc<dyn ResponseTransform>],
        vec![router as Arc<dyn RequestResponder>],
    );
    let audit: Arc<dyn AuditSink> = Arc::new(JsonSink::new(tokio::io::sink()));
    let server = Server::new(
        ServerConfig { listen: vec!["127.0.0.1:0".into()], unix_socket: None },
        handle(runtime),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        audit,
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |address| {
                let _ = tx.take().unwrap().send(address);
            })
            .await;
    });

    let mut client = connect_named(rx.await.unwrap(), "llm.test", &proxy_ca_pem).await;
    let request_body = serde_json::to_vec(&serde_json::json!({
        "model": "smart",
        "state": {"task": "hello"},
        "questions": {"route": {"type": "choice", "instructions": "Pick a route", "criteria": {"fast": "Simple", "slow": "Complex"}}}
    }))
    .unwrap();
    let request = hyper::Request::builder()
        .method("POST")
        .uri("https://llm.test/v1/systemone")
        .header("host", "llm.test")
        .header("content-type", "application/json")
        .header("authorization", "Bearer must-not-reach-origin")
        .body(Full::new(bytes::Bytes::from(request_body)).map_err(std::io::Error::other).boxed())
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(document["model"], "smart");
    assert_eq!(document["answers"]["route"]["choice"], "fast");
    assert_eq!(document["answers"]["route"]["confidence"], 0.95);
}
