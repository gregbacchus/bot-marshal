use marshal_judge::{Decision, JudgeRequest, Provider, SystemOneProvider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn decision_auth_is_optional_and_request_metadata_stays_reduced() {
    for authenticated in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            let (header_end, length) = loop {
                let mut chunk = [0; 4096];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    break (end + 4, length);
                }
            };
            while bytes.len() < header_end + length {
                let mut chunk = [0; 4096];
                let count = socket.read(&mut chunk).await.unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            let headers = String::from_utf8_lossy(&bytes[..header_end]).to_lowercase();
            assert_eq!(headers.contains("authorization:"), authenticated);
            if authenticated {
                assert!(headers.contains("authorization: bearer test-key"));
            }
            let body: serde_json::Value =
                serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
            assert_eq!(body["questions"]["verdict"]["instructions"]["policy"], "Permit reads.");
            assert_eq!(
                body["state"],
                serde_json::json!({"method":"GET","host":"example.com","path":"/repo","header_names":["authorization"]})
            );
            let response = r#"{"answers":{"verdict":{"type":"choice","choice":"allow","confidence":0.95,"probabilities":{"allow":0.98,"deny":0.01,"pass":0.01}}}}"#;
            socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}", response.len()).as_bytes()).await.unwrap();
        });
        let provider = if authenticated {
            SystemOneProvider::new("nimble".into(), "test-key".into(), &origin, 0.9).unwrap()
        } else {
            SystemOneProvider::without_auth("nimble".into(), &origin, 0.9).unwrap()
        };
        let verdict = provider
            .judge(
                &JudgeRequest {
                    method: "GET".into(),
                    host: "example.com".into(),
                    path: "/repo".into(),
                    header_names: vec!["authorization".into()],
                },
                "Permit reads.",
            )
            .await
            .unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
        server.await.unwrap();
    }
}
