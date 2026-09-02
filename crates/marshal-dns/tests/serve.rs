//! End-to-end DNS: real queries over a real socket.
//!
//! The policy is unit-tested as a function of a name; this exercises the wire format, which
//! is where a DNS implementation actually goes wrong.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig,
};
use marshal_dns::{DnsPolicy, DnsServer};

/// Start the DNS server on an ephemeral port and return a resolver pointed at it.
async fn start(policy: DnsPolicy) -> TokioResolver {
    // The server's own upstream resolver. Never consulted by these tests, which avoid
    // passthrough names precisely so the suite does not depend on the network.
    let upstream = Arc::new(
        hickory_resolver::Resolver::builder_with_config(
            ResolverConfig::default(),
            Default::default(),
        )
        .build()
        .expect("upstream resolver builds"),
    );

    let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let mut server = hickory_server::Server::new(DnsServer::new(Arc::new(policy), upstream));
    server.register_socket(listener);
    tokio::spawn(async move {
        let _ = server.block_until_done().await;
    });

    let mut connection = ConnectionConfig::new(ProtocolConfig::Udp);
    connection.port = addr.port();
    let config = ResolverConfig::from_parts(
        None,
        Vec::new(),
        vec![NameServerConfig::new(addr.ip(), false, vec![connection])],
    );
    let mut builder = hickory_resolver::Resolver::builder_with_config(config, Default::default());
    builder.options_mut().attempts = 1;
    builder.options_mut().timeout = std::time::Duration::from_secs(3);
    builder.build().expect("test resolver builds")
}

fn policy() -> DnsPolicy {
    DnsPolicy::new(
        "10.16.0.1".parse().unwrap(),
        &["*.internal.corp".to_string()],
        [("db.example.com".to_string(), vec!["10.0.0.5".parse::<IpAddr>().unwrap()])],
    )
    .unwrap()
}

#[tokio::test]
async fn arbitrary_names_resolve_to_the_proxy() {
    // The whole point of DNS mode: a client that was never configured still arrives at the
    // proxy, because that is what its own resolver told it to do.
    let resolver = start(policy()).await;
    let answer = resolver.lookup_ip("api.github.com.").await.expect("a response");
    let ips: Vec<IpAddr> = answer.iter().collect();
    assert_eq!(ips, ["10.16.0.1".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn static_records_are_returned_verbatim() {
    let resolver = start(policy()).await;
    let answer = resolver.lookup_ip("db.example.com.").await.expect("a response");
    let ips: Vec<IpAddr> = answer.iter().collect();
    assert_eq!(ips, ["10.0.0.5".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn a_records_and_aaaa_records_do_not_bleed_into_each_other() {
    // The proxy address here is IPv4, so an AAAA query must come back empty rather than
    // carrying an A record in an AAAA answer, which some clients accept and then misuse.
    let resolver = start(policy()).await;
    let answer = resolver.ipv6_lookup("api.github.com.").await;
    match answer {
        Err(_) => {}
        Ok(records) => {
            assert_eq!(records.answers().len(), 0, "AAAA carried an A record")
        }
    }
}

#[tokio::test]
async fn non_address_queries_are_answered_empty_rather_than_invented() {
    // An HTTP proxy cannot meaningfully intercept MX or TXT, and answering with the proxy's
    // address would break whatever legitimately asked.
    let resolver = start(policy()).await;
    let answer = resolver.lookup("example.com.", hickory_resolver::proto::rr::RecordType::MX).await;
    match answer {
        Err(_) => {}
        Ok(records) => assert_eq!(records.answers().len(), 0),
    }
}

#[tokio::test]
async fn answers_carry_a_short_ttl() {
    // A long TTL would let clients keep resolving to the proxy after it stops, and keep a
    // passthrough answer alive after policy changed.
    let resolver = start(policy()).await;
    let answer = resolver.lookup_ip("anything.test.").await.expect("a response");
    let ttl = answer.as_lookup().answers().first().map(|r| r.ttl).unwrap();
    assert!(ttl <= 60, "ttl was {ttl}");
}
