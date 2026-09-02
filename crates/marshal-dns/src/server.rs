//! The DNS listener.
//!
//! Thin glue: every decision worth reasoning about is in [`crate::policy`], and this module
//! only turns a query into a call and an answer into a packet.

use std::net::IpAddr;
use std::sync::Arc;

use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{MessageType, Metadata, OpCode, ResponseCode};
use hickory_server::proto::rr::{RData, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

use crate::policy::{Answer, DnsPolicy};

#[derive(Debug, thiserror::Error)]
pub enum DnsServerError {
    #[error("binding the DNS listener on {listen}: {source}")]
    Bind {
        listen: String,
        #[source]
        source: std::io::Error,
    },

    #[error("building the upstream resolver: {0}")]
    Resolver(String),
}

/// How long clients may cache an answer.
///
/// Deliberately short. A long TTL would let a client keep resolving to the proxy after the
/// proxy has stopped, and — worse — keep a passthrough answer alive after policy changed.
const TTL_SECONDS: u32 = 30;

pub struct DnsServer {
    policy: Arc<DnsPolicy>,
    resolver: Arc<hickory_resolver::TokioResolver>,
}

impl std::fmt::Debug for DnsServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsServer").field("policy", &self.policy).finish_non_exhaustive()
    }
}

impl DnsServer {
    pub fn new(policy: Arc<DnsPolicy>, resolver: Arc<hickory_resolver::TokioResolver>) -> Self {
        Self { policy, resolver }
    }

    /// Resolve a passthrough name using the host's own resolver.
    ///
    /// A failure yields no addresses rather than an error: the query is answered NOERROR with
    /// an empty section, which a client treats as "no such record" and retries sensibly. A
    /// SERVFAIL would make an upstream hiccup look like the proxy being broken.
    async fn passthrough(&self, name: &str, want: RecordType) -> Vec<IpAddr> {
        let Ok(lookup) = self.resolver.lookup_ip(name).await else {
            return Vec::new();
        };
        lookup
            .iter()
            .filter(|ip| {
                matches!(
                    (ip, want),
                    (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)
                )
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServer {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let Ok(info) = request.request_info() else {
            return respond(request, &mut response_handle, ResponseCode::FormErr, &[]).await;
        };
        let name = info.query.name().to_string();
        let record_type = info.query.query_type();
        let query_name: hickory_server::proto::rr::Name = info.query.name().into();

        // Only address queries are answered. Anything else — MX, TXT, SRV — is not something
        // an HTTP proxy can meaningfully intercept, and inventing an answer would break
        // whatever legitimately asked for it.
        if !matches!(record_type, RecordType::A | RecordType::AAAA) {
            return respond(request, &mut response_handle, ResponseCode::NoError, &[]).await;
        }

        let addresses = match self.policy.answer(&name) {
            Answer::Proxy(ip) => vec![ip],
            Answer::Static(ips) => ips,
            Answer::Passthrough => self.passthrough(&name, record_type).await,
        };

        let records: Vec<Record> = addresses
            .into_iter()
            .filter(|ip| {
                matches!(
                    (ip, record_type),
                    (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)
                )
            })
            .map(|ip| {
                let rdata = match ip {
                    IpAddr::V4(v4) => RData::A(v4.into()),
                    IpAddr::V6(v6) => RData::AAAA(v6.into()),
                };
                Record::from_rdata(query_name.clone(), TTL_SECONDS, rdata)
            })
            .collect();

        respond(request, &mut response_handle, ResponseCode::NoError, &records).await
    }
}

async fn respond<R: ResponseHandler>(
    request: &Request,
    handle: &mut R,
    code: ResponseCode,
    records: &[Record],
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);

    let mut metadata = Metadata::new(request.metadata.id, MessageType::Response, OpCode::Query);
    metadata.response_code = code;
    // Authoritative: these answers are the proxy's own, not a cached copy of someone else's.
    metadata.authoritative = true;
    metadata.recursion_desired = request.metadata.recursion_desired;
    metadata.recursion_available = true;

    let response = builder.build(metadata, records, &[], &[], &[]);
    match handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            tracing::warn!(error = %e, "failed to send a DNS response");
            let mut fallback =
                Metadata::new(request.metadata.id, MessageType::Response, OpCode::Query);
            fallback.response_code = ResponseCode::ServFail;
            hickory_server::proto::op::Header { metadata: fallback, counts: Default::default() }
                .into()
        }
    }
}

/// Bind and serve DNS on UDP and TCP.
pub async fn serve(
    server: DnsServer,
    listen: &str,
) -> Result<hickory_server::Server<DnsServer>, DnsServerError> {
    let udp = tokio::net::UdpSocket::bind(listen)
        .await
        .map_err(|source| DnsServerError::Bind { listen: listen.to_string(), source })?;
    let tcp = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|source| DnsServerError::Bind { listen: listen.to_string(), source })?;

    let mut hickory = hickory_server::Server::new(server);
    hickory.register_socket(udp);
    // TCP as well as UDP: an answer with several addresses, or a large passthrough result,
    // will not fit a UDP packet and the client retries over TCP.
    hickory.register_listener(tcp, std::time::Duration::from_secs(5), 4096);
    Ok(hickory)
}
