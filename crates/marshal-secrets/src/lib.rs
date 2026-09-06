//! Secret sources, boundary injection, and redaction.

pub mod oauth;
pub mod source;
pub mod swap;

pub use oauth::{
    Algorithm, AssertionKey, AuthCodeFlow, BootstrapCapture, Bootstrapped, CaptureMode, ClientAuth,
    DeviceAuthorization, DevicePoll, Enrolled, ExchangeSubject, Grant, Oauth2Broker, Oauth2Config,
    Oauth2Source, OauthClaimSource, StoredGrant, TokenExchange, TokenStore,
};
pub use source::{EnvSource, FileSource};
pub use swap::{Injection, SecretInjector, SecretSwap};
