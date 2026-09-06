//! OAuth2 credential acquisition.
//!
//! See [`source`] for why this is a secret *source* rather than an injection kind, and
//! [`store`] for why anything is written to disk at all.

pub mod bootstrap;
pub mod broker;
pub mod claim;
pub(crate) mod form;
pub mod jwt;
pub mod pkce;
pub mod source;
pub mod store;
pub mod token;

pub use bootstrap::{BootstrapCapture, Bootstrapped, CaptureMode};
pub use broker::Oauth2Broker;
pub use claim::OauthClaimSource;
pub use jwt::{Algorithm, Claims};
pub use pkce::{Pkce, challenge_s256};
pub use source::{
    AssertionKey, AuthCodeFlow, ClientAuth, DeviceAuthorization, DevicePoll, Enrolled,
    ExchangeSubject, Grant, Oauth2Config, Oauth2Source, TokenExchange,
};
pub use store::{StoredGrant, TokenStore};
pub use token::{CachedToken, TokenResponse, decode_id_token_claims, describe_error};
