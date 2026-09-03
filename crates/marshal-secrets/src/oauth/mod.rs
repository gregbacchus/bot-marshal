//! OAuth2 credential acquisition.
//!
//! See [`source`] for why this is a secret *source* rather than an injection kind, and
//! [`store`] for why anything is written to disk at all.

pub mod broker;
pub mod pkce;
pub mod source;
pub mod store;
pub mod token;

pub use broker::Oauth2Broker;
pub use pkce::{Pkce, challenge_s256};
pub use source::{
    AuthCodeFlow, ClientAuth, DeviceAuthorization, DevicePoll, Enrolled, Grant, Oauth2Config,
    Oauth2Source,
};
pub use store::{StoredGrant, TokenStore};
pub use token::{CachedToken, TokenResponse, describe_error};
