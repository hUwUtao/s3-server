use std::{collections::HashMap, u64};

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::jwt::Claims;
pub(crate) mod database;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Token {
    /// Billing Reported Subject
    sub: u64,
    /// Security Issued at
    iat: u64,
    /// Unreported cryptographic key. An unhashed version of secret key.
    jti: u128,
    /// Security Expire at
    exp: Option<u64>,
    /// Origin bucket AD
    origin: String,
    /// Roles
    roles: Vec<String>,
}

impl Into<Claims> for &Token {
    fn into(self) -> Claims {
        Claims {
            sub: self.sub.to_string(),
            exp: self.exp.unwrap_or(u64::MAX) as usize,
            aud: vec!["s3".to_string()],
            sec: self.jti.to_string(),
            roles: self.roles.clone(),
        }
    }
}

impl Token {
    pub fn get_sec_str(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.jti.to_be_bytes())
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BucketConfigFile {
    /// Which paths should be publiced
    public: Vec<String>,
    /// Which bucket can allow role from this bucket
    /// If the token, whose origin is from which bucket, is the origin specified here?
    allows: String,
    /// Who owns this bucket? metadata preserved for future query
    owners: Vec<u64>,
    /// The tokens
    tokens: HashMap<String, Token>,
}
