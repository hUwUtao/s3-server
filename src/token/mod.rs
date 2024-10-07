use std::{collections::HashMap, u64};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::debug;

// use crate::jwt::Claims;
pub(crate) mod database;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Token {
    /// Billing Reported Subject
    pub sub: u64,
    /// Security Issued at
    pub iat: u64,
    /// Unreported cryptographic key. An unhashed version of secret key.
    pub jti: u128,
    /// Security Expire at
    pub exp: Option<u64>,
    /// Origin bucket AD
    pub origin: String,
    /// Roles
    pub roles: Vec<String>,
}

// impl From<&Token> for Claims {
//     fn from(val: &Token) -> Self {
//         Self {
//             sub: val.sub.to_string(),
//             exp: val.exp.unwrap_or(u64::MAX) as usize,
//             aud: vec!["s3".to_owned()],
//             sec: val.jti.to_string(),
//             roles: val.roles.clone(),
//         }
//     }
// }

impl Token {
    pub fn get_sec_str(&self) -> String {
        use sha2::{Digest, Sha512};

        let mut hasher = Sha512::new();
        hasher.update(self.sub.to_be_bytes());
        hasher.update(self.iat.to_be_bytes());
        hasher.update(self.jti.to_be_bytes());
        let hashed = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
            [0x48, 0x45]
                .iter()
                .copied()
                .chain(hasher.finalize().iter().copied())
                .collect::<Vec<u8>>(),
        );

        debug!("{}", &hashed);

        hashed
    }

    pub fn set_jti(&mut self, new: u128) {
        self.jti = new;
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BucketConfigFile {
    /// Which paths should be publiced
    pub public: Vec<String>,
    /// Do public paths indexible?
    pub indexable: Option<bool>,
    /// A list of bucket, which token is defined in that bucket is allowed here. Determined by token's origin claim
    pub allows: Vec<String>,
    /// Who owns this bucket? metadata preserved for future query
    pub owners: Vec<u64>,
    /// The tokens
    pub tokens: HashMap<String, Token>,
}
