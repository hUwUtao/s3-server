//! S3 Authentication

use crate::dto::S3AuthContext;
use crate::errors::S3AuthError;

use std::collections::HashMap;

use async_trait::async_trait;

/// S3 Authentication Provider
#[async_trait]
pub trait S3Auth {
    /// Verify the authentication token
    async fn verify_token<'a>(
        &self,
        token: &str,
        context: &S3AuthContext<'a>,
    ) -> Result<(), S3AuthError>;

    /// lookup `secret_access_key` by `access_key_id`
    async fn get_secret_access_key(&self, access_key_id: &str) -> Result<String, S3AuthError>;
}

/// JWT-based authentication provider
pub struct JwtAuth {
    public_key: Vec<u8>,
}

impl JwtAuth {
    /// Constructs a new `JwtAuth`
    pub fn new(public_key: Vec<u8>) -> Self {
        Self { public_key }
    }
}

#[async_trait]
impl S3Auth for JwtAuth {
    async fn verify_token<'a>(
        &self,
        token: &str,
        _context: &S3AuthContext<'a>,
    ) -> Result<(), S3AuthError> {
        match crate::jwt::validate_jwt(token, &self.public_key) {
            Ok(_) => Ok(()),
            Err(_) => Err(S3AuthError::InvalidToken),
        }
    }

    async fn get_secret_access_key(&self, _access_key_id: &str) -> Result<String, S3AuthError> {
        Err(S3AuthError::NotSignedUp)
    }
}

/// A ~~simple~~ JWT-based authentication provider
#[derive(Debug, Default)]
pub struct SimpleAuth {
    /// key map
    map: HashMap<String, String>,
}

impl SimpleAuth {
    /// Constructs a new `SimpleAuth`
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// register a credential
    pub fn register(&mut self, access_key: String, secret_key: String) {
        let _prev = self.map.insert(access_key, secret_key);
    }

    /// lookup a credential
    #[must_use]
    pub fn lookup(&self, access_key: &str) -> Option<&str> {
        Some(self.map.get(access_key)?.as_str())
    }
}

#[async_trait]
impl S3Auth for SimpleAuth {
    async fn verify_token<'a>(
        &self,
        _token: &str,
        _context: &S3AuthContext<'a>,
    ) -> Result<(), S3AuthError> {
        Err(S3AuthError::MissingToken)
    }

    async fn get_secret_access_key(&self, access_key_id: &str) -> Result<String, S3AuthError> {
        self.lookup(access_key_id)
            .map(ToOwned::to_owned)
            .ok_or(S3AuthError::NotSignedUp)
    }
}
