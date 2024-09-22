//! JWT validation module
//!
//! This module provides functionality for validating JSON Web Tokens (JWTs)
//! and extracting their claims. It includes a `Claims` struct to represent
//! the JWT payload and a `validate_jwt` function to verify tokens.

use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// Represents the claims within a JWT
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user identifier)
    pub sub: String,
    /// Expiration time (as UNIX timestamp)
    pub exp: usize,
    /// Audience (intended recipients)
    pub aud: Vec<String>,
    /// User roles
    pub roles: Vec<String>,
}

/// Validates a JWT using the provided public key
///
/// # Arguments
///
/// * `token` - The JWT to validate
/// * `public_key` - The public key used to verify the JWT's signature
///
/// # Returns
///
/// A Result containing the validated Claims if successful, or a jsonwebtoken error if validation fails
pub fn validate_jwt(token: &str, public_key: &[u8]) -> Result<Claims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key)?;
    let validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    let token_data = decode::<Claims>(token, &key, &validation)?;
    Ok(token_data.claims)
}
