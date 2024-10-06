//! S3 Authentication

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::errors::S3AuthError;
use crate::ops::{ReqContext, S3Operation};
use crate::path::S3Path;
use crate::token::database::IndexDB;
use crate::utils::metrics::Mesurable;
use crate::S3Storage;
use crate::{dto::S3AuthContext, ops::S3Handler};

mod authorization {

    use std::fmt::Debug;
    use std::path::{Path, PathBuf};

    use crate::errors::S3AuthError;
    use crate::ops::S3Operation;

    use path_matchers::{glob, PathMatcher, PatternError};
    use regex::Regex;
    use tracing::debug;

    pub struct Matcher(String, Box<dyn PathMatcher + Send + Sync>);
    impl<'a> Matcher {
        pub fn new(pattern: String) -> Result<Self, PatternError> {
            let glob = Box::new(glob(&pattern)?);
            Ok(Self(pattern, glob))
        }

        pub fn matches(&self, path: &Path) -> bool {
            self.1.matches(path)
        }
    }

    impl Debug for Matcher {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&format!("Matcher({})", self.0))
        }
    }

    #[derive(Debug)]
    pub struct Permission {
        operations: Vec<String>,
        bucket_matcher: Regex,
        path_matcher: Option<Matcher>,
        path_matcher_inverted: bool,
    }

    impl Permission {
        pub fn new(permission_str: &str) -> Result<Self, S3AuthError> {
            let parts: Vec<&str> = permission_str.split(':').collect();
            if parts.len() < 3 || parts.len() > 4 {
                return Err(S3AuthError::InvalidCredentials);
            }

            let operations = parts[1].split(',').map(String::from).collect();
            let bucket_matcher = Regex::new(&glob_to_regex(parts[2]))
                .map_err(|_| S3AuthError::InvalidCredentials)?;

            let (path_matcher, path_matcher_inverted) = if parts.len() == 4 {
                (
                    Some(
                        Matcher::new(parts[3].to_owned())
                            .map_err(|_| S3AuthError::InvalidCredentials)?,
                    ),
                    parts[3].starts_with('!'),
                )
            } else {
                (None, false)
            };

            Ok(Self {
                operations,
                bucket_matcher,
                path_matcher,
                path_matcher_inverted,
            })
        }

        pub fn matches(&self, operation: &S3Operation, bucket: &str, path: Option<&str>) -> bool {
            if !self.operations.contains(&operation.to_string()) {
                debug!("not match ops");
                return false;
            }

            if !self.bucket_matcher.is_match(bucket) {
                debug!("not match bucket");
                return false;
            }
            if let Some(ref path_matcher) = self.path_matcher {
                if let Some(path) = path {
                    debug!("attempt to path matching");
                    let matches = path_matcher.matches(&PathBuf::from(path));
                    matches ^ self.path_matcher_inverted
                } else {
                    // TODO
                    // if there is no path but requested in a path required endpoint, it should not be possible
                    // there is no such case yet this is exploitable
                    true
                }
            } else {
                true
            }
        }
    }

    // pub fn authorize(
    //     roles: &[String],
    //     handler: &Box<dyn S3Handler + Send + Sync>,
    //     context: &'_ ReqContext<'_>,
    // ) -> Result<(), S3AuthError> {
    //     let operation = handler.kind();

    //     debug!("{:?} {:?} {:?}", operation, bucket, path);

    //     for role in roles {
    //         if let Ok(permission) = Permission::new(role) {
    //             // info!("{:?}", &permission);
    //             if permission.matches(&format!("{:?}", operation), bucket, path) {
    //                 return Ok(());
    //             }
    //         }
    //     }
    //     Err(S3AuthError::Unauthorized)
    // }

    fn glob_to_regex(pattern: &str) -> String {
        // info!("Parsing path glob {pattern}");
        let mut regex = String::new();
        regex.push('^');
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '*' => {
                    if chars.peek() == Some(&'*') {
                        regex.push_str("(?:|.*)");
                        let _ = chars.next();
                    } else {
                        regex.push_str("[^/]*");
                    }
                }
                '?' => regex.push_str("[^/]"),
                '$' => regex.push('.'),
                '.' | '+' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' => {
                    regex.push('\\');
                    regex.push(c);
                }
                _ => regex.push(c),
            }
        }
        regex.push('$');
        regex
    }
}
pub use authorization::{Matcher, Permission};

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::debug;
use tracing::field::debug;

/// S3 Authentication Provider

#[async_trait]
pub trait S3Auth: Mesurable {
    /// lookup `secret_access_key` by `access_key_id`
    async fn get_secret_access_key(
        &self,
        context: &mut S3AuthContext<'_>,
        access_key_id: &str,
    ) -> Result<String, S3AuthError>;

    async fn authorize_query(
        &self,
        _ctx: &'_ ReqContext<'_>,
        _handler: &Box<dyn S3Handler + Send + Sync>,
        _storage: &Box<dyn S3Storage + Send + Sync>,
    ) -> Result<(), S3AuthError> {
        Err(S3AuthError::AuthServiceUnavailable)
    }

    async fn authorize_public_query(&self, _ctx: &'_ ReqContext<'_>) -> Result<(), S3AuthError> {
        Err(S3AuthError::Unauthorized)
    }
}

/// JWT-based authentication provider
// #[derive(Debug)]
// pub struct JwtAuth {
//     public_key: Vec<u8>,
// }

// impl JwtAuth {
//     /// Constructs a new `JwtAuth`
//     pub fn new(public_key: Vec<u8>) -> Self {
//         Self { public_key }
//     }
// }

// #[async_trait]
// impl S3Auth for JwtAuth {
//     async fn get_secret_access_key(
//         &self,
//         context: &mut S3AuthContext<'_>,
//         token: &str,
//     ) -> Result<String, S3AuthError> {
//         if let Some(claim) = &context.accessId {
//             Ok(claim.sec.clone())
//         } else {
//             match crate::jwt::validate_jwt(token, &self.public_key) {
//                 Ok(claims) => {
//                     if !claims.aud.contains(&"storage".to_string()) {
//                         return Err(S3AuthError::InsufficientScope);
//                     }
//                     let cloned = claims.sec.clone();
//                     context.accessId = Some(claims);
//                     Ok(cloned)
//                 }
//                 Err(_) => Err(S3AuthError::InvalidToken),
//             }
//         }
//     }
// }

#[derive(Debug)]
pub struct ACLAuth {
    indexdb: IndexDB,
}

impl ACLAuth {
    pub fn new(fs_root: PathBuf) -> Self {
        Self {
            indexdb: IndexDB::new(fs_root).unwrap(),
        }
    }
}

#[async_trait]
impl S3Auth for RwLock<ACLAuth> {
    async fn get_secret_access_key(
        &self,
        context: &mut S3AuthContext<'_>,
        access_id: &str,
    ) -> Result<String, S3AuthError> {
        let readed = self.read().await;
        if let Some(token) = readed.indexdb.query_token(access_id) {
            context.access_id = Some(readed.indexdb.hash_string_unsafe(access_id));
            return Ok(token.get_sec_str());
        }
        Err(S3AuthError::NotSignedUp)
    }

    async fn authorize_public_query(&self, ctx: &'_ ReqContext<'_>) -> Result<(), S3AuthError> {
        let readed = self.read().await;
        if let S3Path::Object { bucket, key } = ctx.path {
            let (path_match, _) = readed
                .indexdb
                .query_is_match_indexed_public(bucket, Path::new(key));
            if path_match {
                return Ok(());
            }
        }
        if let S3Path::Bucket { bucket } = ctx.path {
            let (path_match, indexable) = readed
                .indexdb
                .query_is_match_indexed_public(bucket, Path::new(""));
            if path_match && indexable {
                return Ok(());
            }
        }
        Err(S3AuthError::Unauthorized)
    }
    // too much lock to be leased
    async fn authorize_query(
        &self,
        ctx: &'_ ReqContext<'_>,
        handler: &Box<dyn S3Handler + Send + Sync>,
        storage: &Box<dyn S3Storage + Send + Sync>,
    ) -> Result<(), S3AuthError> {
        let operation = handler.kind();
        if let Some(access_id) = ctx.auth.access_id {
            let (bucket, path) = match ctx.path {
                S3Path::Root => ("*", None),
                S3Path::Bucket { bucket } => (bucket, None),
                S3Path::Object { bucket, key } => (bucket, Some(key)),
            };

            let (perms, token) = {
                let read_guard = self.read().await;
                (
                    read_guard.indexdb.get_roles_as_permission(&access_id),
                    read_guard.indexdb.query_token_prehashed(access_id),
                )
            };

            if let (Some(perms), Some(token)) = (perms, token) {
                if perms.iter().any(|i| i.matches(&operation, bucket, path)) {
                    if operation == S3Operation::BucketCreate
                        && !storage.is_bucket_exist(bucket).await.map_err(|_| {
                            S3AuthError::InvalidBucket(
                                "Unexpected: your token origin does not exist".to_string(),
                            )
                        })?
                        && storage.is_bucket_exist(&token.origin).await.map_err(|_| {
                            S3AuthError::InvalidBucket("An bucket already exist".to_string())
                        })?
                    {
                        debug!("Now creating new bucket");
                        let mut write_guard = self.write().await;
                        return write_guard
                            .indexdb
                            .create_bucket_from(bucket, &token.origin)
                            .map_err(|e| {
                                S3AuthError::InvalidBucket(format!("Upon create bucket, {}", e))
                            });
                    }
                    let is_valid_origin = {
                        let read_guard = self.read().await;
                        (token.origin == bucket) ^ read_guard.indexdb.validate_orign(bucket, &token)
                    };
                    if is_valid_origin {
                        return Ok(());
                    } else {
                        return Err(S3AuthError::InvalidOrigin);
                    }
                }
            }
        }
        Err(S3AuthError::InsufficientScope)
    }
}

#[async_trait]
impl Mesurable for RwLock<ACLAuth> {
    async fn metrics(&self) -> HashMap<String, String> {
        self.read().await.indexdb.metrics().await
    }
}

// #[derive(Debug, Default)]
// pub struct SimpleAuth {
//     /// key map
//     map: HashMap<String, String>,
// }

// impl SimpleAuth {
//     /// Constructs a new `SimpleAuth`
//     #[must_use]
//     pub fn new() -> Self {
//         Self {
//             map: HashMap::new(),
//         }
//     }

//     /// register a credential
//     pub fn register(&mut self, access_key: String, secret_key: String) {
//         let _prev = self.map.insert(access_key, secret_key);
//     }

//     /// lookup a credential
//     #[must_use]
//     pub fn lookup(&self, access_key: &str) -> Option<&str> {
//         Some(self.map.get(access_key)?.as_str())
//     }
// }

// #[async_trait]
// impl S3Auth for SimpleAuth {
//     async fn verify_token<'a>(
//         &self,
//         _token: &str,
//         _context: &S3AuthContext<'a>,
//     ) -> Result<Box<dyn AuthCtx + Sync + Send>, S3AuthError> {
//         Err(S3AuthError::MissingToken)
//     }

//     async fn get_secret_access_key(&self, access_key_id: &str) -> Result<String, S3AuthError> {
//         self.lookup(access_key_id)
//             .map(ToOwned::to_owned)
//             .ok_or(S3AuthError::NotSignedUp)
//     }
// }
