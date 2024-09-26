//! S3 Authentication

use crate::dto::S3AuthContext;
use crate::errors::S3AuthError;
use crate::jwt::Claims;

mod authorization {

    use crate::errors::S3AuthError;
    use crate::ops::{ReqContext, S3Handler};
    use crate::path::S3Path;
    use regex::Regex;
    use tracing::info;

    #[derive(Debug)]
    pub struct Permission {
        operations: Vec<String>,
        bucket_matcher: Regex,
        path_matcher: Option<Regex>,
        path_matcher_inverted: bool,
    }

    impl Permission {
        pub fn new(permission_str: &str) -> Result<Self, S3AuthError> {
            let parts: Vec<&str> = permission_str.split(':').collect();
            if parts.len() < 3 || parts.len() > 4 {
                return Err(S3AuthError::InvalidCredentials);
            }

            let operations = parts[1].split(',').map(String::from).collect();
            let bucket_matcher = Regex::new(&glob_to_regex(&parts[2]))
                .map_err(|_| S3AuthError::InvalidCredentials)?;

            let (path_matcher, path_matcher_inverted) = if parts.len() == 4 {
                let (inverted, pattern) = if parts[3].starts_with('!') {
                    (true, &parts[3][1..])
                } else {
                    (false, parts[3])
                };
                let regex = Regex::new(&glob_to_regex(pattern))
                    .map_err(|_| S3AuthError::InvalidCredentials)?;
                (Some(regex), inverted)
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

        pub fn matches(&self, operation: &str, bucket: &str, path: Option<&str>) -> bool {
            if !self.operations.contains(&operation.to_string()) {
                info!("not match ops");
                return false;
            }

            if !self.bucket_matcher.is_match(bucket) {
                info!("not match bucket");
                return false;
            }
            // TODO: Path ACL
            // if let Some(ref path_matcher) = self.path_matcher {
            //     if let Some(path) = path {
            //         let matches = path_matcher.is_match(path);
            //         if self.path_matcher_inverted {
            //             !matches
            //         } else {
            //             matches
            //         }
            //     } else {
            //         false
            //     }
            // } else {
            //     true
            // }
            true
        }
    }

    pub fn authorize(
        roles: &[String],
        handler: &Box<dyn S3Handler + Send + Sync>,
        context: &'_ ReqContext<'_>,
    ) -> Result<(), S3AuthError> {
        let operation = handler.kind();
        let (bucket, path) = match context.path {
            S3Path::Root => ("*", None),
            S3Path::Bucket { bucket } => (bucket, None),
            S3Path::Object { bucket, key } => (bucket, Some(key)),
        };

        info!("{:?} {:?} {:?}", operation, bucket, path);

        for role in roles {
            if let Ok(permission) = Permission::new(role) {
                info!("{:?}", &permission);
                if permission.matches(&format!("{:?}", operation), bucket, path) {
                    return Ok(());
                }
            }
        }
        Err(S3AuthError::Unauthorized)
    }

    fn glob_to_regex(pattern: &str) -> String {
        let mut regex = String::new();
        regex.push('^');
        for c in pattern.chars() {
            match c {
                '*' => regex.push_str(".*"),
                '?' => regex.push('.'),
                '.' | '+' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' => {
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
pub use authorization::authorize;

use async_trait::async_trait;

/// S3 Authentication Provider

#[async_trait]
pub trait S3Auth {
    /// lookup `secret_access_key` by `access_key_id`
    async fn get_secret_access_key(
        &self,
        context: &mut S3AuthContext<'_>,
        access_key_id: &str,
    ) -> Result<String, S3AuthError>;
}

/// JWT-based authentication provider
#[derive(Debug)]
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
    async fn get_secret_access_key(
        &self,
        context: &mut S3AuthContext<'_>,
        token: &str,
    ) -> Result<String, S3AuthError> {
        if let Some(claim) = &context.claims {
            Ok(claim.sec.clone())
        } else {
            match crate::jwt::validate_jwt(token, &self.public_key) {
                Ok(claims) => {
                    if !claims.aud.contains(&"storage".to_string()) {
                        return Err(S3AuthError::InsufficientScope);
                    }
                    let cloned = claims.sec.clone();
                    context.claims = Some(claims);
                    Ok(cloned)
                }
                Err(_) => Err(S3AuthError::InvalidToken),
            }
        }
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
