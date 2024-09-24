mod authorization {
    use crate::dto::S3AuthContext;
    use crate::errors::S3AuthError;
    use regex::Regex;

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

        pub fn matches(&self, operation: &S3Operation, bucket: &str, path: Option<&str>) -> bool {
            if !self.operations.contains(&operation.into()) {
                return false;
            }

            if !self.bucket_matcher.is_match(bucket) {
                return false;
            }

            if let Some(ref path_matcher) = self.path_matcher {
                if let Some(path) = path {
                    let matches = path_matcher.is_match(path);
                    if self.path_matcher_inverted {
                        !matches
                    } else {
                        matches
                    }
                } else {
                    false
                }
            } else {
                true
            }
        }
    }

    pub fn authorize(
        jwt_ctx: &JwtCtx,
        handler: &dyn S3Handler,
        context: &S3AuthContext,
    ) -> Result<(), S3AuthError> {
        for role in &jwt_ctx.0.roles {
            if let Ok(permission) = Permission::new(role) {
                if permission.matches(&handler.kind(), &context.bucket, context.path.as_deref()) {
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
