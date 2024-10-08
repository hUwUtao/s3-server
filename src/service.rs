//! S3 service

use crate::auth::ACLAuth;
use crate::auth::S3Auth;
use crate::data_structures::{OrderedHeaders, OrderedQs};
use crate::dto::S3AuthContext;
use crate::errors::{S3ErrorCode, S3Result};
use crate::headers::{AmzContentSha256, AmzDate, AuthorizationV4, CredentialV4};
use crate::headers::{AUTHORIZATION, CONTENT_TYPE, X_AMZ_CONTENT_SHA256, X_AMZ_DATE};
use crate::ops::S3Operation;
use crate::ops::{ReqContext, S3Handler};
use crate::output::S3Output;
use crate::path::{S3Path, S3PathErrorKind};
use crate::signature_v4;
use crate::storage::S3Storage;
use crate::utils::metrics::Mesurable;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::streams::aws_chunked_stream::AwsChunkedStream;
use crate::streams::multipart::{self, Multipart};
use crate::utils::{crypto, Apply};
use crate::{Body, BoxStdError, Method, Mime, Request, Response};

use std::borrow::Cow;
use std::fmt::{self, Debug};
use std::io;
use std::mem;
use std::ops::Deref;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::future::BoxFuture;
use futures::stream::{Stream, StreamExt};
use hyper::body::Bytes;

use hyper::header::HeaderValue;
use tokio::sync::RwLock;
use tracing::debug;

/// S3 service
pub struct S3Service {
    /// handlers
    handlers: Vec<Box<dyn S3Handler + Send + Sync + 'static>>,

    /// storage
    storage: Box<dyn S3Storage + Send + Sync + 'static>,

    /// auth
    auth: Option<Box<dyn S3Auth + Send + Sync + 'static>>,
}

/// Shared S3 service
#[derive(Debug)]
pub struct SharedS3Service {
    /// inner service
    inner: Arc<S3Service>,
}

impl Debug for S3Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S3Service{{...}}")
    }
}

impl Deref for SharedS3Service {
    type Target = S3Service;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Clone for SharedS3Service {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl hyper::service::Service<Request> for SharedS3Service {
    type Response = Response;

    type Error = BoxStdError;

    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(())) // FIXME: back pressue
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let service = self.clone();
        Box::pin(async move { service.hyper_call(req).await })
    }
}

use once_cell::sync::Lazy;

static BANNER: Lazy<String> = Lazy::new(|| {
    format!(
        "{}@{}<{}>",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY")
    )
});

impl S3Service {
    /// Constructs a S3 service
    pub fn new(
        storage: impl S3Storage + Send + Sync + 'static,
        path: PathBuf,
    ) -> Result<Self, io::Error> {
        // let public_key = fs::read(token_pem_file)?;
        let auth = ACLAuth::new(path);
        // let auth = JwtAuth::new(public_key);
        Ok(Self {
            handlers: crate::ops::setup_handlers(),
            storage: Box::new(storage),
            auth: Some(Box::new(RwLock::new(auth))),
        })
    }

    /// Converts `S3Service` to `SharedS3Service`
    #[must_use]
    pub fn into_shared(self) -> SharedS3Service {
        SharedS3Service {
            inner: Arc::new(self),
        }
    }

    /// call s3 service with a hyper request
    /// # Errors
    /// Returns an `Err` if any component failed
    #[tracing::instrument(
        level = "debug",
        skip(self, req),
        fields(
            method = ?req.method(),
            uri = ?req.uri(),
            start_time = ?chrono::Utc::now(),
        )
    )]
    pub async fn hyper_call(&self, req: Request) -> Result<Response, BoxStdError> {
        #[cfg(debug_assertions)]
        debug!("req = \n{:#?}", req);

        let ret = match self.handle(req).await {
            Ok(resp) => {
                let mut resp = resp;
                let _ = resp
                    .headers_mut()
                    .insert("X-Powered-By", HeaderValue::from_str(&BANNER)?);
                Ok(resp)
            }
            Err(err) => err.into_xml_response().try_into_response(),
        };

        // #[cfg(debug_assertions)]
        // match ret {
        //     Ok(ref resp) => debug!("resp = \n{:#?}", resp),
        //     Err(ref err) => error!(%err),
        // };

        Ok(ret?)
    }

    /// handle a request
    /// # Errors
    /// Returns an `Err` if any component failed
    pub async fn handle(&self, mut req: Request) -> S3Result<Response> {
        match req.uri().path() {
            "/favicon.ico" => {
                let favicon = include_bytes!("../assets/favicon.ico");
                let mut res = Response::new(Body::from(favicon.to_vec()));
                let _ = res
                    .headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("image/x-icon"));
                return Ok(res);
            }
            "/metrics" => {
                // Handle metrics endpoint
                let metrics = self.metrics().await;
                let mut sorted_metrics: Vec<_> = metrics.into_iter().collect();
                sorted_metrics.sort_by(|a, b| a.0.cmp(&b.0));
                let metrics_str = sorted_metrics
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Ok(Response::new(Body::from(metrics_str)));
            }
            _ => {}
        }

        // Handle S3 Request

        let mut context = S3AuthContext {
            method: &req.method().clone(),
            uri: &req.uri().clone(),
            headers: &req.headers().clone(),
            access_id: None,
        };

        let body = mem::take(req.body_mut());
        let uri_path = decode_uri_path(&req)?;
        let path = extract_s3_path(&uri_path)?;
        let headers = extract_headers(&req)?;
        let query_strings = extract_qs(&req)?;
        let mime = extract_mime(&headers)?;

        let mut ctx: ReqContext<'_> = ReqContext {
            req: &req,
            headers,
            query_strings,
            path,
            body,
            mime,
            multipart: None,
            auth: &mut context,
            auth_engine: self.auth.as_ref(),
        };

        debug!("authenticated");

        if ctx.req.method() == Method::POST && ctx.path.is_object() && ctx.multipart.is_some() {
            return Err(code_error!(
                MethodNotAllowed,
                "The specified method is not allowed against this resource."
            ));
        }

        if let Some(auth) = self.auth.as_ref() {
            for handler in &self.handlers {
                if !match handler.kind() {
                    S3Operation::ObjectGet => true,
                    S3Operation::ObjectList => true,
                    _ => false,
                } {
                    break;
                }
                if handler.is_match(&ctx) {
                    debug!("Testing handler");
                    if auth.authorize_public_query(&ctx).await.is_ok() {
                        return handler.handle(&mut ctx, &*self.storage).await;
                    }
                }
            }
            check_signature(&mut ctx, auth.as_ref()).await?;
            for handler in &self.handlers {
                if handler.is_match(&ctx) {
                    auth.authorize_query(&ctx, handler, &self.storage)
                        .await
                        .map_err(super::errors::S3AuthError::into_generic_error)?;
                    debug!("Authorized");
                    return handler.handle(&mut ctx, &*self.storage).await;
                }
            }

            return Err(not_supported!("The operation is not supported yet."));
        }
        Err(not_supported!("Did not present any authentication service"))
    }
}

#[async_trait]
impl Mesurable for S3Service {
    async fn metrics(&self) -> HashMap<String, String> {
        let mut table = HashMap::new();
        if let Some(auth) = &self.auth {
            let auth_metrics = auth.metrics().await;
            table.extend(auth_metrics);
        }
        table
    }
}

/// Extract urlencoded URI from Request
fn decode_uri_path(req: &Request) -> S3Result<Cow<'_, str>> {
    urlencoding::decode(req.uri().path())
        .map_err(|e| code_error!(InvalidURI, "Cannot url decode uri path", e))
}

/// util function
fn extract_s3_path(uri_path: &str) -> S3Result<S3Path<'_>> {
    let result = S3Path::try_from_path(uri_path);
    let err = try_err!(result);
    let (code, msg) = match *err.kind() {
        S3PathErrorKind::InvalidPath => {
            (S3ErrorCode::InvalidURI, "Couldn't parse the specified URI.")
        }
        S3PathErrorKind::InvalidBucketName => (
            S3ErrorCode::InvalidBucketName,
            "The specified bucket is not valid.",
        ),
        S3PathErrorKind::KeyTooLong => (S3ErrorCode::KeyTooLongError, "Your key is too long."),
    };
    Err(code_error!(code = code, msg, err))
}

/// extrace `OrderedHeaders<'_>` from request
fn extract_headers(req: &Request) -> S3Result<OrderedHeaders<'_>> {
    let err = try_err!(OrderedHeaders::from_req(req));
    invalid_request!("Invalid headers", err).apply(Err)
}

/// extract `Option<OrderedQs>` from request
fn extract_qs(req: &Request) -> S3Result<Option<OrderedQs>> {
    let query = try_some!(req.uri().query());
    let err = try_err!(OrderedQs::from_query(query).map(Some));
    invalid_request!("Invalid query strings", err).apply(Err)
}

/// extrace `Option<Mime>` from headers
fn extract_mime(headers: &OrderedHeaders<'_>) -> S3Result<Option<Mime>> {
    let content_type = try_some!(headers.get(CONTENT_TYPE));
    let err = try_err!(content_type.parse::<Mime>().map(Some));
    invalid_request!("Invalid header: Content-Type", err).apply(Err)
}

/// extract `AmzContentSha256` from headers
fn extract_amz_content_sha256<'a>(
    headers: &'_ OrderedHeaders<'a>,
) -> S3Result<Option<AmzContentSha256<'a>>> {
    let value = try_some!(headers.get(X_AMZ_CONTENT_SHA256));
    let err = try_err!(AmzContentSha256::from_header_str(value).map(Some));
    Err(code_error!(
        XAmzContentSHA256Mismatch,
        "Invalid header: x-amz-content-sha256",
        err
    ))
}

/// extract `AuthorizationV4` from headers
fn extract_authorization_v4<'a>(
    headers: &'_ OrderedHeaders<'a>,
) -> S3Result<Option<AuthorizationV4<'a>>> {
    let value = try_some!(headers.get(AUTHORIZATION));
    let err = try_err!(AuthorizationV4::from_header_str(value).map(Some));
    Err(invalid_request!("Invalid header: Authorization", err))
}

/// extract `AmzDate` from headers
fn extract_amz_date(headers: &'_ OrderedHeaders<'_>) -> S3Result<Option<AmzDate>> {
    let value = try_some!(headers.get(X_AMZ_DATE));
    let err = try_err!(AmzDate::from_header_str(value).map(Some));
    Err(invalid_request!("Invalid header: x-amz-date", err))
}

/// replace `body` with an empty body and transform it to IO stream
fn take_io_body(body: &mut Body) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    mem::take(body).map(|try_chunk| {
        try_chunk.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Error obtaining chunk: {e}"))
        })
    })
}

/// check signature (v4)
async fn check_signature(
    ctx: &mut ReqContext<'_>,
    auth: &(dyn S3Auth + Send + Sync),
) -> S3Result<()> {
    // --- POST auth ---
    if ctx.req.method() == Method::POST {
        if let Some(mime) = ctx.mime.as_ref() {
            if mime.type_() == mime::MULTIPART && mime.subtype() == mime::FORM_DATA {
                return check_post_signature(ctx, auth).await;
            }
        }
    }

    // --- query auth ---
    if let Some(qs) = ctx.query_strings.as_ref() {
        if qs.get("X-Amz-Signature").is_some() {
            return check_presigned_url(ctx, auth).await;
        }
    }

    // --- header auth ---
    check_header_auth(ctx, auth).await
}

/// fetch secret key from auth
async fn fetch_secret_key(
    ctx: &mut S3AuthContext<'_>,
    auth: &(dyn S3Auth + Send + Sync),
    access_key: &str,
) -> S3Result<String> {
    auth.get_secret_access_key(ctx, access_key)
        .await
        .map_err(super::errors::S3AuthError::into_generic_error)
}

/// check post signature (v4)
async fn check_post_signature(
    ctx: &mut ReqContext<'_>,
    auth_provider: &(dyn S3Auth + Send + Sync),
) -> S3Result<()> {
    /// util method
    fn find_info(multipart: &Multipart) -> Option<(&str, &str, &str, &str, &str)> {
        let policy = multipart.find_field_value("policy")?;
        let x_amz_algorithm = multipart.find_field_value("x-amz-algorithm")?;
        let x_amz_credential = multipart.find_field_value("x-amz-credential")?;
        let x_amz_date = multipart.find_field_value("x-amz-date")?;
        let x_amz_signature = multipart.find_field_value("x-amz-signature")?;
        Some((
            policy,
            x_amz_algorithm,
            x_amz_credential,
            x_amz_date,
            x_amz_signature,
        ))
    }

    let mime = ctx.mime.as_ref().unwrap_or_else(|| panic!("missing mime"));

    let boundary = mime
        .get_param(mime::BOUNDARY)
        .ok_or_else(|| invalid_request!("Missing boundary"))?;

    let body = take_io_body(&mut ctx.body);

    let multipart = multipart::transform_multipart(body, boundary.as_str().as_bytes())
        .await
        .map_err(|err| invalid_request!("Invalid multipart/form-data body", err))?;
    {
        let (policy, x_amz_algorithm, x_amz_credential, x_amz_date, x_amz_signature) = {
            match find_info(&multipart) {
                None => return Err(invalid_request!("Missing required fields")),
                Some(ans) => ans,
            }
        };

        // check policy
        if !crypto::is_base64_encoded(policy.as_bytes()) {
            return Err(invalid_request!("Invalid field: policy"));
        }

        // check x_amz_algorithm
        if x_amz_algorithm != "AWS4-HMAC-SHA256" {
            return Err(not_supported!(
                "x-amz-algorithm other than AWS4-HMAC-SHA256 is not supported."
            ));
        }

        // check x_amz_credential
        let (_, credential) = CredentialV4::parse_by_nom(x_amz_credential)
            .map_err(|_err| invalid_request!("Invalid field: x-amz-credential"))?;

        // check x_amz_date
        let amz_date = AmzDate::from_header_str(x_amz_date)
            .map_err(|err| invalid_request!("Invalid field: x-amz-date", err))?;

        // fetch secret_key
        let secret_key =
            fetch_secret_key(ctx.auth, auth_provider, credential.access_key_id).await?;

        // calculate signature
        let string_to_sign = policy;
        let signature = signature_v4::calculate_signature(
            string_to_sign,
            &secret_key,
            &amz_date,
            credential.aws_region,
        );

        // check x_amz_signature
        if signature != x_amz_signature {
            return Err(signature_mismatch!());
        }
    }

    // store ctx value
    ctx.multipart = Some(multipart);

    Ok(())
}

/// check presigned url (v4)
async fn check_presigned_url(
    ctx: &mut ReqContext<'_>,
    auth_provider: &(dyn S3Auth + Send + Sync),
) -> S3Result<()> {
    let qs = ctx
        .query_strings
        .as_ref()
        .unwrap_or_else(|| panic!("missing query string"));

    let presigned_url = signature_v4::PresignedUrl::from_query(qs)
        .map_err(|err| invalid_request!("Missing presigned fields", err))?;

    // TODO: how to use it?
    let _content_sha256: Option<AmzContentSha256<'_>> = extract_amz_content_sha256(&ctx.headers)?;

    let secret_key = fetch_secret_key(
        ctx.auth,
        auth_provider,
        presigned_url.credential.access_key_id,
    )
    .await?;

    let signature = {
        let headers = ctx
            .headers
            .map_signed_headers(&presigned_url.signed_headers);

        let canonical_request = signature_v4::create_presigned_canonical_request(
            ctx.req.method(),
            ctx.req.uri().path(),
            qs.as_ref(),
            &headers,
        );

        let region = presigned_url.credential.aws_region;
        let amz_date = &presigned_url.amz_date;
        let string_to_sign =
            signature_v4::create_string_to_sign(&canonical_request, amz_date, region);

        signature_v4::calculate_signature(&string_to_sign, &secret_key, amz_date, region)
    };

    if signature != presigned_url.signature {
        return Err(signature_mismatch!());
    }

    Ok(())
}

/// check header auth (v4)
async fn check_header_auth(
    ctx: &mut ReqContext<'_>,
    auth_provider: &(dyn S3Auth + Send + Sync),
) -> S3Result<()> {
    let authorization: AuthorizationV4<'_> = {
        if let Some(mut a) = extract_authorization_v4(&ctx.headers)? {
            a.signed_headers.sort_unstable();
            a
        } else {
            return Ok(());
        }
    };

    let amz_content_sha256 = extract_amz_content_sha256(&ctx.headers)?
        .ok_or_else(|| invalid_request!("Missing header: x-amz-content-sha256"))?;

    let secret_key = fetch_secret_key(
        ctx.auth,
        auth_provider,
        authorization.credential.access_key_id,
    )
    .await?;

    let amz_date = extract_amz_date(&ctx.headers)?
        .ok_or_else(|| invalid_request!("Missing header: x-amz-date"))?;

    let is_stream = matches!(amz_content_sha256, AmzContentSha256::MultipleChunks);

    let signature = {
        let method = ctx.req.method();
        let uri_path = decode_uri_path(ctx.req)?.into_owned();
        let query_strings: &[(String, String)] =
            ctx.query_strings.as_ref().map_or(&[], AsRef::as_ref);

        // here requires that `auth.signed_headers` is sorted
        let headers = ctx
            .headers
            .map_signed_headers(&authorization.signed_headers);

        let canonical_request = if is_stream {
            signature_v4::create_canonical_request(
                method,
                &uri_path,
                query_strings,
                &headers,
                signature_v4::Payload::MultipleChunks,
            )
        } else {
            let bytes = mem::take(&mut ctx.body)
                .apply(hyper::body::to_bytes)
                .await
                .map_err(|err| invalid_request!("Can not obtain the whole request body.", err))?;

            let payload = if matches!(amz_content_sha256, AmzContentSha256::UnsignedPayload) {
                signature_v4::Payload::Unsigned
            } else if bytes.is_empty() {
                signature_v4::Payload::Empty
            } else {
                signature_v4::Payload::SingleChunk(&bytes)
            };

            let ans = signature_v4::create_canonical_request(
                method,
                &uri_path,
                query_strings,
                &headers,
                payload,
            );

            ctx.body = Body::from(bytes);

            ans
        };

        let region = authorization.credential.aws_region;
        let string_to_sign =
            signature_v4::create_string_to_sign(&canonical_request, &amz_date, region);

        signature_v4::calculate_signature(&string_to_sign, &secret_key, &amz_date, region)
    };

    if signature != authorization.signature {
        return Err(signature_mismatch!());
    }

    if is_stream {
        let body = take_io_body(&mut ctx.body);

        let chunked_stream = AwsChunkedStream::new(
            body,
            signature.into(),
            amz_date,
            authorization.credential.aws_region.into(),
            secret_key.into(),
        );

        ctx.body = Body::wrap_stream(chunked_stream);
    }

    Ok(())
}
