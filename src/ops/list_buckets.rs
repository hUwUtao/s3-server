//! [`ListBuckets`](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html)

use std::ops::Deref;

use super::{wrap_internal_error, ReqContext, S3Handler};

use crate::dto::{ListBucketsError, ListBucketsOutput, ListBucketsRequest};
use crate::errors::{S3Error, S3Result};
use crate::output::S3Output;
use crate::storage::S3Storage;
use crate::utils::{ResponseExt, XmlWriterExt};
use crate::{async_trait, Method, Response};

/// `ListBuckets` handler
pub struct Handler;

#[async_trait]
impl S3Handler for Handler {
    ops_kind! {BucketList}

    fn is_match(&self, ctx: &'_ ReqContext<'_>) -> bool {
        bool_try!(ctx.req.method() == Method::GET);
        ctx.path.is_root()
    }

    async fn handle(
        &self,
        ctx: &mut ReqContext<'_>,
        storage: &(dyn S3Storage + Send + Sync),
    ) -> S3Result<Response> {
        let input = extract(ctx)?;
        if let Some(auth_engine) = ctx.auth_engine {
            if let Ok(matchers) = auth_engine
                .as_ref()
                .get_listops_matchers(ctx.auth.deref())
                .await
            {
                let output = storage
                    .list_buckets(input)
                    .await
                    .map(|f| ListBucketsOutput {
                        buckets: f.buckets.map(|b| {
                            b.iter()
                                .filter(|bn| {
                                    matchers.iter().any(|m| {
                                        m.match_listops(bn.name.as_ref().unwrap_or(&String::new()))
                                    })
                                })
                                .map(|f| f.clone())
                                .collect::<Vec<_>>()
                        }),
                        ..f
                    });
                return output.try_into_response();
            }
        }
        ListBucketsOutput::default().try_into_response()
    }
}

/// extract operation request
fn extract(_: &mut ReqContext<'_>) -> S3Result<ListBucketsRequest> {
    Ok(ListBucketsRequest)
}

impl S3Output for ListBucketsOutput {
    #[allow(clippy::shadow_unrelated)]
    fn try_into_response(self) -> S3Result<Response> {
        wrap_internal_error(|res| {
            res.set_xml_body(4096, |w| {
                w.stack("ListAllMyBucketsResult", |w| {
                    w.opt_stack("Buckets", self.buckets, |w, buckets| {
                        for bucket in buckets {
                            w.stack("Bucket", |w| {
                                w.opt_element("CreationDate", bucket.creation_date)?;
                                w.opt_element("Name", bucket.name)
                            })?;
                        }
                        Ok(())
                    })?;

                    w.opt_stack("Owner", self.owner, |w, owner| {
                        w.opt_element("DisplayName", owner.display_name)?;
                        w.opt_element("ID", owner.id)
                    })?;
                    Ok(())
                })
            })
        })
    }
}

impl From<ListBucketsError> for S3Error {
    fn from(e: ListBucketsError) -> Self {
        match e {}
    }
}
