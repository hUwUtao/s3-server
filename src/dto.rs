//! S3 data transfer objects

use hyper::{HeaderMap, Method, Uri};
pub use rusoto_core::ByteStream;
pub use rusoto_s3::{
    Bucket, CompleteMultipartUploadError, CompleteMultipartUploadOutput,
    CompleteMultipartUploadRequest, CompletedMultipartUpload, CompletedPart, CopyObjectError,
    CopyObjectOutput, CopyObjectRequest, CopyObjectResult, CreateBucketConfiguration,
    CreateBucketError, CreateBucketOutput, CreateBucketRequest, CreateMultipartUploadError,
    CreateMultipartUploadOutput, CreateMultipartUploadRequest, Delete, DeleteBucketError,
    DeleteBucketRequest, DeleteObjectError, DeleteObjectOutput, DeleteObjectRequest,
    DeleteObjectsError, DeleteObjectsOutput, DeleteObjectsRequest, DeletedObject,
    GetBucketLocationError, GetBucketLocationOutput, GetBucketLocationRequest, GetObjectError,
    GetObjectOutput, GetObjectRequest, HeadBucketError, HeadBucketRequest, HeadObjectError,
    HeadObjectOutput, HeadObjectRequest, ListBucketsError, ListBucketsOutput, ListObjectsError,
    ListObjectsOutput, ListObjectsRequest, ListObjectsV2Error, ListObjectsV2Output,
    ListObjectsV2Request, Object, ObjectIdentifier, Owner, PutObjectError, PutObjectOutput,
    PutObjectRequest, UploadPartError, UploadPartOutput, UploadPartRequest,
};

use crate::jwt::Claims;

/// S3 authentication context
///
/// This struct contains the necessary information from an HTTP request
/// to perform S3 authentication and authorization.
#[derive(Debug)]
pub struct S3AuthContext<'a> {
    /// The HTTP method of the request
    pub method: &'a Method,
    /// The URI of the request
    pub uri: &'a Uri,
    /// The headers of the request
    pub headers: &'a HeaderMap,
    /// The mutable claims for authorization
    pub claims: Option<Claims>,
}

/// `DeleteBucketOutput`
#[derive(Debug, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct DeleteBucketOutput;

/// `HeadBucketOutput`
#[derive(Debug, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct HeadBucketOutput;

/// `HeadBucketOutput`
#[derive(Debug, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct ListBucketsRequest;
