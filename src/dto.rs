//! S3 data transfer objects

use hyper::{HeaderMap, Method, Uri};
pub use rusoto_core::ByteStream;
pub use rusoto_s3::{
    Bucket, CommonPrefix, CompleteMultipartUploadError, CompleteMultipartUploadOutput,
    CompleteMultipartUploadRequest, CompletedMultipartUpload, CompletedPart, CopyObjectError,
    CopyObjectOutput, CopyObjectRequest, CopyObjectResult, CreateBucketConfiguration,
    CreateBucketError, CreateBucketOutput, CreateBucketRequest, CreateMultipartUploadError,
    CreateMultipartUploadOutput, CreateMultipartUploadRequest, Delete, DeleteBucketError,
    DeleteBucketRequest, DeleteObjectError, DeleteObjectOutput, DeleteObjectRequest,
    DeleteObjectsError, DeleteObjectsOutput, DeleteObjectsRequest, DeletedObject,
    GetBucketLocationError, GetBucketLocationOutput, GetBucketLocationRequest, GetObjectError,
    GetObjectOutput, GetObjectRequest, HeadBucketError, HeadBucketRequest, HeadObjectError,
    HeadObjectOutput, HeadObjectRequest, ListBucketsError, ListBucketsOutput, ListObjectsError,
    ListObjectsRequest, ListObjectsV2Error, ListObjectsV2Output, ListObjectsV2Request, Object,
    ObjectIdentifier, Owner, PutObjectError, PutObjectOutput, PutObjectRequest, UploadPartError,
    UploadPartOutput, UploadPartRequest,
};

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
    pub access_id: Option<u64>,
}

/// `DeleteBucketOutput`
#[derive(Debug, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct DeleteBucketOutput;

/// `ListObjectsOutput`
#[derive(Debug, Default)]
pub struct ListObjectsOutput {
    /// Bucket name.
    pub name: Option<String>,
    /// A list of objects.
    pub contents: Option<Vec<Object>>,
    /// A list of common prefixes.
    pub common_prefixes: Option<Vec<CommonPrefix>>,
    /// A flag that indicates whether or not all of the results were returned.
    pub is_truncated: Option<bool>,
    /// Indicates where in the bucket listing begins.
    pub marker: Option<String>,
    /// Indicates where in the bucket listing to begin in the next request.
    pub next_marker: Option<String>,
    /// The maximum number of keys returned in the response body.
    pub max_keys: Option<i32>,
    /// Limits the response to keys that begin with the specified prefix.
    pub prefix: Option<String>,
    /// Encoding type used by Amazon S3 to encode object keys in the response.
    pub encoding_type: Option<String>,
    /// A delimiter is a character you use to group keys.
    pub delimiter: Option<String>,
}

/// `HeadBucketOutput`
#[derive(Debug, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct HeadBucketOutput;

/// `HeadBucketOutput`
#[derive(Debug, Clone, Copy)]
#[allow(clippy::exhaustive_structs)]
pub struct ListBucketsRequest;
