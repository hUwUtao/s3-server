//! fs implementation

use crate::async_trait;
use crate::data_structures::BytesStream;
use crate::dto::{
    Bucket, CommonPrefix, CompleteMultipartUploadError, CompleteMultipartUploadOutput,
    CompleteMultipartUploadRequest, CopyObjectError, CopyObjectOutput, CopyObjectRequest,
    CopyObjectResult, CreateBucketError, CreateBucketOutput, CreateBucketRequest,
    CreateMultipartUploadError, CreateMultipartUploadOutput, CreateMultipartUploadRequest,
    DeleteBucketError, DeleteBucketOutput, DeleteBucketRequest, DeleteObjectError,
    DeleteObjectOutput, DeleteObjectRequest, DeleteObjectsError, DeleteObjectsOutput,
    DeleteObjectsRequest, DeletedObject, GetBucketLocationError, GetBucketLocationOutput,
    GetBucketLocationRequest, GetObjectError, GetObjectOutput, GetObjectRequest, HeadBucketError,
    HeadBucketOutput, HeadBucketRequest, HeadObjectError, HeadObjectOutput, HeadObjectRequest,
    ListBucketsError, ListBucketsOutput, ListBucketsRequest, ListObjectsError, ListObjectsOutput,
    ListObjectsRequest, ListObjectsV2Error, ListObjectsV2Output, ListObjectsV2Request, Object,
    PutObjectError, PutObjectOutput, PutObjectRequest, UploadPartError, UploadPartOutput,
    UploadPartRequest,
};
use crate::errors::{S3StorageError, S3StorageResult};
use crate::headers::{AmzCopySource, Range};
use crate::path::S3Path;
use crate::storage::S3Storage;
use crate::utils::{crypto, time, Apply};

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryInto;
use std::env;
use std::io::{self, SeekFrom};
use std::path::{Component, Path, PathBuf};

use futures::io::{AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufWriter};
use futures::stream::{Stream, StreamExt, TryStreamExt};
use hyper::body::Bytes;
use md5::{Digest, Md5};
use path_absolutize::Absolutize;
use tracing::{debug, error};
use uuid::Uuid;

use async_fs::File;

/// A S3 storage implementation based on file system
#[derive(Debug)]
pub struct FileSystem {
    /// root path
    root: PathBuf,
}

impl FileSystem {
    /// Constructs a file system storage located at `root`
    /// # Errors
    /// Returns an `Err` if current working directory is invalid or `root` doesn't exist
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = env::current_dir()?.join(root).canonicalize()?;
        Ok(Self { root })
    }

    /// resolve object path under the virtual root
    fn get_object_path(&self, bucket: &str, key: &str) -> io::Result<PathBuf> {
        let dir = Path::new(&bucket);
        let file_path = Path::new(&key);
        let ans = dir.join(file_path).absolutize_virtually(&self.root)?.into();
        Ok(ans)
    }

    /// resolve bucket path under the virtual root
    fn get_bucket_path(&self, bucket: &str) -> io::Result<PathBuf> {
        let dir = Path::new(&bucket);
        let ans = dir.absolutize_virtually(&self.root)?.into();
        Ok(ans)
    }

    /// resolve metadata path under the virtual root (custom format)
    fn get_metadata_path(&self, bucket: &str, key: &str) -> io::Result<PathBuf> {
        let encode = |s: &str| base64_simd::URL_SAFE_NO_PAD.encode_to_string(s);

        let file_path_str = format!(
            ".bucket-{}.object-{}.metadata.json",
            encode(bucket),
            encode(key),
        );
        let file_path = Path::new(&file_path_str);
        let ans = file_path.absolutize_virtually(&self.root)?.into();
        Ok(ans)
    }

    /// load metadata from fs
    async fn load_metadata(
        &self,
        bucket: &str,
        key: &str,
    ) -> io::Result<Option<HashMap<String, String>>> {
        let path = self.get_metadata_path(bucket, key)?;
        if path.exists() {
            let content = async_fs::read(&path).await?;
            let map = serde_json::from_slice(&content)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Ok(Some(map))
        } else {
            Ok(None)
        }
    }

    /// save metadata
    async fn save_metadata(
        &self,
        bucket: &str,
        key: &str,
        metadata: &HashMap<String, String>,
    ) -> io::Result<()> {
        let path = self.get_metadata_path(bucket, key)?;
        let content = serde_json::to_vec(metadata)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        async_fs::write(&path, &content).await
    }

    /// get md5 sum
    async fn get_md5_sum(&self, bucket: &str, key: &str) -> io::Result<String> {
        let object_path = self.get_object_path(bucket, key)?;
        let mut file = File::open(&object_path).await?;
        let mut buf = vec![0; 4_usize.wrapping_mul(1024).wrapping_mul(1024)];
        let mut md5_hash = Md5::new();
        loop {
            let nread = file.read(&mut buf).await?;
            if nread == 0 {
                break;
            }
            md5_hash.update(buf.get(..nread).unwrap_or_else(|| {
                panic!(
                    "nread is larger than buffer size: nread = {}, size = {}",
                    nread,
                    buf.len()
                )
            }));
        }
        md5_hash.finalize().apply(crypto::to_hex_string).apply(Ok)
    }
    fn parse_prefix_and_delimiter(
        &self,
        prefix: &Option<String>,
        delimiter: &Option<String>,
    ) -> (PathBuf, String) {
        // Unwrap the prefix option, defaulting to an empty string if None
        let prefix = prefix.as_deref().unwrap_or("");
        println!("Input prefix: {:?}", prefix);

        // Unwrap the delimiter option, defaulting to "/" if None
        let delimiter = delimiter.as_deref().unwrap_or("/");
        println!("Input delimiter: {:?}", delimiter);

        if prefix.ends_with(delimiter) {
            // If the prefix ends with the delimiter, return the full prefix as the path
            // and an empty string as the prefix filter
            println!("Prefix ends with delimiter. Returning full prefix as path.");
            (PathBuf::from(prefix), String::new())
        } else {
            // Split the prefix into components using the delimiter
            let mut components: Vec<&str> = prefix.split(delimiter).collect();
            println!("Split components: {:?}", components);

            // Pop the last component to use as the prefix filter, defaulting to an empty string
            let prefix_filter = components.pop().unwrap_or("").to_string();
            println!("Prefix filter: {:?}", prefix_filter);

            // Join the remaining components to form the path
            let path = PathBuf::from(components.join(delimiter));
            println!("Resulting path: {:?}", path);

            (path, prefix_filter)
        }
    }

    async fn list_contents(
        &self,
        has_prefix: bool,
        bucket_path: &Path,
        search_path: &Path,
        prefix_filter: &str,
        delimiter: &Option<String>,
        max_keys: i64,
    ) -> io::Result<(Vec<Object>, HashSet<String>)> {
        let mut objects = Vec::new();
        let mut common_prefixes = HashSet::new();

        if has_prefix {
            let mut entries = async_fs::read_dir(search_path).await?;

            while let Some(entry) = entries.next().await {
                if objects.len() as i64 >= max_keys {
                    break;
                }

                let entry = entry?;
                let file_type = entry.file_type().await?;
                let file_path = entry.path();
                let key = file_path
                    .strip_prefix(bucket_path)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");

                let file_name = file_path.file_name().unwrap().to_str().unwrap();
                if !file_name.starts_with(&prefix_filter) {
                    continue;
                }

                if file_type.is_dir() {
                    if let Some(delimiter) = delimiter {
                        let common_prefix = format!("{}{}", key, delimiter);
                        let _ = common_prefixes.insert(common_prefix);
                    }
                } else {
                    self.add_object(&mut objects, &file_path, &key).await?;
                }
            }
        } else {
            self.list_contents_recursively(
                &mut objects,
                bucket_path,
                search_path,
                prefix_filter,
                max_keys,
            )
            .await?;
        }

        Ok((objects, common_prefixes))
    }

    async fn list_contents_recursively(
        &self,
        objects: &mut Vec<Object>,
        bucket_path: &Path,
        current_path: &Path,
        prefix_filter: &str,
        max_keys: i64,
    ) -> io::Result<()> {
        let mut entries = async_fs::read_dir(current_path).await?;

        while let Some(entry) = entries.next().await {
            if objects.len() as i64 >= max_keys {
                break;
            }

            let entry = entry?;
            let file_type = entry.file_type().await?;
            let file_path = entry.path();
            let key = file_path
                .strip_prefix(bucket_path)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");

            if !key.starts_with(prefix_filter) {
                continue;
            }

            if file_type.is_dir() {
                Box::pin(self.list_contents_recursively(
                    objects,
                    bucket_path,
                    &file_path,
                    prefix_filter,
                    max_keys,
                ))
                .await?;
            } else {
                self.add_object(objects, &file_path, &key).await?;
            }
        }

        Ok(())
    }

    async fn add_object(
        &self,
        objects: &mut Vec<Object>,
        file_path: &Path,
        key: &str,
    ) -> io::Result<()> {
        let metadata = async_fs::metadata(file_path).await?;
        let last_modified = time::to_rfc3339(metadata.modified()?);
        let size = metadata.len();

        objects.push(Object {
            key: Some(key.to_string()),
            last_modified: Some(last_modified),
            e_tag: None, // You might want to calculate this if needed
            size: Some(size as i64),
            storage_class: Some("STANDARD".to_string()),
            owner: None,
        });

        Ok(())
    }
}

/// copy bytes from a stream to a writer
async fn copy_bytes<S, W>(mut stream: S, writer: &mut W) -> io::Result<usize>
where
    S: Stream<Item = io::Result<Bytes>> + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let mut nwrite: usize = 0;
    while let Some(bytes) = stream.next().await {
        let bytes = bytes?;

        let amt_u64 = futures::io::copy_buf(bytes.as_ref(), writer).await?;
        let amt: usize = amt_u64.try_into().unwrap_or_else(|err| {
            panic!("number overflow: u64 to usize, n = {amt_u64}, err = {err}")
        });

        assert_eq!(
            bytes.len(),
            amt,
            "amt mismatch: bytes.len() = {}, amt = {}, nwrite = {}",
            bytes.len(),
            amt,
            nwrite
        );

        nwrite = nwrite
            .checked_add(amt)
            .unwrap_or_else(|| panic!("nwrite overflow: amt = {amt}, nwrite = {nwrite}"));
    }
    writer.flush().await?;
    Ok(nwrite)
}

/// wrap operation error
const fn operation_error<E>(e: E) -> S3StorageError<E> {
    S3StorageError::Operation(e)
}

#[async_trait]
impl S3Storage for FileSystem {
    #[tracing::instrument]
    async fn is_bucket_exist(&self, bucket: &str) -> S3StorageResult<bool, HeadBucketError> {
        let path = trace_try!(self.get_bucket_path(bucket));
        Ok(path.exists())
    }

    #[tracing::instrument]
    async fn create_bucket(
        &self,
        input: CreateBucketRequest,
    ) -> S3StorageResult<CreateBucketOutput, CreateBucketError> {
        let path = trace_try!(self.get_bucket_path(&input.bucket));

        if path.exists() {
            let err = CreateBucketError::BucketAlreadyExists(String::from(
                "The requested bucket name is not available. \
                    The bucket namespace is shared by all users of the system. \
                    Please select a different name and try again.",
            ));
            return Err(operation_error(err));
        }

        trace_try!(async_fs::create_dir(&path).await);

        let output = CreateBucketOutput::default(); // TODO: handle other fields
        Ok(output)
    }

    #[tracing::instrument]
    async fn copy_object(
        &self,
        input: CopyObjectRequest,
    ) -> S3StorageResult<CopyObjectOutput, CopyObjectError> {
        let copy_source = AmzCopySource::from_header_str(&input.copy_source)
            .map_err(|err| invalid_request!("Invalid header: x-amz-copy-source", err))?;

        let (bucket, key) = match copy_source {
            AmzCopySource::AccessPoint { .. } => {
                return Err(not_supported!("Access point is not supported yet.").into())
            }
            AmzCopySource::Bucket { bucket, key } => (bucket, key),
        };

        let src_path = trace_try!(self.get_object_path(bucket, key));
        let dst_path = trace_try!(self.get_object_path(&input.bucket, &input.key));

        let file_metadata = trace_try!(async_fs::metadata(&src_path).await);
        let last_modified = time::to_rfc3339(trace_try!(file_metadata.modified()));

        let _ = trace_try!(async_fs::copy(&src_path, &dst_path).await);

        debug!(
            from = %src_path.display(),
            to = %dst_path.display(),
            "CopyObject: copy file",
        );

        let src_metadata_path = trace_try!(self.get_metadata_path(bucket, key));
        if src_metadata_path.exists() {
            let dst_metadata_path = trace_try!(self.get_metadata_path(&input.bucket, &input.key));
            let _ = trace_try!(async_fs::copy(src_metadata_path, dst_metadata_path).await);
        }

        let md5_sum = trace_try!(self.get_md5_sum(bucket, key).await);

        let output = CopyObjectOutput {
            copy_object_result: CopyObjectResult {
                e_tag: Some(format!("\"{md5_sum}\"")),
                last_modified: Some(last_modified),
            }
            .apply(Some),
            ..CopyObjectOutput::default()
        };

        Ok(output)
    }

    #[tracing::instrument]
    async fn delete_bucket(
        &self,
        input: DeleteBucketRequest,
    ) -> S3StorageResult<DeleteBucketOutput, DeleteBucketError> {
        let path = trace_try!(self.get_bucket_path(&input.bucket));
        trace_try!(async_fs::remove_dir_all(path).await);
        Ok(DeleteBucketOutput)
    }

    #[tracing::instrument]
    async fn delete_object(
        &self,
        input: DeleteObjectRequest,
    ) -> S3StorageResult<DeleteObjectOutput, DeleteObjectError> {
        let path = trace_try!(self.get_object_path(&input.bucket, &input.key));
        if input.key.ends_with('/') {
            let mut dir = trace_try!(async_fs::read_dir(&path).await);
            let is_empty = dir.next().await.is_none();
            if is_empty {
                trace_try!(async_fs::remove_dir(&path).await);
            }
        } else {
            trace_try!(async_fs::remove_file(path).await);
        }
        let output = DeleteObjectOutput::default(); // TODO: handle other fields
        Ok(output)
    }

    #[tracing::instrument]
    async fn delete_objects(
        &self,
        input: DeleteObjectsRequest,
    ) -> S3StorageResult<DeleteObjectsOutput, DeleteObjectsError> {
        let mut objects: Vec<(PathBuf, String)> = Vec::new();
        for object in input.delete.objects {
            let path = trace_try!(self.get_object_path(&input.bucket, &object.key));
            if path.exists() {
                objects.push((path, object.key));
            }
        }

        let mut deleted: Vec<DeletedObject> = Vec::new();
        for (path, key) in objects {
            trace_try!(async_fs::remove_file(path).await);
            deleted.push(DeletedObject {
                key: Some(key),
                ..DeletedObject::default()
            });
        }
        let output = DeleteObjectsOutput {
            deleted: Some(deleted),
            ..DeleteObjectsOutput::default()
        };
        Ok(output)
    }

    #[tracing::instrument]
    async fn get_bucket_location(
        &self,
        input: GetBucketLocationRequest,
    ) -> S3StorageResult<GetBucketLocationOutput, GetBucketLocationError> {
        let path = trace_try!(self.get_bucket_path(&input.bucket));

        if !path.exists() {
            let err = code_error!(NoSuchBucket, "NotFound");
            return Err(err.into());
        }

        let output = GetBucketLocationOutput {
            location_constraint: None, // TODO: handle region
        };

        Ok(output)
    }

    #[tracing::instrument]
    async fn get_object(
        &self,
        input: GetObjectRequest,
    ) -> S3StorageResult<GetObjectOutput, GetObjectError> {
        let object_path = trace_try!(self.get_object_path(&input.bucket, &input.key));

        let parse_range = |s: &str| {
            Range::from_header_str(s).map_err(|err| invalid_request!("Invalid header: range", err))
        };
        let range: Option<Range> = input.range.as_deref().map(parse_range).transpose()?;

        let mut file = match File::open(&object_path).await {
            Ok(file) => file,
            Err(e) => {
                error!(error = %e, "GetObject: open file");
                let err = code_error!(NoSuchKey, "The specified key does not exist.");
                return Err(err.into());
            }
        };

        let file_metadata = trace_try!(file.metadata().await);
        let last_modified = time::to_rfc3339(trace_try!(file_metadata.modified()));

        let content_length = {
            let file_len = file_metadata.len();
            let content_len = match range {
                None => file_len,
                Some(Range::Normal { first, last }) => {
                    if first >= file_len {
                        let err =
                            code_error!(InvalidRange, "The requested range cannot be satisfied.");
                        return Err(err.into());
                    }
                    let _ = trace_try!(file.seek(SeekFrom::Start(first)).await);

                    // HTTP byte range is inclusive
                    //      len = last + 1 - first
                    // or   len = file_len - first

                    last.and_then(|x| x.checked_add(1))
                        .unwrap_or(file_len)
                        .wrapping_sub(first)
                }
                Some(Range::Suffix { last }) => {
                    let offset = Some(last)
                        .filter(|&x| x <= file_len)
                        .and_then(|x| i64::try_from(x).ok())
                        .and_then(i64::checked_neg);

                    if let Some(x) = offset {
                        let _ = trace_try!(file.seek(SeekFrom::End(x)).await);
                    } else {
                        let err =
                            code_error!(InvalidRange, "The requested range cannot be satisfied.");
                        return Err(err.into());
                    }
                    last
                }
            };
            trace_try!(usize::try_from(content_len))
        };

        let stream = BytesStream::new(file, 4096, Some(content_length));

        let object_metadata = trace_try!(self.load_metadata(&input.bucket, &input.key).await);

        let (md5_sum, duration) = {
            let (ret, duration) =
                time::count_duration(self.get_md5_sum(&input.bucket, &input.key)).await;
            let md5_sum = trace_try!(ret);
            (md5_sum, duration)
        };

        debug!(
            sum = ?md5_sum,
            path = %object_path.display(),
            size = ?content_length,
            ?duration,
            "GetObject: calculate md5 sum",
        );

        let output: GetObjectOutput = GetObjectOutput {
            body: Some(crate::dto::ByteStream::new(stream)),
            content_length: Some(trace_try!(content_length.try_into())),
            last_modified: Some(last_modified),
            metadata: object_metadata,
            e_tag: Some(format!("\"{md5_sum}\"")),
            ..GetObjectOutput::default() // TODO: handle other fields
        };

        Ok(output)
    }

    #[tracing::instrument]
    async fn head_bucket(
        &self,
        input: HeadBucketRequest,
    ) -> S3StorageResult<HeadBucketOutput, HeadBucketError> {
        let path = trace_try!(self.get_bucket_path(&input.bucket));

        if !path.exists() {
            let err = code_error!(NoSuchBucket, "The specified bucket does not exist.");
            return Err(err.into());
        }

        Ok(HeadBucketOutput)
    }

    #[tracing::instrument]
    async fn head_object(
        &self,
        input: HeadObjectRequest,
    ) -> S3StorageResult<HeadObjectOutput, HeadObjectError> {
        let path = trace_try!(self.get_object_path(&input.bucket, &input.key));

        if !path.exists() {
            let err = code_error!(NoSuchKey, "The specified key does not exist.");
            return Err(err.into());
        }

        let file_metadata = trace_try!(async_fs::metadata(path).await);
        let last_modified = time::to_rfc3339(trace_try!(file_metadata.modified()));
        let size = file_metadata.len();

        let object_metadata = trace_try!(self.load_metadata(&input.bucket, &input.key).await);

        let output: HeadObjectOutput = HeadObjectOutput {
            content_length: Some(trace_try!(size.try_into())),
            content_type: Some(mime::APPLICATION_OCTET_STREAM.as_ref().to_owned()), // TODO: handle content type
            last_modified: Some(last_modified),
            metadata: object_metadata,
            ..HeadObjectOutput::default()
        };
        Ok(output)
    }

    #[tracing::instrument]
    async fn list_buckets(
        &self,
        _: ListBucketsRequest,
    ) -> S3StorageResult<ListBucketsOutput, ListBucketsError> {
        let mut buckets = Vec::new();

        let mut iter = trace_try!(async_fs::read_dir(&self.root).await);
        while let Some(entry) = iter.next().await {
            let entry = trace_try!(entry);
            let file_type = trace_try!(entry.file_type().await);
            if file_type.is_dir() {
                let file_name = entry.file_name();
                let name = file_name.to_string_lossy();
                if S3Path::check_bucket_name(&name) {
                    let file_meta = trace_try!(entry.metadata().await);
                    let creation_date = trace_try!(file_meta.created());
                    buckets.push(Bucket {
                        creation_date: Some(time::to_rfc3339(creation_date)),
                        name: Some(name.into()),
                    });
                }
            }
        }

        let output = ListBucketsOutput {
            buckets: Some(buckets),
            owner: None, // TODO: handle owner
        };
        Ok(output)
    }

    #[tracing::instrument]
    async fn list_objects(
        &self,
        input: ListObjectsRequest,
    ) -> S3StorageResult<ListObjectsOutput, ListObjectsError> {
        let bucket_path = trace_try!(self.get_bucket_path(&input.bucket));
        debug!("Bucket path: {:?}", bucket_path);

        let (search_dir, prefix_filter) =
            if input.delimiter.is_none() || input.prefix.as_deref().unwrap_or("").is_empty() {
                (PathBuf::new(), String::new())
            } else {
                self.parse_prefix_and_delimiter(&input.prefix, &input.delimiter)
            };
        let search_path = bucket_path.join(&search_dir);
        debug!("Search path: {:?}", search_path);

        if !search_path.is_dir() {
            return Ok(ListObjectsOutput {
                name: Some(input.bucket),
                prefix: input.prefix,
                delimiter: input.delimiter,
                encoding_type: input.encoding_type,
                ..Default::default()
            });
        }

        let (mut objects, common_prefixes) = trace_try!(
            self.list_contents(
                input.delimiter.is_some()
                    && input.prefix.as_deref().map_or(false, |p| !p.is_empty()),
                &bucket_path,
                &search_path,
                &prefix_filter,
                &input.delimiter,
                input.max_keys.unwrap_or(1000i64),
            )
            .await
        );

        objects.sort_by(|a, b| a.key.cmp(&b.key));
        let mut common_prefixes: Vec<_> = common_prefixes.into_iter().collect();
        common_prefixes.sort();

        // URL encode object keys and common prefixes if encoding type is specified
        if input.encoding_type.as_deref() == Some("url") {
            for object in objects.iter_mut() {
                if let Some(key) = object.key.as_mut() {
                    *key = urlencoding::encode(key).into_owned();
                }
            }
            common_prefixes = common_prefixes
                .into_iter()
                .map(|p| urlencoding::encode(&p).into_owned())
                .collect();
        }

        Ok(ListObjectsOutput {
            contents: Some(objects),
            common_prefixes: if input.delimiter.is_some()
                && !input.prefix.as_deref().unwrap_or("").is_empty()
            {
                Some(
                    common_prefixes
                        .into_iter()
                        .map(|p| CommonPrefix { prefix: Some(p) })
                        .collect(),
                )
            } else {
                None
            },
            name: Some(input.bucket),
            prefix: input.prefix,
            delimiter: input.delimiter,
            max_keys: input.max_keys.map(|x| x as i32),
            encoding_type: input.encoding_type,
            ..Default::default()
        })
    }

    #[tracing::instrument]
    async fn list_objects_v2(
        &self,
        input: ListObjectsV2Request,
    ) -> S3StorageResult<ListObjectsV2Output, ListObjectsV2Error> {
        let bucket_path = trace_try!(self.get_bucket_path(&input.bucket));
        debug!("Bucket path: {:?}", bucket_path);

        let (search_dir, prefix_filter) =
            if input.delimiter.is_none() || input.prefix.as_deref().unwrap_or("").is_empty() {
                (PathBuf::new(), String::new())
            } else {
                self.parse_prefix_and_delimiter(&input.prefix, &input.delimiter)
            };
        let search_path = bucket_path.join(&search_dir);
        debug!("Search path: {:?}", search_path);

        if !search_path.is_dir() {
            return Ok(ListObjectsV2Output {
                name: Some(input.bucket),
                prefix: input.prefix,
                delimiter: input.delimiter,
                key_count: Some(0),
                encoding_type: input.encoding_type.clone(),
                ..Default::default()
            });
        }

        let (mut objects, common_prefixes) = trace_try!(
            self.list_contents(
                input.delimiter.is_some()
                    && input.prefix.as_deref().map_or(false, |p| !p.is_empty()),
                &bucket_path,
                &search_path,
                &prefix_filter,
                &input.delimiter,
                input.max_keys.unwrap_or(1000i64),
            )
            .await
        );

        objects.sort_by(|a, b| a.key.cmp(&b.key));
        let mut common_prefixes: Vec<_> = common_prefixes.into_iter().collect();
        common_prefixes.sort();

        let object_count = objects.len();
        let common_prefix_count = common_prefixes.len();

        // URL encode object keys if encoding type is specified
        if input.encoding_type.as_deref() == Some("url") {
            for object in objects.iter_mut() {
                if let Some(key) = object.key.as_mut() {
                    *key = urlencoding::encode(key).into_owned();
                }
            }
            common_prefixes = common_prefixes
                .into_iter()
                .map(|p| urlencoding::encode(&p).into_owned())
                .collect();
        }

        Ok(ListObjectsV2Output {
            contents: Some(objects),
            common_prefixes: if input.delimiter.is_some()
                && !input.prefix.as_deref().unwrap_or("").is_empty()
            {
                Some(
                    common_prefixes
                        .iter()
                        .map(|p| CommonPrefix {
                            prefix: Some(p.clone()),
                        })
                        .collect(),
                )
            } else {
                None
            },
            name: Some(input.bucket),
            prefix: input.prefix,
            delimiter: input.delimiter,
            max_keys: input.max_keys,
            key_count: Some((object_count + common_prefix_count) as i64),
            encoding_type: input.encoding_type,
            ..Default::default()
        })
    }

    #[tracing::instrument]
    async fn put_object(
        &self,
        input: PutObjectRequest,
    ) -> S3StorageResult<PutObjectOutput, PutObjectError> {
        if let Some(ref storage_class) = input.storage_class {
            let is_valid = ["STANDARD", "REDUCED_REDUNDANCY"].contains(&storage_class.as_str());
            if !is_valid {
                let err = code_error!(
                    InvalidStorageClass,
                    "The storage class you specified is not valid."
                );
                return Err(err.into());
            }
        }

        let PutObjectRequest {
            body,
            bucket,
            key,
            metadata,
            content_length,
            ..
        } = input;

        let body = body.ok_or_else(||{
            code_error!(IncompleteBody,"You did not provide the number of bytes specified by the Content-Length HTTP header.")
        })?;

        if key.ends_with('/') {
            if content_length == Some(0) {
                let object_path = trace_try!(self.get_object_path(&bucket, &key));
                trace_try!(async_fs::create_dir_all(&object_path).await);
                let output = PutObjectOutput::default();
                return Ok(output);
            }
            let err = code_error!(
                UnexpectedContent,
                "Unexpected request body when creating a directory object."
            );
            return Err(err.into());
        }

        let object_path = trace_try!(self.get_object_path(&bucket, &key));
        if let Some(dir_path) = object_path.parent() {
            trace_try!(async_fs::create_dir_all(&dir_path).await);
        }

        let mut md5_hash = Md5::new();
        let stream = body.inspect_ok(|bytes| md5_hash.update(bytes.as_ref()));

        let file = trace_try!(File::create(&object_path).await);
        let mut writer = BufWriter::new(file);

        let (ret, duration) = time::count_duration(copy_bytes(stream, &mut writer)).await;
        let size = trace_try!(ret);
        let md5_sum = md5_hash.finalize().apply(crypto::to_hex_string);

        #[cfg(debug_assertions)]
        debug!(
            path = %object_path.display(),
            ?size,
            ?duration,
            %md5_sum,
            "PutObject: write file",
        );

        if let Some(ref metadata) = metadata {
            trace_try!(self.save_metadata(&bucket, &key, metadata).await);
        }

        let output = PutObjectOutput {
            e_tag: Some(format!("\"{md5_sum}\"")),
            ..PutObjectOutput::default()
        }; // TODO: handle other fields

        Ok(output)
    }

    #[tracing::instrument]
    async fn create_multipart_upload(
        &self,
        input: CreateMultipartUploadRequest,
    ) -> S3StorageResult<CreateMultipartUploadOutput, CreateMultipartUploadError> {
        let upload_id = Uuid::new_v4().to_string();

        let output = CreateMultipartUploadOutput {
            bucket: Some(input.bucket),
            key: Some(input.key),
            upload_id: Some(upload_id),
            ..CreateMultipartUploadOutput::default()
        };

        Ok(output)
    }

    #[tracing::instrument]
    async fn upload_part(
        &self,
        input: UploadPartRequest,
    ) -> S3StorageResult<UploadPartOutput, UploadPartError> {
        let UploadPartRequest {
            body,
            upload_id,
            part_number,
            ..
        } = input;

        let body = body.ok_or_else(||{
            code_error!(IncompleteBody, "You did not provide the number of bytes specified by the Content-Length HTTP header.")
        })?;

        let file_path_str = format!(".upload_id-{upload_id}.part-{part_number}");
        let file_path = trace_try!(Path::new(&file_path_str).absolutize_virtually(&self.root));

        let mut md5_hash = Md5::new();
        let stream = body.inspect_ok(|bytes| md5_hash.update(bytes.as_ref()));

        let file = trace_try!(File::create(&file_path).await);
        let mut writer = BufWriter::new(file);

        let (ret, duration) = time::count_duration(copy_bytes(stream, &mut writer)).await;
        let size = trace_try!(ret);
        let md5_sum = md5_hash.finalize().apply(crypto::to_hex_string);

        debug!(
            path = %file_path.display(),
            ?size,
            ?duration,
            %md5_sum,
            "UploadPart: write file",
        );

        let e_tag = format!("\"{md5_sum}\"");

        let output = UploadPartOutput {
            e_tag: Some(e_tag),
            ..UploadPartOutput::default()
        };

        Ok(output)
    }

    #[tracing::instrument]
    async fn complete_multipart_upload(
        &self,
        input: CompleteMultipartUploadRequest,
    ) -> S3StorageResult<CompleteMultipartUploadOutput, CompleteMultipartUploadError> {
        let CompleteMultipartUploadRequest {
            multipart_upload,
            bucket,
            key,
            upload_id,
            ..
        } = input;

        let multipart_upload = if let Some(multipart_upload) = multipart_upload {
            multipart_upload
        } else {
            let err = code_error!(InvalidPart, "Missing multipart_upload");
            return Err(err.into());
        };

        let object_path = trace_try!(self.get_object_path(&bucket, &key));
        let file = trace_try!(File::create(&object_path).await);
        let mut writer = BufWriter::new(file);

        let mut cnt: i64 = 0;
        for part in multipart_upload.parts.into_iter().flatten() {
            let part_number = trace_try!(part
                .part_number
                .ok_or_else(|| { io::Error::new(io::ErrorKind::NotFound, "Missing part_number") }));
            cnt = cnt.wrapping_add(1);
            if part_number != cnt {
                trace_try!(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "InvalidPartOrder"
                )));
            }
            let part_path_str = format!(".upload_id-{upload_id}.part-{part_number}");
            let part_path = trace_try!(Path::new(&part_path_str).absolutize_virtually(&self.root));

            let mut reader = trace_try!(File::open(&part_path).await);
            let (ret, duration) =
                time::count_duration(futures::io::copy(&mut reader, &mut writer)).await;
            let size = trace_try!(ret);

            debug!(
                from = %part_path.display(),
                to = %object_path.display(),
                ?size,
                ?duration,
                "CompleteMultipartUpload: write file",
            );
            trace_try!(async_fs::remove_file(&part_path).await);
        }
        drop(writer);

        let file_size = trace_try!(async_fs::metadata(&object_path).await).len();

        let (md5_sum, duration) = {
            let (ret, duration) = time::count_duration(self.get_md5_sum(&bucket, &key)).await;
            let md5_sum = trace_try!(ret);
            (md5_sum, duration)
        };

        debug!(
            sum = ?md5_sum,
            path = %object_path.display(),
            size = ?file_size,
            ?duration,
            "CompleteMultipartUpload: calculate md5 sum",
        );

        let e_tag = format!("\"{md5_sum}\"");
        let output = CompleteMultipartUploadOutput {
            bucket: Some(bucket),
            key: Some(key),
            e_tag: Some(e_tag),
            ..CompleteMultipartUploadOutput::default()
        };
        Ok(output)
    }
}
