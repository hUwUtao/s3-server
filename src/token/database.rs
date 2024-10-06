use async_trait::async_trait;
use serde_json;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{info, warn};

use crate::{
    auth::{Matcher, Permission},
    utils::metrics::Mesurable,
};

use super::{BucketConfigFile, Token};
#[derive(Debug)]
pub struct IndexDB {
    fs_root: PathBuf,
    /// All config files are loaded
    /// K is bucket name
    indexed_config: HashMap<String, BucketConfigFile>,
    /// Index by K token hash, V is bucket name
    indexed_token: HashMap<u64, (String, String)>,
    /// Index by K token hash, V is permission object
    indexed_roles: HashMap<u64, Arc<Vec<Permission>>>,
    /// Index by k bucket name, V is public matcher
    indexed_public: HashMap<String, Arc<Vec<Matcher>>>,
    /// Buckets that should be ignored during reload
    locked_bucket: Vec<String>,
}

impl IndexDB {
    fn parse_roles(&self, roles: &[String]) -> Vec<Permission> {
        roles
            .iter()
            .filter_map(|role| {
                Permission::new(role)
                    .map_err(|e| {
                        warn!("permparse failed: {}", e);
                        e
                    })
                    .ok()
            })
            .collect()
    }

    fn lock_bucket(&mut self, bucket_name: String) {
        if !self.locked_bucket.contains(&bucket_name) {
            self.locked_bucket.push(bucket_name);
        }
    }

    fn unlock_bucket(&mut self, bucket_name: &str) {
        self.locked_bucket.retain(|b| b != bucket_name);
    }

    fn flush_locks(&mut self) {
        self.locked_bucket.clear();
    }

    pub fn is_locked(&self, bucket_name: &str) -> bool {
        self.locked_bucket.contains(&bucket_name.to_owned())
    }

    pub fn validate_orign(&self, this: &str, token: &Token) -> bool {
        if let Some(cfg) = self.indexed_config.get(this) {
            if cfg.allows.contains(&token.origin) {
                return true;
            }
        }
        false
    }

    pub fn create_bucket_from(
        &mut self,
        new_bucket: &str,
        origin_bucket: &str,
    ) -> std::io::Result<()> {
        let source_config = self.indexed_config.get(origin_bucket).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "Source bucket not found")
        })?;

        let new_config = BucketConfigFile {
            public: Vec::new(),
            allows: vec![origin_bucket.to_owned()],
            owners: source_config.owners.clone(),
            tokens: HashMap::new(),
        };

        let config_path = self.get_config_file_path(new_bucket);
        let config_json = serde_json::to_string_pretty(&new_config)?;
        std::fs::write(config_path, config_json)?;

        self.reload_bucket(new_bucket)?;

        Ok(())
    }

    // pub fn print_indexed_roles(&self) {
    //     println!("Indexed Config:");
    //     for (bucket, config) in &self.indexed_config {
    //         println!("Bucket: {}", bucket);
    //         println!("  Public: {:?}", config.public);
    //         println!("  Allows: {:?}", config.allows);
    //         println!("  Owners: {:?}", config.owners);
    //         println!("  Tokens: {}", config.tokens.len());
    //     }

    //     println!("\nIndexed Tokens:");
    //     for (token_hash, (bucket, key)) in &self.indexed_token {
    //         println!("Token Hash: {}", token_hash);
    //         println!("  Bucket: {}", bucket);
    //         println!("  Key: {}", key);
    //     }

    //     println!("\nIndexed Roles:");
    //     for (token_hash, permissions) in &self.indexed_roles {
    //         println!("Token Hash: {}", token_hash);
    //         for permission in permissions.iter() {
    //             println!("  - {:?}", permission);
    //         }
    //     }

    //     println!("\nIndexed Public:");
    //     for (bucket, matchers) in &self.indexed_public {
    //         println!("Bucket: {}", bucket);
    //         for matcher in matchers.iter() {
    //             println!("  - {:?}", matcher);
    //         }
    //     }

    //     println!("\nLocked Buckets:");
    //     for bucket in &self.locked_bucket {
    //         println!("  - {}", bucket);
    //     }
    // }

    pub fn get_roles_as_permission(&self, token: &u64) -> Option<Arc<Vec<Permission>>> {
        // self.print_indexed_roles();
        self.indexed_roles.get(token).cloned()
    }

    pub fn query_token(&self, token: &str) -> Option<Token> {
        let token_hash = self.hash_string_unsafe(token);
        self.query_token_prehashed(token_hash)
    }

    pub fn query_token_prehashed(&self, token_hash: u64) -> Option<Token> {
        self.indexed_token
            .get(&token_hash)
            .and_then(|(bucket, key)| {
                self.indexed_config
                    .get(bucket)
                    .and_then(|c| c.tokens.get(key).map(ToOwned::to_owned))
            })
    }

    pub fn query_is_match_indexed_public(&self, bucket: &str, path: &Path) -> bool {
        if let Some(matchs) = self.indexed_public.get(bucket) {
            if matchs.iter().any(|m| m.matches(path)) {
                return true;
            }
        }
        false
    }

    pub fn initiate_reload(&mut self, bucket_name: &str) -> std::io::Result<()> {
        if self.is_locked(bucket_name) {
            warn!("Deadlock on reload \"{}\"", bucket_name);
            if self.indexed_config.get(bucket_name).is_some() {
                self.unlock_bucket(bucket_name);
                ();
            }
        }
        self.lock_bucket(bucket_name.to_owned());
        let result = self.reload_bucket(bucket_name);
        self.unlock_bucket(bucket_name);
        result
    }

    pub fn new(fs_root: PathBuf) -> std::io::Result<Self> {
        let mut db = Self {
            fs_root,
            indexed_config: HashMap::new(),
            indexed_token: HashMap::new(),
            indexed_roles: HashMap::new(),
            indexed_public: HashMap::new(),
            locked_bucket: Vec::new(),
        };
        db.load()?;

        {
            // Add volatile bucket with empty string name
            let null_bucket = String::new();
            let mut null_cfg = BucketConfigFile {
                public: Vec::new(),
                allows: Vec::new(),
                owners: Vec::new(),
                tokens: HashMap::new(),
            };

            // Add token with empty string access_id and jti of 0x0
            let null_token = Token {
                sub: 0,
                iat: 0,
                jti: 0x0,
                exp: None,
                origin: String::new(),
                roles: Vec::new(),
            };
            let _ = null_cfg.tokens.insert(String::new(), null_token);

            // Add volatile bucket to indexed_config
            let _ = db.indexed_config.insert(null_bucket.clone(), null_cfg);

            // Index the volatile token
            let token_hash = db.hash_string_unsafe("");
            let _ = db
                .indexed_token
                .insert(token_hash, (null_bucket, String::new()));
            let _ = db.indexed_roles.insert(token_hash, Arc::new(Vec::new()));
        }

        Ok(db)
    }
    fn reload_bucket(&mut self, bucket_name: &str) -> std::io::Result<()> {
        // Remove the existing config and its tokens
        if let Some(old_config) = self.indexed_config.remove(bucket_name) {
            for (key, _) in old_config.tokens {
                let token_index = self.hash_string_unsafe(&key);
                let _ = self.indexed_token.remove(&token_index);
                let _ = self.indexed_roles.remove(&token_index);
            }
            let _ = self.indexed_public.remove(bucket_name);
        }

        // Load the new config
        let rules_path = self.get_config_file_path(bucket_name);
        if rules_path.exists() {
            let new_config = self.load_config(bucket_name)?;
            let _ = self
                .indexed_config
                .insert(bucket_name.to_owned(), new_config.clone());
            self.index_tokens(bucket_name, &new_config);
            self.index_public(bucket_name, &new_config);
        }

        Ok(())
    }

    pub(crate) fn hash_string_unsafe(&self, token: &str) -> u64 {
        let token_bytes = token.as_bytes();
        let (hash, _) = mur3::murmurhash3_x64_128(token_bytes, 727);
        hash
    }

    pub fn load(&mut self) -> std::io::Result<()> {
        let sys_dir = self.fs_root.join("sys");
        if !sys_dir.exists() {
            std::fs::create_dir_all(&sys_dir)?;
        }

        let mut entries: usize = 0;
        for entry in std::fs::read_dir(sys_dir)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = path.file_name().and_then(|f| f.to_str());
            let file_str = match file_name {
                Some(s) if s.ends_with(".rule.json") => s,
                _ => continue,
            };
            let bucket_name = file_str.trim_end_matches(".rule.json").to_owned();
            if self.is_locked(&bucket_name) {
                continue;
            }
            match self.load_config(&bucket_name) {
                Ok(config) => {
                    let _ = self
                        .indexed_config
                        .insert(bucket_name.clone(), config.clone());
                    self.index_tokens(&bucket_name, &config);
                    self.index_public(&bucket_name, &config);
                    entries += 1;
                }
                Err(e) => {
                    warn!(
                        "Failed to load config for bucket: {}\nERR: {}",
                        bucket_name, e
                    );
                }
            }
        }
        info!("Loaded {} rules.", entries);
        Ok(())
    }

    fn get_config_file_path(&self, bucket_name: &str) -> PathBuf {
        self.fs_root
            .join("sys")
            .join(format!("{bucket_name}.rule.json"))
    }

    fn load_config(&self, bucket_name: &str) -> std::io::Result<BucketConfigFile> {
        let path = self.get_config_file_path(bucket_name);
        let content = std::fs::read_to_string(path)?;
        let config: BucketConfigFile = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Note: insert into indexed token table with key is dissected buffer
    fn index_tokens(&mut self, bucket_name: &str, config: &BucketConfigFile) {
        for (key, token) in &config.tokens {
            let token_index = self.hash_string_unsafe(key);
            let _ = self
                .indexed_token
                .insert(token_index, (bucket_name.to_owned(), key.to_string()));

            let permissions = self.parse_roles(&token.roles);
            let _ = self
                .indexed_roles
                .insert(token_index, Arc::new(permissions));
        }
    }

    fn index_public(&mut self, bucket_name: &str, config: &BucketConfigFile) {
        let matchers = config
            .public
            .iter()
            .filter_map(|path| Matcher::new(path.to_string()).ok())
            .collect::<Vec<Matcher>>();
        if !matchers.is_empty() {
            let _ = self
                .indexed_public
                .insert(bucket_name.to_owned(), Arc::new(matchers));
        }
    }
}

#[async_trait]
impl Mesurable for IndexDB {
    async fn metrics(&self) -> HashMap<String, String> {
        let mut metrics = HashMap::new();

        macro_rules! reportable {
            ($name:expr, $value:expr) => {
                let _ = metrics.insert($name.to_string(), $value.to_string());
            };
            ($name:expr, $field:expr, $type:ty) => {
                let _ = metrics.insert(
                    $name.to_string(),
                    (std::mem::size_of_val($field)
                        + $field.capacity() * std::mem::size_of::<$type>())
                    .to_string(),
                );
            };
        }

        reportable!("indexed_config_count", self.indexed_config.len());
        reportable!("indexed_token_count", self.indexed_token.len());
        reportable!("indexed_roles_count", self.indexed_roles.len());
        reportable!("indexed_public_count", self.indexed_public.len());
        reportable!("locked_bucket_count", self.locked_bucket.len());

        let total_tokens: usize = self
            .indexed_config
            .values()
            .map(|config| config.tokens.len())
            .sum();
        reportable!("total_tokens", total_tokens);

        let total_public_matchers: usize = self
            .indexed_public
            .values()
            .map(|matchers| matchers.len())
            .sum();
        reportable!("total_public_matchers", total_public_matchers);

        // Calculate memory usage for each table
        reportable!(
            "indexed_config_bytes",
            &self.indexed_config,
            (String, BucketConfigFile)
        );
        reportable!(
            "indexed_token_bytes",
            &self.indexed_token,
            (u64, (String, String))
        );
        reportable!(
            "indexed_roles_bytes",
            &self.indexed_roles,
            (u64, Arc<Vec<Permission>>)
        );
        reportable!(
            "indexed_public_bytes",
            &self.indexed_public,
            (String, Arc<Vec<Matcher>>)
        );
        reportable!("locked_bucket_bytes", &self.locked_bucket, String);

        // Calculate total memory usage
        let total_bytes = metrics["indexed_config_bytes"]
            .parse::<usize>()
            .unwrap_or(0)
            + metrics["indexed_token_bytes"].parse::<usize>().unwrap_or(0)
            + metrics["indexed_roles_bytes"].parse::<usize>().unwrap_or(0)
            + metrics["indexed_public_bytes"]
                .parse::<usize>()
                .unwrap_or(0)
            + metrics["locked_bucket_bytes"].parse::<usize>().unwrap_or(0);
        reportable!("total_bytes", total_bytes);

        metrics
    }
}
