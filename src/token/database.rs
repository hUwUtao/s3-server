use base64;
use serde_json;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tracing::{info, warn};

use crate::auth::{Matcher, Permission};

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
            .filter_map(|role| Permission::new(role).ok())
            .collect()
    }

    pub fn report_memory_usage(&self) -> String {
        use std::mem::size_of;
        let config_size = self.indexed_config.len() * size_of::<(String, BucketConfigFile)>();
        let token_size = self.indexed_token.len() * size_of::<(u64, String)>();
        let locked_size = self.locked_bucket.len() * size_of::<String>();
        let total_size = config_size + token_size + locked_size;

        format!(
            "Memory Usage Report:\n\
             - Indexed Configs: {} buckets (approx. {} bytes)\n\
             - Indexed Tokens: {} tokens (approx. {} bytes)\n\
             - Locked Buckets: {} buckets (approx. {} bytes)\n\
             - Total Estimated Size: {} bytes",
            self.indexed_config.len(),
            config_size,
            self.indexed_token.len(),
            token_size,
            self.locked_bucket.len(),
            locked_size,
            total_size
        )
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
        self.locked_bucket.contains(&bucket_name.to_string())
    }

    pub fn validate_orign(&self, this: &str, token: &Token) -> bool {
        if let Some(cfg) = self.indexed_config.get(this) {
            if cfg.allows.contains(&token.origin) {
                return true;
            }
        }
        false
    }

    pub fn get_roles_as_permission(&self, token: &u64) -> Option<Arc<Vec<Permission>>> {
        self.indexed_roles.get(token).map(|t| t.to_owned())
    }

    pub fn query_token(&self, token: &str) -> Option<Token> {
        let token_hash = self.hash_access_id(token);
        self.indexed_token
            .get(&token_hash)
            .and_then(|(bucket, key)| {
                self.indexed_config
                    .get(bucket)
                    .and_then(|c| c.tokens.get(key).map(|t| t.to_owned()))
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
                ()
            }
        }
        self.lock_bucket(bucket_name.to_string());
        let result = self.reload_bucket(bucket_name);
        self.unlock_bucket(bucket_name);
        result
    }

    pub fn new(fs_root: PathBuf) -> std::io::Result<Self> {
        let mut db = IndexDB {
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
            let token_hash = db.hash_access_id("");
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
                let token_index = self.hash_access_id(&key);
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
                .insert(bucket_name.to_string(), new_config.clone());
            self.index_tokens(bucket_name, &new_config);
            self.index_public(bucket_name, &new_config);
        }

        Ok(())
    }

    pub(crate) fn hash_access_id(&self, token: &str) -> u64 {
        let bytes = base64::decode(token).unwrap_or_default();
        let token_bytes = &bytes[bytes.len().saturating_sub(16)..];
        let (hash, _) = mur3::murmurhash3_x64_128(token_bytes, 0);
        hash
    }

    fn is_base64(s: &str) -> bool {
        base64::decode(s).is_ok()
    }

    fn hash_and_encode(key: &str) -> String {
        let bytes = key.as_bytes();
        let hash_bytes = mur3::murmurhash3_x64_128(&bytes, 0);
        base64::encode(&[hash_bytes.0.to_be_bytes(), hash_bytes.1.to_be_bytes()].concat())
    }

    fn write_config(&self, bucket_name: &str, config: &BucketConfigFile) -> std::io::Result<()> {
        let rules_path = self
            .fs_root
            .join("sys")
            .join(bucket_name)
            .join(".rules.json");
        let content = serde_json::to_string_pretty(config)?;
        std::fs::write(rules_path, content)?;
        Ok(())
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
            let bucket_name = file_str.trim_end_matches(".rule.json").to_string();
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
            .join(format!("{}.rule.json", bucket_name))
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
            let token_index = self.hash_access_id(key);
            let _ = self
                .indexed_token
                .insert(token_index, (bucket_name.to_string(), key.to_string()));

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
                .insert(bucket_name.to_string(), Arc::new(matchers));
        }
    }
}
