use base64;
use serde_json;
use std::{collections::HashMap, path::PathBuf};
use tracing::warn;

use super::{BucketConfigFile, Token};

#[derive(Debug)]
pub struct IndexDB {
    fs_root: PathBuf,
    /// All config files are loaded
    /// K is bucket name
    indexed_config: HashMap<String, BucketConfigFile>,
    /// Index by K token hash, V is bucket name
    indexed_token: HashMap<u64, String>,
    /// Buckets that should be ignored during reload
    locked_bucket: Vec<String>,
}

impl<'a> IndexDB {
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

    pub fn query_token(&self, token: &str) -> Option<Token> {
        self.indexed_token
            .get(&Self::hash_token(&self, token))
            .map(|t| {
                self.indexed_config
                    .get(t)
                    .map(|c| c.tokens.get(token).map(|t| t.clone()))
                    .flatten()
            })
            .flatten()
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
            locked_bucket: Vec::new(),
        };
        db.load()?;
        db.ensure_hashed_keys()?;
        Ok(db)
    }

    fn reload_bucket(&mut self, bucket_name: &str) -> std::io::Result<()> {
        // Remove the existing config and its tokens
        if let Some(old_config) = self.indexed_config.remove(bucket_name) {
            for (key, _) in old_config.tokens {
                let token_index = self.hash_token(&key);
                let _ = self.indexed_token.remove(&token_index);
            }
        }

        // Load the new config
        let rules_path = self.get_config_file_path(bucket_name);
        if rules_path.exists() {
            let new_config = self.load_config(bucket_name)?;
            let _ = self
                .indexed_config
                .insert(bucket_name.to_string(), new_config.clone());
            self.index_tokens(bucket_name, &new_config);
        }

        Ok(())
    }

    fn hash_token(&self, token: &str) -> u64 {
        let bytes = base64::decode(token).unwrap_or_default();
        let token_bytes = &bytes[bytes.len().saturating_sub(16)..];
        let (hash, _) = mur3::murmurhash3_x64_128(token_bytes, 0);
        hash
    }

    pub fn ensure_hashed_keys(&mut self) -> std::io::Result<()> {
        let mut updates = Vec::new();
        for (bucket_name, config) in &mut self.indexed_config {
            let mut updated_tokens = HashMap::new();
            let mut updated = false;
            for (key, value) in &config.tokens {
                if !Self::is_base64(key) {
                    let hashed_key = Self::hash_and_encode(key);
                    let _ = updated_tokens.insert(hashed_key, value.clone());
                    updated = true;
                } else {
                    let _ = updated_tokens.insert(key.clone(), value.clone());
                }
            }
            if updated {
                config.tokens = updated_tokens;
                updates.push((bucket_name.clone(), config.clone()));
            }
        }
        for (bucket_name, config) in updates {
            self.write_config(&bucket_name, &config)?;
        }
        Ok(())
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
        let rules_path = self.fs_root.join(bucket_name).join(".rules.json");
        let content = serde_json::to_string_pretty(config)?;
        std::fs::write(rules_path, content)?;
        Ok(())
    }
    pub fn load(&mut self) -> std::io::Result<()> {
        for entry in std::fs::read_dir(&self.fs_root)? {
            let entry = entry?;
            let path = entry.path();
            if let Some(file_name) = path.file_name() {
                if let Some(file_str) = file_name.to_str() {
                    if file_str.ends_with(".rule.json") {
                        let bucket_name = file_str.trim_end_matches(".rule.json").to_string();
                        if !self.is_locked(&bucket_name) {
                            let config = self.load_config(&bucket_name)?;
                            let _ = self
                                .indexed_config
                                .insert(bucket_name.clone(), config.clone());
                            self.index_tokens(&bucket_name, &config);
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn get_config_file_path(&self, bucket_name: &str) -> PathBuf {
        self.fs_root.join(format!("{}.rule.json", bucket_name))
    }

    fn load_config(&self, bucket_name: &str) -> std::io::Result<BucketConfigFile> {
        let path = self.get_config_file_path(bucket_name);
        let content = std::fs::read_to_string(path)?;
        let config: BucketConfigFile = serde_json::from_str(&content)?;
        Ok(config)
    }

    fn index_tokens(&mut self, bucket_name: &str, config: &BucketConfigFile) {
        for (key, _) in &config.tokens {
            let token_index = self.hash_token(key);
            let _ = self
                .indexed_token
                .insert(token_index, bucket_name.to_string());
        }
    }
}
