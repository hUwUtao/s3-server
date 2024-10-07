use anyhow::{Context, Result};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use s3_server::token::{BucketConfigFile, Token};
use std::fs;
use std::path::PathBuf;
use structopt::StructOpt;
use uuid::Uuid;

#[derive(StructOpt)]
#[structopt(name = "s3-sec", about = "S3 security management tool")]
enum Cli {
    #[structopt(name = "get-sec")]
    GetSec {
        #[structopt(long, parse(from_os_str), default_value = "./storage")]
        fs_root: PathBuf,
        bucket: String,
        token_key: String,
    },
    #[structopt(name = "add-token")]
    AddToken {
        #[structopt(long, parse(from_os_str), default_value = "./storage")]
        fs_root: PathBuf,
        bucket: String,
        #[structopt(long)]
        sub: u64,
        #[structopt(long)]
        iat: u64,
        #[structopt(long)]
        exp: Option<u64>,
        #[structopt(long)]
        origin: String,
        #[structopt(long, use_delimiter = true)]
        roles: Vec<String>,
    },
    #[structopt(name = "generate-jti")]
    GenerateJti {
        #[structopt(long, parse(from_os_str), default_value = "./storage")]
        fs_root: PathBuf,
        bucket: String,
        token_key: String,
    },
    #[structopt(name = "create-bucket")]
    CreateBucket {
        #[structopt(long, parse(from_os_str), default_value = "./storage")]
        fs_root: PathBuf,
        bucket: String,
        owner_id: u64,
        #[structopt(long)]
        ci: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::from_args();

    match cli {
        Cli::GetSec {
            fs_root,
            bucket,
            token_key,
        } => get_sec(fs_root, bucket, token_key),
        Cli::AddToken {
            fs_root,
            bucket,
            sub,
            iat,
            exp,
            origin,
            roles,
        } => add_token(fs_root, bucket, sub, iat, exp, origin, roles),
        Cli::GenerateJti {
            fs_root,
            bucket,
            token_key,
        } => generate_jti(fs_root, bucket, token_key),
        Cli::CreateBucket {
            fs_root,
            bucket,
            owner_id,
            ci,
        } => create_bucket(fs_root, bucket, owner_id, ci),
    }
}

fn get_config_file_path(fs_root: &PathBuf, bucket: &str) -> PathBuf {
    fs_root.join("sys").join(format!("{}.rule.json", bucket))
}

fn read_config(file_path: &PathBuf) -> Result<BucketConfigFile> {
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {:?}", file_path))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from file: {:?}", file_path))
}

fn write_config(file_path: &PathBuf, config: &BucketConfigFile) -> Result<()> {
    let content = serde_json::to_string_pretty(&config)?;
    fs::write(file_path, content).with_context(|| format!("Failed to write file: {:?}", file_path))
}

fn generate_token_key() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(24)
        .map(char::from)
        .collect()
}

fn get_sec(fs_root: PathBuf, bucket: String, token_key: String) -> Result<()> {
    let file_path = get_config_file_path(&fs_root, &bucket);
    let config = read_config(&file_path)?;

    if let Some(token) = config.tokens.get(&token_key) {
        let sec_str = token.get_sec_str();
        println!("sec_str for token '{}': {}", token_key, sec_str);
    } else {
        println!("Token not found: {}", token_key);
    }

    Ok(())
}

fn add_token(
    fs_root: PathBuf,
    bucket: String,
    sub: u64,
    iat: u64,
    exp: Option<u64>,
    origin: String,
    roles: Vec<String>,
) -> Result<()> {
    let file_path = get_config_file_path(&fs_root, &bucket);
    let mut config = read_config(&file_path)?;

    let new_token = Token {
        sub,
        iat,
        jti: Uuid::new_v4().as_u128(),
        exp,
        origin,
        roles,
    };

    let token_key = generate_token_key();
    config.tokens.insert(token_key.clone(), new_token);

    write_config(&file_path, &config)?;

    println!("Added new token with key: {}", token_key);
    Ok(())
}

fn generate_jti(fs_root: PathBuf, bucket: String, token_key: String) -> Result<()> {
    let file_path = get_config_file_path(&fs_root, &bucket);
    let mut config = read_config(&file_path)?;

    if let Some(token) = config.tokens.get_mut(&token_key) {
        token.jti = Uuid::new_v4().as_u128();
        let new_sec_str = token.get_sec_str();
        write_config(&file_path, &config)?;
        println!("Generated new JTI for token: {}", token_key);
        println!("New sec_str: {}", new_sec_str);
    } else {
        println!("Token not found: {}", token_key);
    }

    Ok(())
}

fn create_bucket(fs_root: PathBuf, bucket: String, owner_id: u64, ci: bool) -> Result<()> {
    fs::create_dir_all(&fs_root)?;
    fs::create_dir_all(fs_root.join("sys"))?;
    fs::create_dir_all(fs_root.join(&bucket))?;
    let file_path = get_config_file_path(&fs_root, &bucket);

    if file_path.exists() {
        return Err(anyhow::anyhow!("Bucket already exists"));
    }

    let token = Token {
        sub: owner_id,
        iat: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        jti: Uuid::new_v4().as_u128(),
        exp: None,
        origin: bucket.clone(),
        roles: vec![format!("s3:ObjectGet,ObjectPut,ObjectDelete,ObjectList,BucketGet,BucketList,BucketCreate,BucketDelete:{}*:*", bucket)],
    };

    let token_key = generate_token_key();

    let config = BucketConfigFile {
        public: Vec::new(),
        indexable: None,
        allows: vec![bucket.clone()],
        owners: vec![owner_id],
        tokens: [(token_key.clone(), token.clone())].into_iter().collect(),
    };

    write_config(&file_path, &config)?;

    if ci {
        println!("{}", token_key);
        println!("{}", token.get_sec_str());
    } else {
        println!("Bucket '{}' created successfully", bucket);
        println!("Owner token key: {}", token_key);
        println!("Hash key: {}", token.get_sec_str());
    }

    Ok(())
}
