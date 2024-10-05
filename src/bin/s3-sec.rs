use anyhow::{Context, Result};
use s3_server::token::{BucketConfigFile, Token};
use serde_json;
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
    }
}

fn get_sec(fs_root: PathBuf, bucket: String, token_key: String) -> Result<()> {
    let file_path = fs_root.join("sys").join(format!("{}.rule.json", bucket));
    let content = fs::read_to_string(&file_path)
        .with_context(|| format!("Failed to read file: {:?}", file_path))?;
    let config: BucketConfigFile = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from file: {:?}", file_path))?;

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
    let file_path = fs_root.join("sys").join(format!("{}.rule.json", bucket));
    let content = fs::read_to_string(&file_path)
        .with_context(|| format!("Failed to read file: {:?}", file_path))?;
    let mut config: BucketConfigFile = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from file: {:?}", file_path))?;

    let new_token = Token {
        sub,
        iat,
        jti: Uuid::new_v4().as_u128(),
        exp,
        origin,
        roles,
    };

    let token_key = new_token.get_sec_str();
    config.tokens.insert(token_key.clone(), new_token);

    let updated_content = serde_json::to_string_pretty(&config)?;
    fs::write(&file_path, updated_content)?;

    println!("Added new token with key: {}", token_key);
    Ok(())
}

fn generate_jti(fs_root: PathBuf, bucket: String, token_key: String) -> Result<()> {
    let file_path = fs_root.join("sys").join(format!("{}.rule.json", bucket));
    let content = fs::read_to_string(&file_path)
        .with_context(|| format!("Failed to read file: {:?}", file_path))?;
    let mut config: BucketConfigFile = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON from file: {:?}", file_path))?;

    if let Some(token) = config.tokens.get_mut(&token_key) {
        token.jti = Uuid::new_v4().as_u128();
        let new_sec_str = token.get_sec_str();
        let updated_content = serde_json::to_string_pretty(&config)?;
        fs::write(&file_path, updated_content)?;
        println!("Generated new JTI for token: {}", token_key);
        println!("New sec_str: {}", new_sec_str);
    } else {
        println!("Token not found: {}", token_key);
    }

    Ok(())
}
