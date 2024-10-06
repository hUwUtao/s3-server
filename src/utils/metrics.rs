use std::collections::HashMap;

use async_trait::async_trait;

#[async_trait]
pub trait Mesurable {
    async fn metrics(&self) -> HashMap<String, String>;
}
