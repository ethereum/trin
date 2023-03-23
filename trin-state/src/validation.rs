use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use ethportal_api::StateContentKey;
use trin_validation::{oracle::HeaderOracle, validator::Validator};

pub struct StateValidator {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

#[async_trait]
impl Validator<StateContentKey> for StateValidator {
    async fn validate_content(
        &self,
        _content_key: &StateContentKey,
        _content: &[u8],
    ) -> anyhow::Result<()>
    where
        StateContentKey: 'async_trait,
    {
        // todo: implement state network validation
        Ok(())
    }
}
