use std::sync::Arc;

use async_trait::async_trait;
use ethportal_api::BeaconContentKey;
use tokio::sync::RwLock;

use trin_validation::{
    oracle::HeaderOracle,
    validator::{ValidationResult, Validator},
};

pub struct BeaconValidator {
    // TODO: HeaderOracle is not network agnostic name
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

#[async_trait]
impl Validator<BeaconContentKey> for BeaconValidator {
    async fn validate_content(
        &self,
        _content_key: &BeaconContentKey,
        _content: &[u8],
    ) -> anyhow::Result<ValidationResult<BeaconContentKey>>
    where
        BeaconContentKey: 'async_trait,
    {
        // todo: implement beacon network validation
        Ok(ValidationResult::new(true))
    }
}
