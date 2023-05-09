use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use trin_types::content_key::BeaconContentKey;

use trin_validation::{oracle::HeaderOracle, validator::Validator};

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
    ) -> anyhow::Result<()>
    where
        BeaconContentKey: 'async_trait,
    {
        // todo: implement beacon network validation
        Ok(())
    }
}
