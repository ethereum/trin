use async_trait::async_trait;
use rlp::Rlp;

use trin_core::portalnet::types::content_key::HistoryContentKey;
use trin_core::portalnet::types::messages::ByteList;
use trin_core::types::header::Header;
use trin_core::types::validation::{ValidationOracle, Validator};

pub struct ChainHistoryValidator {
    pub validation_oracle: ValidationOracle,
}

#[async_trait]
impl Validator<HistoryContentKey> for ChainHistoryValidator {
    async fn validate_content(&mut self, content_key: HistoryContentKey, content: ByteList)
    where
        HistoryContentKey: 'async_trait,
    {
        match content_key {
            HistoryContentKey::BlockHeader(key) => {
                let rlp = Rlp::new(&content);
                let header = Header::decode_rlp(&rlp).expect("invalid header");
                let number = format!("0x{:02X}", header.number);
                let expected_hash = self.validation_oracle.get_hash_at_height(number).unwrap();
                assert_eq!(hex::encode(key.block_hash), expected_hash);
            }
            HistoryContentKey::BlockBody(_key) => {
                // use timeout w/ fallback to infura
                // send fetch header request to validation oracle
                // - already validated whether it's fetched from local db or from network
                // validate body against header
            }
            HistoryContentKey::BlockReceipts(_key) => {
                // use timeout w/ fallback to infura
                // send fetch header request to validation oracle
                // - already validated whether it's fetched from local db or from network
                // validate body against header
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rlp::{self, Rlp};

    use trin_core::portalnet::types::content_key::BlockHeader;
    use trin_core::utils::infura::{fetch_infura_id_from_env, get_infura_url};

    #[tokio::test]
    async fn validate_header() {
        let infura_project_id = fetch_infura_id_from_env();
        // RLP encoded block header #669051
        let header_rlp = hex::decode("f90217a092bccf7a38604c5441dffc5eb5a5ca295b3fbb7ff01cc92fb3b48f0d456e732ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794f8b483dba2c3b7176a3da549ad41a48bb3121069a08a779b9d52800c3f0fc2ec4f8388dd56e1fcf4685126466bc1a9832ab2ddf612a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860717d1b1cd0e830a357b832fefd88084566930a39ad983010203844765746887676f312e342e328777696e646f7773a0daa40d4b72000209b43526ada798b90b98f9cd6e4cdc5bebbad690208aa1728788e6b9441a5df2f6ad").unwrap();
        let header_bytelist = ByteList::try_from(header_rlp.clone()).unwrap();
        let rlp = Rlp::new(&header_rlp);

        let header: Header = Header::decode_rlp(&rlp).expect("error decoding header");
        let infura_url = get_infura_url(&infura_project_id);
        let validation_oracle = ValidationOracle {
            infura_url,
            ..ValidationOracle::default()
        };
        let mut chain_history_validator = ChainHistoryValidator { validation_oracle };
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().0,
        });
        chain_history_validator
            .validate_content(content_key, header_bytelist)
            .await;
    }
}
