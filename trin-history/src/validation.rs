use std::sync::{Arc, RwLock};

use anyhow::anyhow;
use async_trait::async_trait;

use trin_core::{
    portalnet::types::{content_key::HistoryContentKey, messages::ByteList},
    types::{
        header::Header,
        validation::{HeaderOracle, Validator},
    },
};

pub struct ChainHistoryValidator {
    pub header_oracle: Arc<RwLock<HeaderOracle>>,
}

#[async_trait]
impl Validator<HistoryContentKey> for ChainHistoryValidator {
    async fn validate_content(
        &mut self,
        content_key: &HistoryContentKey,
        content: &ByteList,
    ) -> anyhow::Result<()>
    where
        HistoryContentKey: 'async_trait,
    {
        match content_key {
            HistoryContentKey::BlockHeader(key) => {
                let header: Header = rlp::decode(content)?;
                let expected_hash = &self
                    .header_oracle
                    .write()
                    .unwrap()
                    .get_hash_at_height(header.number)?;
                let actual_hash = &hex::encode(key.block_hash);
                if actual_hash == expected_hash {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "Content validation failed. Found: {:?} - Expected: {:?}",
                        actual_hash,
                        expected_hash
                    ))
                }
            }
            HistoryContentKey::BlockBody(_key) => {
                // use timeout w/ fallback to infura
                // send fetch header request to validation oracle
                // - already validated whether it's fetched from local db or from network
                // validate body against header
                Err(anyhow!("Validation for block bodies is not yet supported."))
            }
            HistoryContentKey::BlockReceipts(_key) => {
                // use timeout w/ fallback to infura
                // send fetch header request to validation oracle
                // - already validated whether it's fetched from local db or from network
                // validate body against header
                Err(anyhow!(
                    "Validation for block receipts is not yet supported."
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::U256;
    use hex;
    use httpmock::prelude::*;
    use serde_json::json;

    use trin_core::portalnet::types::content_key::BlockHeader;

    fn get_header_rlp() -> Vec<u8> {
        // RLP encoded block header #669051
        hex::decode("f90217a092bccf7a38604c5441dffc5eb5a5ca295b3fbb7ff01cc92fb3b48f0d456e732ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794f8b483dba2c3b7176a3da549ad41a48bb3121069a08a779b9d52800c3f0fc2ec4f8388dd56e1fcf4685126466bc1a9832ab2ddf612a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000860717d1b1cd0e830a357b832fefd88084566930a39ad983010203844765746887676f312e342e328777696e646f7773a0daa40d4b72000209b43526ada798b90b98f9cd6e4cdc5bebbad690208aa1728788e6b9441a5df2f6ad").unwrap()
    }

    fn setup_mock_infura_server() -> MockServer {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(POST)
                .path("/get_header");
            then.status(200)
                .header("content-type", "application/json")
                .json_body(json!({
                    "jsonrpc":"2.0",
                    "id":1,
                    "result":{
                        "difficulty":"0x717d1b1cd0e",
                        "extraData":"0xd983010203844765746887676f312e342e328777696e646f7773",
                        "gasLimit":"0x2fefd8",
                        "gasUsed":"0x0",
                        "hash":"0xe2f81ab2f7a0aaa6c5cee61a82d176a2344603f8cf8569e135e1ee98667f0bc3",
                        "logsBloom":"0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "miner":"0xf8b483dba2c3b7176a3da549ad41a48bb3121069",
                        "mixHash":"0xdaa40d4b72000209b43526ada798b90b98f9cd6e4cdc5bebbad690208aa17287",
                        "nonce":"0xe6b9441a5df2f6ad",
                        "number":"0xa357b",
                        "parentHash":"0x92bccf7a38604c5441dffc5eb5a5ca295b3fbb7ff01cc92fb3b48f0d456e732e",
                        "receiptsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                        "size":"0x21f",
                        "stateRoot":"0x8a779b9d52800c3f0fc2ec4f8388dd56e1fcf4685126466bc1a9832ab2ddf612",
                        "timestamp":"0x566930a3",
                        "totalDifficulty":"0x37b4d6b53544c4e1",
                        "transactions":[],
                        "transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
                        "uncles":[]
                    }
                }));
        });
        server
    }

    #[tokio::test]
    async fn validate_header() {
        let server = setup_mock_infura_server();
        let header_rlp = get_header_rlp();
        let header_bytelist = ByteList::try_from(header_rlp.clone()).unwrap();

        let header: Header = rlp::decode(&header_rlp).expect("error decoding header");
        let infura_url = server.url("/get_header");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &header_bytelist)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn invalidate_header_with_invalid_number() {
        let server = setup_mock_infura_server();
        // RLP encoded block header #669051
        let header_rlp = get_header_rlp();
        let header_bytelist = ByteList::try_from(header_rlp.clone()).unwrap();
        let mut header: Header = rlp::decode(&header_rlp).expect("error decoding header");

        // set invalid block height
        header.number = 669052;

        let infura_url = server.url("/get_header");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &header_bytelist)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic]
    async fn invalidate_header_with_invalid_gaslimit() {
        let server = setup_mock_infura_server();
        // RLP encoded block header #669051
        let header_rlp = get_header_rlp();
        let header_bytelist = ByteList::try_from(header_rlp.clone()).unwrap();
        let mut header: Header = rlp::decode(&header_rlp).expect("error decoding header");

        // set invalid block gaslimit
        // valid gaslimit = 3141592
        header.gas_limit = U256::from(3141591);

        let infura_url = server.url("/get_header");
        let header_oracle = Arc::new(RwLock::new(HeaderOracle {
            infura_url,
            ..HeaderOracle::default()
        }));
        let mut chain_history_validator = ChainHistoryValidator { header_oracle };
        let content_key = HistoryContentKey::BlockHeader(BlockHeader {
            chain_id: 1,
            block_hash: header.hash().0,
        });
        chain_history_validator
            .validate_content(&content_key, &header_bytelist)
            .await
            .unwrap();
    }
}
