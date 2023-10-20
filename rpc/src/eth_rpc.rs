use ethereum_types::{H256, U256, U64};
use reth_rpc_types::{Block, BlockTransactions, Parity, Signature, Transaction as RethTransaction};
use ruint::Uint;
use tokio::sync::mpsc;

use ethportal_api::types::execution::block_body::BlockBody;
use ethportal_api::types::execution::transaction::Transaction;
use ethportal_api::types::jsonrpc::request::HistoryJsonRpcRequest;
use ethportal_api::utils::rethtypes::{ethtype_u64_to_uint256, u256_to_uint128, u256_to_uint256};
use ethportal_api::EthApiServer;
use trin_validation::constants::CHAIN_ID;

use crate::fetch::{find_block_body_by_hash, find_header_by_hash};
use crate::jsonrpsee::core::{async_trait, RpcResult};

pub struct EthApi {
    network: mpsc::UnboundedSender<HistoryJsonRpcRequest>,
}

impl EthApi {
    pub fn new(network: mpsc::UnboundedSender<HistoryJsonRpcRequest>) -> Self {
        Self { network }
    }
}

fn rpc_transaction(
    transaction: Transaction,
    block_hash: H256,
    block_number: u64,
    transaction_index: usize,
) -> RethTransaction {
    // Fields not extractable from the transaction itself
    let block_hash = Some(block_hash.as_fixed_bytes().into());
    let block_number = Some(Uint::from(block_number.into()));
    let transaction_index = Some(Uint::from(transaction_index));

    // Fields calculated on the full transaction envelope
    let hash = transaction.hash().as_fixed_bytes().into();
    let type_id = match transaction.type_id() {
        0 => None,
        n => Some(U64::from(n)),
    };
    // TODO: generate 'from' address from signature
    let from = None;

    // Fields internal to the transaction, sometimes varying by transaction type
    let (
        transaction_type,
        nonce,
        gas_price,
        gas,
        to,
        value,
        input,
        v,
        r,
        s,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        access_list,
        y_parity,
    ) = match transaction {
        Transaction::Legacy(tx) => (
            None,
            tx.nonce,
            Some(u256_to_uint128(tx.gas_price)),
            tx.gas,
            tx.to,
            tx.value,
            tx.data,
            tx.v,
            tx.r,
            tx.s,
            None,
            None,
            None,
            None,
        ),
        Transaction::AccessList(tx) => (
            Some(1.into()),
            tx.nonce,
            Some(u256_to_uint128(tx.gas_price)),
            tx.gas,
            tx.to,
            tx.value,
            tx.data,
            tx.y_parity,
            tx.r,
            tx.s,
            None,
            None,
            Some(tx.access_list),
            Some(tx.y_parity),
        ),
        Transaction::EIP1559(tx) => (
            Some(2.into()),
            tx.nonce,
            None,
            tx.gas,
            tx.to,
            tx.value,
            tx.data,
            tx.y_parity,
            tx.r,
            tx.s,
            Some(u256_to_uint128(tx.max_fee_per_gas)),
            Some(u256_to_uint128(tx.max_priority_fee_per_gas)),
            Some(tx.access_list),
            Some(tx.y_parity),
        ),
    };

    // Convert types
    let nonce = nonce.as_u64().into();
    let (gas, value) = (u256_to_uint256(gas), u256_to_uint256(value));
    let input = input.into();
    let signature = Some(Signature {
        r: u256_to_uint256(r),
        s: u256_to_uint256(s),
        v: ethtype_u64_to_uint256(v),
        y_parity: y_parity.map(|y| Parity(!y.is_zero())),
    });

    // Fields that are hardcoded, for now
    let max_fee_per_blob_gas = None;
    let chain_id = Some(CHAIN_ID.into());
    let blob_versioned_hashes = vec![];

    RethTransaction {
        hash,
        nonce,
        block_hash,
        block_number,
        transaction_index,
        from,
        to,
        value,
        gas_price,
        gas,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        max_fee_per_blob_gas,
        input,
        signature,
        chain_id,
        blob_versioned_hashes,
        access_list,
        transaction_type,
    }
}

#[async_trait]
impl EthApiServer for EthApi {
    async fn chain_id(&self) -> RpcResult<U256> {
        Ok(U256::from(CHAIN_ID))
    }

    async fn get_block_by_hash(
        &self,
        block_hash: H256,
        hydrated_transactions: bool,
    ) -> RpcResult<Block> {
        let header = find_header_by_hash(&self.network, block_hash).await?;
        let body = find_block_body_by_hash(&self.network, block_hash).await?;
        let transactions = match body {
            BlockBody::Legacy(body) => body.txs,
            BlockBody::Merge(body) => body.txs,
            BlockBody::Shanghai(body) => body.txs,
        };
        let transactions = if hydrated_transactions {
            BlockTransactions::Full(
                transactions
                    .into_iter()
                    .enumerate()
                    .map(|(idx, tx)| rpc_transaction(tx, block_hash, header.number, idx))
                    .collect(),
            )
        } else {
            BlockTransactions::Hashes(
                transactions
                    .into_iter()
                    .map(|tx| tx.hash().as_fixed_bytes().into())
                    .collect(),
            )
        };

        // Combine header and block body into the single json representation of the block.
        let block = Block {
            header: header.into(),
            transactions,
            uncles: vec![],
            size: None,
            total_difficulty: None,
            withdrawals: None,
        };
        Ok(block)
    }
}

impl std::fmt::Debug for EthApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EthApi").finish_non_exhaustive()
    }
}
