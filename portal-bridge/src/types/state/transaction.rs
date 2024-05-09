use alloy_primitives::U256;
use ethportal_api::types::execution::transaction::{
    AccessListTransaction, BlobTransaction, EIP1559Transaction, LegacyTransaction, ToAddress,
};
use revm_primitives::{TransactTo, TxEnv};

use super::{spec_id::SPURIOUS_DRAGON_BLOCK_NUMBER, utils::u256_to_lower_u64};

pub trait TxEnvModifier {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv);
}

impl TxEnvModifier for LegacyTransaction {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv) {
        tx_env.gas_limit = u256_to_lower_u64(self.gas);
        tx_env.gas_price = U256::from(self.gas_price);
        tx_env.gas_priority_fee = None;
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = if block_number >= SPURIOUS_DRAGON_BLOCK_NUMBER {
            Some(1)
        } else {
            None
        };
        tx_env.nonce = Some(u256_to_lower_u64(self.nonce));
        tx_env.access_list.clear();
        tx_env.blob_hashes.clear();
        tx_env.max_fee_per_blob_gas.take();
    }
}

impl TxEnvModifier for EIP1559Transaction {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        tx_env.gas_limit = u256_to_lower_u64(self.gas_limit);
        tx_env.gas_price = U256::from(self.max_fee_per_gas);
        tx_env.gas_priority_fee = Some(U256::from(self.max_priority_fee_per_gas));
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = Some(u256_to_lower_u64(self.chain_id));
        tx_env.nonce = Some(u256_to_lower_u64(self.nonce));
        tx_env.access_list = self
            .access_list
            .list
            .iter()
            .map(|l| {
                (
                    l.address,
                    l.storage_keys
                        .iter()
                        .map(|k| U256::from_be_bytes(k.0))
                        .collect(),
                )
            })
            .collect();
        tx_env.blob_hashes.clear();
        tx_env.max_fee_per_blob_gas.take();
    }
}

impl TxEnvModifier for AccessListTransaction {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        tx_env.gas_limit = u256_to_lower_u64(self.gas_limit);
        tx_env.gas_price = U256::from(self.gas_price);
        tx_env.gas_priority_fee = None;
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = Some(u256_to_lower_u64(self.chain_id));
        tx_env.nonce = Some(u256_to_lower_u64(self.nonce));
        tx_env.access_list = self
            .access_list
            .list
            .iter()
            .map(|l| {
                (
                    l.address,
                    l.storage_keys
                        .iter()
                        .map(|k| U256::from_be_bytes(k.0))
                        .collect(),
                )
            })
            .collect();
        tx_env.blob_hashes.clear();
        tx_env.max_fee_per_blob_gas.take();
    }
}

impl TxEnvModifier for BlobTransaction {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        tx_env.gas_limit = u256_to_lower_u64(self.gas_limit);
        tx_env.gas_price = U256::from(self.max_fee_per_gas);
        tx_env.gas_priority_fee = Some(U256::from(self.max_priority_fee_per_gas));
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = Some(u256_to_lower_u64(self.chain_id));
        tx_env.nonce = Some(u256_to_lower_u64(self.nonce));
        tx_env.access_list = self
            .access_list
            .list
            .iter()
            .map(|l| {
                (
                    l.address,
                    l.storage_keys
                        .iter()
                        .map(|k| U256::from_be_bytes(k.0))
                        .collect(),
                )
            })
            .collect();
        tx_env.blob_hashes = self.blob_versioned_hashes.clone();
        tx_env.max_fee_per_blob_gas = Some(U256::from(self.max_fee_per_blob_gas));
    }
}
