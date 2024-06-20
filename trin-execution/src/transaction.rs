use alloy_primitives::U256;
use ethportal_api::types::execution::transaction::{
    AccessListTransaction, BlobTransaction, EIP1559Transaction, LegacyTransaction, ToAddress,
};
use revm_primitives::{SpecId, TransactTo, TxEnv};

use super::spec_id::get_spec_id;

pub trait TxEnvModifier {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv);
}

impl TxEnvModifier for LegacyTransaction {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv) {
        tx_env.gas_limit = self.gas.to::<u64>();
        tx_env.gas_price = U256::from(self.gas_price);
        tx_env.gas_priority_fee = None;
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = if get_spec_id(block_number).is_enabled_in(SpecId::SPURIOUS_DRAGON) {
            Some(1)
        } else {
            None
        };
        tx_env.nonce = Some(self.nonce.to::<u64>());
        tx_env.access_list.clear();
        tx_env.blob_hashes.clear();
        tx_env.max_fee_per_blob_gas.take();
    }
}

impl TxEnvModifier for EIP1559Transaction {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        tx_env.gas_limit = self.gas_limit.to::<u64>();
        tx_env.gas_price = self.max_fee_per_gas;
        tx_env.gas_priority_fee = Some(self.max_priority_fee_per_gas);
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = Some(self.chain_id.to::<u64>());
        tx_env.nonce = Some(self.nonce.to::<u64>());
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
        tx_env.gas_limit = self.gas_limit.to::<u64>();
        tx_env.gas_price = self.gas_price;
        tx_env.gas_priority_fee = None;
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = Some(self.chain_id.to::<u64>());
        tx_env.nonce = Some(self.nonce.to::<u64>());
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
        tx_env.gas_limit = self.gas_limit.to::<u64>();
        tx_env.gas_price = self.max_fee_per_gas;
        tx_env.gas_priority_fee = Some(self.max_priority_fee_per_gas);
        tx_env.transact_to = match self.to {
            ToAddress::Exists(to) => TransactTo::Call(to),
            ToAddress::Empty => TransactTo::create(),
        };
        tx_env.value = self.value;
        tx_env.data = alloy_primitives::Bytes(self.data.clone());
        tx_env.chain_id = Some(self.chain_id.to::<u64>());
        tx_env.nonce = Some(self.nonce.to::<u64>());
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
        tx_env.blob_hashes.clone_from(&self.blob_versioned_hashes);
        tx_env.max_fee_per_blob_gas = Some(U256::from(self.max_fee_per_blob_gas));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U64;
    use alloy_rlp::Bytes;
    use revm_primitives::TxEnv;

    #[test]
    fn test_legacy_tx_env_modifier() {
        let tx = LegacyTransaction {
            nonce: U256::from(1),
            gas_price: U256::from(1),
            gas: U256::from(1),
            to: ToAddress::Exists(Default::default()),
            value: U256::from(1),
            data: Bytes::from(vec![1, 2, 3]),
            v: U64::from(1),
            r: U256::from(1),
            s: U256::from(1),
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, Some(1));
        assert_eq!(tx_env.gas_price, U256::from(1));
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.transact_to, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
    }

    #[test]
    fn test_eip1559_tx_env_modifier() {
        let tx = EIP1559Transaction {
            nonce: U256::from(1),
            max_fee_per_gas: U256::from(1),
            max_priority_fee_per_gas: U256::from(1),
            gas_limit: U256::from(1),
            to: ToAddress::Exists(Default::default()),
            value: U256::from(1),
            data: Bytes::from(vec![1, 2, 3]),
            chain_id: U256::from(1),
            access_list: Default::default(),
            y_parity: U64::from(1),
            r: U256::from(1),
            s: U256::from(1),
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, Some(1));
        assert_eq!(tx_env.gas_price, U256::from(1));
        assert_eq!(tx_env.gas_priority_fee, Some(U256::from(1)));
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.transact_to, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
        assert_eq!(tx_env.chain_id, Some(1));
        assert_eq!(tx_env.access_list, vec![]);
    }

    #[test]
    fn test_access_list_tx_env_modifier() {
        let tx = AccessListTransaction {
            nonce: U256::from(1),
            gas_price: U256::from(1),
            gas_limit: U256::from(1),
            to: ToAddress::Exists(Default::default()),
            value: U256::from(1),
            data: Bytes::from(vec![1, 2, 3]),
            chain_id: U256::from(1),
            access_list: Default::default(),
            y_parity: U64::from(1),
            r: U256::from(1),
            s: U256::from(1),
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, Some(1));
        assert_eq!(tx_env.gas_price, U256::from(1));
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.transact_to, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
        assert_eq!(tx_env.chain_id, Some(1));
        assert_eq!(tx_env.access_list, vec![]);
    }

    #[test]
    fn test_blob_tx_env_modifier() {
        let tx = BlobTransaction {
            nonce: U256::from(1),
            max_fee_per_gas: U256::from(1),
            max_priority_fee_per_gas: U256::from(1),
            max_fee_per_blob_gas: U256::from(1),
            gas_limit: U256::from(1),
            to: ToAddress::Exists(Default::default()),
            value: U256::from(1),
            data: Bytes::from(vec![1, 2, 3]),
            chain_id: U256::from(1),
            access_list: Default::default(),
            blob_versioned_hashes: Default::default(),
            y_parity: U64::from(1),
            r: U256::from(1),
            s: U256::from(1),
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, Some(1));
        assert_eq!(tx_env.gas_price, U256::from(1));
        assert_eq!(tx_env.gas_priority_fee, Some(U256::from(1)));
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.transact_to, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
        assert_eq!(tx_env.chain_id, Some(1));
        assert_eq!(tx_env.access_list, vec![]);
        assert_eq!(tx_env.blob_hashes.len(), 0);
        assert_eq!(tx_env.max_fee_per_blob_gas, Some(U256::from(1)));
    }
}
