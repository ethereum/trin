use alloy::{
    consensus::{TxEip1559, TxEip2930, TxEip4844, TxLegacy},
    rpc::types::TransactionRequest,
};
use revm::context::TxEnv;
use revm_primitives::{hardfork::SpecId, TxKind};

use super::spec_id::get_spec_id;

pub trait TxEnvModifier {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv);
}

impl TxEnvModifier for TxLegacy {
    fn modify(&self, block_number: u64, tx_env: &mut TxEnv) {
        *tx_env = TxEnv {
            tx_type: 0,
            caller: tx_env.caller,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            kind: self.to,
            value: self.value,
            data: self.input.clone(),
            nonce: self.nonce,
            chain_id: if get_spec_id(block_number).is_enabled_in(SpecId::SPURIOUS_DRAGON) {
                Some(1)
            } else {
                None
            },
            access_list: Default::default(),
            gas_priority_fee: None,
            blob_hashes: Default::default(),
            max_fee_per_blob_gas: Default::default(),
            authorization_list: Default::default(),
        };
    }
}

impl TxEnvModifier for TxEip2930 {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        *tx_env = TxEnv {
            tx_type: 1,
            caller: tx_env.caller,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            kind: self.to,
            value: self.value,
            data: self.input.clone(),
            nonce: self.nonce,
            chain_id: Some(self.chain_id),
            access_list: self.access_list.clone(),
            gas_priority_fee: None,
            blob_hashes: Default::default(),
            max_fee_per_blob_gas: Default::default(),
            authorization_list: Default::default(),
        };
    }
}

impl TxEnvModifier for TxEip1559 {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        *tx_env = TxEnv {
            tx_type: 2,
            caller: tx_env.caller,
            gas_limit: self.gas_limit,
            gas_price: self.max_fee_per_gas,
            kind: self.to,
            value: self.value,
            data: self.input.clone(),
            nonce: self.nonce,
            chain_id: Some(self.chain_id),
            access_list: self.access_list.clone(),
            gas_priority_fee: Some(self.max_priority_fee_per_gas),
            blob_hashes: Default::default(),
            max_fee_per_blob_gas: Default::default(),
            authorization_list: Default::default(),
        };
    }
}

impl TxEnvModifier for TxEip4844 {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        *tx_env = TxEnv {
            tx_type: 3,
            caller: tx_env.caller,
            gas_limit: self.gas_limit,
            gas_price: self.max_fee_per_gas,
            kind: TxKind::Call(self.to),
            value: self.value,
            data: self.input.clone(),
            nonce: self.nonce,
            chain_id: Some(self.chain_id),
            access_list: self.access_list.clone(),
            gas_priority_fee: Some(self.max_priority_fee_per_gas),
            blob_hashes: self.blob_versioned_hashes.clone(),
            max_fee_per_blob_gas: self.max_fee_per_blob_gas,
            authorization_list: Default::default(),
        };
    }
}

impl TxEnvModifier for TransactionRequest {
    fn modify(&self, _block_number: u64, tx_env: &mut TxEnv) {
        if let Some(from) = self.from {
            tx_env.caller = from;
        }
        if let Some(to) = self.to {
            tx_env.kind = to;
        }
        if let Some(gas_price) = self.gas_price {
            tx_env.gas_price = gas_price;
        }
        if let Some(max_fee_per_gas) = self.max_fee_per_gas {
            tx_env.gas_price = max_fee_per_gas;
        }
        tx_env.gas_priority_fee = self.max_priority_fee_per_gas;
        if let Some(max_fee_per_blob_gas) = self.max_fee_per_blob_gas {
            tx_env.max_fee_per_blob_gas = max_fee_per_blob_gas;
        }
        if let Some(gas) = self.gas {
            tx_env.gas_limit = gas;
        }
        if let Some(value) = self.value {
            tx_env.value = value;
        }
        if let Some(data) = self.input.input() {
            tx_env.data.clone_from(data);
        }
        if let Some(nonce) = self.nonce {
            tx_env.nonce = nonce;
        }
        tx_env.chain_id = self.chain_id;
        if let Some(access_list) = &self.access_list {
            tx_env.access_list.clone_from(access_list);
        }
        if let Some(blob_versioned_hashes) = &self.blob_versioned_hashes {
            tx_env.blob_hashes.clone_from(blob_versioned_hashes);
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::bytes::Bytes;
    use revm::context::TransactTo;
    use revm_primitives::{TxKind, U256};

    use super::*;

    #[test]
    fn test_legacy_tx_env_modifier() {
        let tx = TxLegacy {
            nonce: 1,
            gas_price: 1,
            gas_limit: 1,
            to: TxKind::Call(Default::default()),
            value: U256::from(1),
            input: revm_primitives::Bytes(Bytes::from(vec![1, 2, 3])),
            chain_id: None,
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, 1);
        assert_eq!(tx_env.gas_price, 1);
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.kind, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
    }

    #[test]
    fn test_eip1559_tx_env_modifier() {
        let tx = TxEip1559 {
            nonce: 1,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            gas_limit: 1,
            to: TxKind::Call(Default::default()),
            value: U256::from(1),
            input: revm_primitives::Bytes(Bytes::from(vec![1, 2, 3])),
            chain_id: 1,
            access_list: Default::default(),
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, 1);
        assert_eq!(tx_env.gas_price, 1);
        assert_eq!(tx_env.gas_priority_fee, Some(1));
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.kind, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
        assert_eq!(tx_env.chain_id, Some(1));
        assert_eq!(tx_env.access_list, Default::default());
    }

    #[test]
    fn test_access_list_tx_env_modifier() {
        let tx = TxEip2930 {
            nonce: 1,
            gas_price: 1,
            gas_limit: 1,
            to: TxKind::Call(Default::default()),
            value: U256::from(1),
            input: revm_primitives::Bytes(Bytes::from(vec![1, 2, 3])),
            chain_id: 1,
            access_list: Default::default(),
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, 1);
        assert_eq!(tx_env.gas_price, 1);
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.kind, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
        assert_eq!(tx_env.chain_id, Some(1));
        assert_eq!(tx_env.access_list, Default::default());
    }

    #[test]
    fn test_blob_tx_env_modifier() {
        let tx = TxEip4844 {
            nonce: 1,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            max_fee_per_blob_gas: 1,
            gas_limit: 1,
            to: Default::default(),
            value: U256::from(1),
            input: revm_primitives::Bytes(Bytes::from(vec![1, 2, 3])),
            chain_id: 1,
            access_list: Default::default(),
            blob_versioned_hashes: Default::default(),
        };
        let mut tx_env = TxEnv::default();
        tx.modify(0, &mut tx_env);
        assert_eq!(tx_env.nonce, 1);
        assert_eq!(tx_env.gas_price, 1);
        assert_eq!(tx_env.gas_priority_fee, Some(1));
        assert_eq!(tx_env.gas_limit, 1);
        assert_eq!(tx_env.kind, TransactTo::Call(Default::default()));
        assert_eq!(tx_env.value, U256::from(1));
        assert_eq!(tx_env.data.0, vec![1, 2, 3]);
        assert_eq!(tx_env.chain_id, Some(1));
        assert_eq!(tx_env.access_list, Default::default());
        assert_eq!(tx_env.blob_hashes.len(), 0);
        assert_eq!(tx_env.max_fee_per_blob_gas, 1);
    }
}
