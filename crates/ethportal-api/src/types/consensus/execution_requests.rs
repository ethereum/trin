use alloy::{eips::eip7685::Requests as AlloyRequests, primitives::B256};
use serde::{Deserialize, Serialize};
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{
    typenum::{U16, U2, U8192},
    VariableList,
};
use tree_hash_derive::TreeHash;

use crate::consensus::{
    consolidation_request::ConsolidationRequest, deposit_request::DepositRequest,
    withdrawal_request::WithdrawalRequest,
};

type MaxDepositRequestsPerPayload = U8192;
type MaxWithdrawalRequestsPerPayload = U16;
type MaxConsolidationRequestsPerPayload = U2;

pub type DepositRequests = VariableList<DepositRequest, MaxDepositRequestsPerPayload>;
pub type WithdrawalRequests = VariableList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>;
pub type ConsolidationRequests =
    VariableList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>;

#[derive(Debug, Default, Clone, Serialize, Deserialize, Encode, Decode, TreeHash, PartialEq)]
pub struct ExecutionRequests {
    pub deposits: DepositRequests,
    pub withdrawals: WithdrawalRequests,
    pub consolidations: ConsolidationRequests,
}

impl ExecutionRequests {
    pub fn requests_hash(&self) -> B256 {
        let mut requests = AlloyRequests::with_capacity(3);

        requests.push_request_with_type(DepositRequest::REQUEST_TYPE, self.deposits.as_ssz_bytes());
        requests.push_request_with_type(
            WithdrawalRequest::REQUEST_TYPE,
            self.withdrawals.as_ssz_bytes(),
        );
        requests.push_request_with_type(
            ConsolidationRequest::REQUEST_TYPE,
            self.consolidations.as_ssz_bytes(),
        );

        requests.requests_hash()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{b256, Address, B256};

    use super::*;
    use crate::consensus::{pubkey::PubKey, signature::BlsSignature};

    #[test]
    fn test_requests_hash() {
        let deposit_request = DepositRequest {
            pubkey: PubKey::default(),
            withdrawal_credentials: B256::default(),
            amount: 0,
            signature: BlsSignature::default(),
            index: 0,
        };

        let withdrawal_request = WithdrawalRequest {
            amount: 0,
            source_address: Address::default(),
            validator_pubkey: PubKey::default(),
        };

        let consolidation_request = ConsolidationRequest {
            source_address: Address::default(),
            source_pubkey: PubKey::default(),
            target_pubkey: PubKey::default(),
        };

        let execution_requests = ExecutionRequests {
            deposits: vec![deposit_request].into(),
            withdrawals: vec![withdrawal_request].into(),
            consolidations: vec![consolidation_request].into(),
        };

        let expected_hash =
            b256!("0x4001980e70daeb56b1dc6d921726b87df98f92d04f400e3b21ed96d9a1c28062");
        assert_eq!(expected_hash, execution_requests.requests_hash());
    }
}
