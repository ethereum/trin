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
        let mut requests = AlloyRequests::with_capacity(
            self.deposits.len() + self.withdrawals.len() + self.consolidations.len(),
        );

        for deposit_request in &self.deposits {
            requests.push_request_with_type(
                DepositRequest::REQUEST_TYPE,
                deposit_request.as_ssz_bytes(),
            );
        }
        for withdrawal_request in &self.withdrawals {
            requests.push_request_with_type(
                WithdrawalRequest::REQUEST_TYPE,
                withdrawal_request.as_ssz_bytes(),
            );
        }
        for consolidation_request in &self.consolidations {
            requests.push_request_with_type(
                ConsolidationRequest::REQUEST_TYPE,
                consolidation_request.as_ssz_bytes(),
            );
        }

        requests.requests_hash()
    }
}
