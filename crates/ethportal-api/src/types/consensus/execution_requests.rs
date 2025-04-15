use serde::{Deserialize, Serialize};
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
