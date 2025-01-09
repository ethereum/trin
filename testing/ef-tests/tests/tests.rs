#![cfg(feature = "ef-tests")]

use ef_tests::test_consensus_type;
use ethportal_api::{
    consensus::{
        beacon_block::{
            BeaconBlockBellatrix, BeaconBlockCapella, BeaconBlockDeneb, SignedBeaconBlockBellatrix,
            SignedBeaconBlockCapella, SignedBeaconBlockDeneb,
        },
        beacon_state::{
            BeaconStateBellatrix, BeaconStateCapella, BeaconStateDeneb, Fork, HistoricalBatch,
            Validator,
        },
        body::{
            Attestation, AttestationData, AttesterSlashing, BLSToExecutionChange,
            BeaconBlockBodyBellatrix, BeaconBlockBodyCapella, BeaconBlockBodyDeneb, Checkpoint,
            Deposit, DepositData, Eth1Data, IndexedAttestation, ProposerSlashing,
            SignedBLSToExecutionChange, SignedVoluntaryExit, SyncAggregate, VoluntaryExit,
        },
        execution_payload::{
            ExecutionPayloadBellatrix, ExecutionPayloadCapella, ExecutionPayloadDeneb,
            ExecutionPayloadHeaderBellatrix, ExecutionPayloadHeaderCapella,
            ExecutionPayloadHeaderDeneb, Withdrawal,
        },
        fork::ForkName,
        header::BeaconBlockHeader,
        historical_summaries::HistoricalSummary,
        sync_committee::SyncCommittee,
    },
    light_client::{
        bootstrap::{
            LightClientBootstrapBellatrix, LightClientBootstrapCapella, LightClientBootstrapDeneb,
        },
        finality_update::{
            LightClientFinalityUpdateBellatrix, LightClientFinalityUpdateCapella,
            LightClientFinalityUpdateDeneb,
        },
        header::{LightClientHeaderBellatrix, LightClientHeaderCapella, LightClientHeaderDeneb},
        optimistic_update::{
            LightClientOptimisticUpdateBellatrix, LightClientOptimisticUpdateCapella,
            LightClientOptimisticUpdateDeneb,
        },
        update::{LightClientUpdateBellatrix, LightClientUpdateCapella, LightClientUpdateDeneb},
    },
};

// Generic types
test_consensus_type!(Attestation, ForkName::Bellatrix);
test_consensus_type!(AttestationData, ForkName::Bellatrix);
test_consensus_type!(AttesterSlashing, ForkName::Bellatrix);
test_consensus_type!(BeaconBlockHeader, ForkName::Bellatrix);
test_consensus_type!(Checkpoint, ForkName::Bellatrix);
test_consensus_type!(Deposit, ForkName::Bellatrix);
test_consensus_type!(DepositData, ForkName::Bellatrix);
test_consensus_type!(Eth1Data, ForkName::Bellatrix);
test_consensus_type!(Fork, ForkName::Bellatrix);
test_consensus_type!(HistoricalBatch, ForkName::Bellatrix);
test_consensus_type!(IndexedAttestation, ForkName::Bellatrix);
test_consensus_type!(ProposerSlashing, ForkName::Bellatrix);
test_consensus_type!(SignedVoluntaryExit, ForkName::Bellatrix);
test_consensus_type!(SyncAggregate, ForkName::Bellatrix);
test_consensus_type!(SyncCommittee, ForkName::Bellatrix);
test_consensus_type!(Validator, ForkName::Bellatrix);
test_consensus_type!(VoluntaryExit, ForkName::Bellatrix);

// Bellatrix types
test_consensus_type!(BeaconBlockBellatrix, ForkName::Bellatrix);
test_consensus_type!(BeaconBlockBodyBellatrix, ForkName::Bellatrix);
test_consensus_type!(BeaconStateBellatrix, ForkName::Bellatrix);
test_consensus_type!(ExecutionPayloadBellatrix, ForkName::Bellatrix);
test_consensus_type!(ExecutionPayloadHeaderBellatrix, ForkName::Bellatrix);
test_consensus_type!(LightClientBootstrapBellatrix, ForkName::Bellatrix);
test_consensus_type!(LightClientFinalityUpdateBellatrix, ForkName::Bellatrix);
test_consensus_type!(LightClientHeaderBellatrix, ForkName::Bellatrix);
test_consensus_type!(LightClientOptimisticUpdateBellatrix, ForkName::Bellatrix);
test_consensus_type!(LightClientUpdateBellatrix, ForkName::Bellatrix);
test_consensus_type!(SignedBeaconBlockBellatrix, ForkName::Bellatrix);

// Generic types added in Capella
test_consensus_type!(BLSToExecutionChange, ForkName::Capella);
test_consensus_type!(HistoricalSummary, ForkName::Capella);
test_consensus_type!(SignedBLSToExecutionChange, ForkName::Capella);
test_consensus_type!(Withdrawal, ForkName::Capella);

// Capella types
test_consensus_type!(BeaconBlockCapella, ForkName::Capella);
test_consensus_type!(BeaconBlockBodyCapella, ForkName::Capella);
test_consensus_type!(BeaconStateCapella, ForkName::Capella);
test_consensus_type!(ExecutionPayloadCapella, ForkName::Capella);
test_consensus_type!(ExecutionPayloadHeaderCapella, ForkName::Capella);
test_consensus_type!(LightClientBootstrapCapella, ForkName::Capella);
test_consensus_type!(LightClientFinalityUpdateCapella, ForkName::Capella);
test_consensus_type!(LightClientHeaderCapella, ForkName::Capella);
test_consensus_type!(LightClientOptimisticUpdateCapella, ForkName::Capella);
test_consensus_type!(LightClientUpdateCapella, ForkName::Capella);
test_consensus_type!(SignedBeaconBlockCapella, ForkName::Capella);

// Deneb types
test_consensus_type!(BeaconBlockDeneb, ForkName::Deneb);
test_consensus_type!(BeaconBlockBodyDeneb, ForkName::Deneb);
test_consensus_type!(BeaconStateDeneb, ForkName::Deneb);
test_consensus_type!(ExecutionPayloadDeneb, ForkName::Deneb);
test_consensus_type!(ExecutionPayloadHeaderDeneb, ForkName::Deneb);
test_consensus_type!(LightClientBootstrapDeneb, ForkName::Deneb);
test_consensus_type!(LightClientFinalityUpdateDeneb, ForkName::Deneb);
test_consensus_type!(LightClientHeaderDeneb, ForkName::Deneb);
test_consensus_type!(LightClientOptimisticUpdateDeneb, ForkName::Deneb);
test_consensus_type!(LightClientUpdateDeneb, ForkName::Deneb);
test_consensus_type!(SignedBeaconBlockDeneb, ForkName::Deneb);
