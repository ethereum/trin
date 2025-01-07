#![cfg(feature = "ef-tests")]

use ef_tests::{test_consensus_type, types::NetworkUpgrade};
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
test_consensus_type!(Attestation, NetworkUpgrade::Bellatrix);
test_consensus_type!(AttestationData, NetworkUpgrade::Bellatrix);
test_consensus_type!(AttesterSlashing, NetworkUpgrade::Bellatrix);
test_consensus_type!(BeaconBlockHeader, NetworkUpgrade::Bellatrix);
test_consensus_type!(Checkpoint, NetworkUpgrade::Bellatrix);
test_consensus_type!(Deposit, NetworkUpgrade::Bellatrix);
test_consensus_type!(DepositData, NetworkUpgrade::Bellatrix);
test_consensus_type!(Eth1Data, NetworkUpgrade::Bellatrix);
test_consensus_type!(Fork, NetworkUpgrade::Bellatrix);
test_consensus_type!(HistoricalBatch, NetworkUpgrade::Bellatrix);
test_consensus_type!(IndexedAttestation, NetworkUpgrade::Bellatrix);
test_consensus_type!(ProposerSlashing, NetworkUpgrade::Bellatrix);
test_consensus_type!(SignedVoluntaryExit, NetworkUpgrade::Bellatrix);
test_consensus_type!(SyncAggregate, NetworkUpgrade::Bellatrix);
test_consensus_type!(SyncCommittee, NetworkUpgrade::Bellatrix);
test_consensus_type!(Validator, NetworkUpgrade::Bellatrix);
test_consensus_type!(VoluntaryExit, NetworkUpgrade::Bellatrix);

// Bellatrix types
test_consensus_type!(BeaconBlockBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(BeaconBlockBodyBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(BeaconStateBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(ExecutionPayloadBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(ExecutionPayloadHeaderBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(LightClientBootstrapBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(
    LightClientFinalityUpdateBellatrix,
    NetworkUpgrade::Bellatrix
);
test_consensus_type!(LightClientHeaderBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(
    LightClientOptimisticUpdateBellatrix,
    NetworkUpgrade::Bellatrix
);
test_consensus_type!(LightClientUpdateBellatrix, NetworkUpgrade::Bellatrix);
test_consensus_type!(SignedBeaconBlockBellatrix, NetworkUpgrade::Bellatrix);

// Generic types added in Capella
test_consensus_type!(BLSToExecutionChange, NetworkUpgrade::Capella);
test_consensus_type!(HistoricalSummary, NetworkUpgrade::Capella);
test_consensus_type!(SignedBLSToExecutionChange, NetworkUpgrade::Capella);
test_consensus_type!(Withdrawal, NetworkUpgrade::Capella);

// Capella types
test_consensus_type!(BeaconBlockCapella, NetworkUpgrade::Capella);
test_consensus_type!(BeaconBlockBodyCapella, NetworkUpgrade::Capella);
test_consensus_type!(BeaconStateCapella, NetworkUpgrade::Capella);
test_consensus_type!(ExecutionPayloadCapella, NetworkUpgrade::Capella);
test_consensus_type!(ExecutionPayloadHeaderCapella, NetworkUpgrade::Capella);
test_consensus_type!(LightClientBootstrapCapella, NetworkUpgrade::Capella);
test_consensus_type!(LightClientFinalityUpdateCapella, NetworkUpgrade::Capella);
test_consensus_type!(LightClientHeaderCapella, NetworkUpgrade::Capella);
test_consensus_type!(LightClientOptimisticUpdateCapella, NetworkUpgrade::Capella);
test_consensus_type!(LightClientUpdateCapella, NetworkUpgrade::Capella);
test_consensus_type!(SignedBeaconBlockCapella, NetworkUpgrade::Capella);

// Deneb types
test_consensus_type!(BeaconBlockDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(BeaconBlockBodyDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(BeaconStateDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(ExecutionPayloadDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(ExecutionPayloadHeaderDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(LightClientBootstrapDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(LightClientFinalityUpdateDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(LightClientHeaderDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(LightClientOptimisticUpdateDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(LightClientUpdateDeneb, NetworkUpgrade::Deneb);
test_consensus_type!(SignedBeaconBlockDeneb, NetworkUpgrade::Deneb);
