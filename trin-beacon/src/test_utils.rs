use alloy::primitives::B256;
use ethportal_api::{
    consensus::{
        beacon_state::BeaconStateDeneb,
        fork::ForkName,
        historical_summaries::{HistoricalSummariesStateProof, HistoricalSummariesWithProof},
    },
    light_client::{
        bootstrap::LightClientBootstrap, finality_update::LightClientFinalityUpdate,
        optimistic_update::LightClientOptimisticUpdate, update::LightClientUpdate,
    },
    types::content_value::beacon::{
        ForkVersionedHistoricalSummariesWithProof, ForkVersionedLightClientBootstrap,
        ForkVersionedLightClientFinalityUpdate, ForkVersionedLightClientOptimisticUpdate,
        ForkVersionedLightClientUpdate,
    },
};
use ssz::Decode;
use tree_hash::TreeHash;

// Valid number range for the test cases is 0..=1
pub fn get_light_client_bootstrap(number: u8) -> ForkVersionedLightClientBootstrap {
    let lc_bootstrap = std::fs::read(format!(
        "../test_assets/beacon/deneb/LightClientBootstrap/ssz_random/case_{number}/serialized.ssz_snappy"
    ))
        .expect("cannot find test asset");
    let mut decoder = snap::raw::Decoder::new();
    let lc_bootstrap = decoder.decompress_vec(&lc_bootstrap).unwrap();
    let lc_bootstrap =
        LightClientBootstrap::from_ssz_bytes(&lc_bootstrap, ForkName::Deneb).unwrap();

    ForkVersionedLightClientBootstrap {
        fork_name: ForkName::Deneb,
        bootstrap: lc_bootstrap,
    }
}

// Valid number range for the test cases is 0..=1
pub fn get_light_client_update(number: u8) -> ForkVersionedLightClientUpdate {
    let lc_update = std::fs::read(format!(
        "../test_assets/beacon/deneb/LightClientUpdate/ssz_random/case_{number}/serialized.ssz_snappy"
    ))
        .expect("cannot find test asset");
    let mut decoder = snap::raw::Decoder::new();
    let lc_update = decoder.decompress_vec(&lc_update).unwrap();
    let lc_update = LightClientUpdate::from_ssz_bytes(&lc_update, ForkName::Deneb).unwrap();

    ForkVersionedLightClientUpdate {
        fork_name: ForkName::Deneb,
        update: lc_update,
    }
}

// Valid number range for the test cases is 0..=1
pub fn get_light_client_finality_update(number: u8) -> ForkVersionedLightClientFinalityUpdate {
    let lc_finality_update = std::fs::read(format!(
        "../test_assets/beacon/deneb/LightClientFinalityUpdate/ssz_random/case_{number}/serialized.ssz_snappy"
    ))
        .expect("cannot find test asset");
    let mut decoder = snap::raw::Decoder::new();
    let lc_finality_update = decoder.decompress_vec(&lc_finality_update).unwrap();
    let lc_finality_update =
        LightClientFinalityUpdate::from_ssz_bytes(&lc_finality_update, ForkName::Deneb).unwrap();

    ForkVersionedLightClientFinalityUpdate {
        fork_name: ForkName::Deneb,
        update: lc_finality_update,
    }
}

// Valid number range for the test cases is 0..=1
pub fn get_light_client_optimistic_update(number: u8) -> ForkVersionedLightClientOptimisticUpdate {
    let lc_optimistic_update = std::fs::read(format!(
        "../test_assets/beacon/deneb/LightClientOptimisticUpdate/ssz_random/case_{number}/serialized.ssz_snappy"
    ))
        .expect("cannot find test asset");
    let mut decoder = snap::raw::Decoder::new();
    let lc_optimistic_update = decoder.decompress_vec(&lc_optimistic_update).unwrap();
    let lc_optimistic_update =
        LightClientOptimisticUpdate::from_ssz_bytes(&lc_optimistic_update, ForkName::Deneb)
            .unwrap();

    ForkVersionedLightClientOptimisticUpdate {
        fork_name: ForkName::Deneb,
        update: lc_optimistic_update,
    }
}

pub fn get_history_summaries_with_proof() -> (ForkVersionedHistoricalSummariesWithProof, B256) {
    let value = std::fs::read(
        "../test_assets/beacon/deneb/BeaconState/ssz_random/case_0/serialized.ssz_snappy",
    )
    .expect("cannot find test asset");
    let mut decoder = snap::raw::Decoder::new();
    let value = decoder.decompress_vec(&value).unwrap();
    let beacon_state = BeaconStateDeneb::from_ssz_bytes(&value).unwrap();

    let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
    let historical_summaries_state_proof =
        HistoricalSummariesStateProof::from(historical_summaries_proof);
    let historical_summaries = beacon_state.historical_summaries.clone();
    let historical_summaries_epoch = beacon_state.slot / 32;
    let historical_summaries_with_proof = HistoricalSummariesWithProof {
        epoch: historical_summaries_epoch,
        historical_summaries,
        proof: historical_summaries_state_proof.clone(),
    };

    (
        ForkVersionedHistoricalSummariesWithProof {
            fork_name: ForkName::Deneb,
            historical_summaries_with_proof,
        },
        beacon_state.tree_hash_root(),
    )
}
