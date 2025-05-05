use ethportal_api::{
    consensus::fork::ForkName,
    light_client::{
        bootstrap::LightClientBootstrap, finality_update::LightClientFinalityUpdate,
        optimistic_update::LightClientOptimisticUpdate, update::LightClientUpdate,
    },
    types::content_value::beacon::{
        ForkVersionedLightClientBootstrap, ForkVersionedLightClientFinalityUpdate,
        ForkVersionedLightClientOptimisticUpdate, ForkVersionedLightClientUpdate,
    },
};

// Valid number range for the test cases is 0..=1
pub fn get_light_client_bootstrap(number: u8) -> ForkVersionedLightClientBootstrap {
    let lc_bootstrap = std::fs::read(format!(
        "../../../test_assets/beacon/deneb/LightClientBootstrap/ssz_random/case_{number}/serialized.ssz_snappy"
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
        "../../../test_assets/beacon/deneb/LightClientUpdate/ssz_random/case_{number}/serialized.ssz_snappy"
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
        "../../../test_assets/beacon/deneb/LightClientFinalityUpdate/ssz_random/case_{number}/serialized.ssz_snappy"
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
        "../../../test_assets/beacon/deneb/LightClientOptimisticUpdate/ssz_random/case_{number}/serialized.ssz_snappy"
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
