#![cfg(feature = "ef-tests")]

use std::str::FromStr;

use alloy::primitives::B256;
use ethportal_api::consensus::{
    beacon_block::BeaconBlockBellatrix,
    beacon_state::{BeaconStateDeneb, BeaconStateElectra, HistoricalBatch},
    body::BeaconBlockBodyBellatrix,
    execution_payload::ExecutionPayloadBellatrix,
    historical_summaries::HistoricalSummariesWithProof,
};
use ssz::{Decode, Encode};

#[test]
fn beacon_block_body_root_proof() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/bellatrix/ssz_static/BeaconBlock/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let content: BeaconBlockBellatrix = serde_yaml::from_str(&value).unwrap();
    let expected_proof = [
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "0x96462cc1b886748c59c77bd22a905a73ca24ec94d35db74c9142f90775d750ef",
    ]
    .map(|x| B256::from_str(x).unwrap());
    let proof = content.build_body_root_proof();

    assert_eq!(proof.len(), 3);
    assert_eq!(proof, expected_proof.to_vec());
}

#[test]
fn historical_batch_block_root_proof() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/bellatrix/ssz_static/HistoricalBatch/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let content: HistoricalBatch = serde_yaml::from_str(&value).unwrap();
    let expected_proof = [
        "0x94b86be66f0f526b4ec5720c97667aec892f1b8b55cad5d8ce63315ffa3fcb53",
        "0xf3e8be1c4d5a4ad8570d4f20e83d9f0a02a5422d9b82551cb4a3853bca0fe7bd",
        "0x8584b1434bf9575a577ea5384819f46ddc3cc58669b954006cd6a31e3501a40f",
        "0x6e386d98a521d6dc6da3a5f482c0c267caed5db427c5ec4218cc223b758d5990",
        "0xecbc798fe161e63a02a3550d65cdc852569cc705fec50a8041611960435a18d6",
        "0xb19d083ae98e9e4d90ba1b93b84a6fe54b5dcc997356f0d36fd518f1d4fa54c7",
        "0xd77f1c965a2f6eea61972eca41293331be23f170d3a3ff307d3fa13033b2ac3c",
        "0x550a52d8011fb9601acc4a7f68ffaaed681deb33b13e1c9c9817e49b8ee0fbf9",
        "0xbe3d1e65d7e54afa2d6d116a4876685832c41def0f640a8bd7229f4e5833405d",
        "0xd608142a0fe66c0c35e4026fc42749cda244fa5ac689968086d433adef94ac20",
        "0x4ae45ea477ca2648c813ef0a9f9d01c5736b087b83b8854410a8fe9048ceaab2",
        "0xb21eb872be33298f6aefc7bee2d46cd481b7ec934f63b870bafe29de566580db",
        "0x7ff417313bd530a4778679238291d021ec774f72636aac132f3024e79b4c81b6",
        "0x493e1b1ddc841da365bd706bab262797cb9e117c5e5459bc3fae7628d16b7509",
    ]
    .map(|x| B256::from_str(x).unwrap());

    let proof = content.build_block_root_proof(0);

    assert_eq!(proof.len(), 14);
    assert_eq!(proof, expected_proof.to_vec());
}

#[test]
fn beacon_state_historical_summaries_proof_deneb() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/deneb/ssz_static/BeaconState/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let beacon_state: BeaconStateDeneb = serde_yaml::from_str(&value).unwrap();
    let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
    assert_eq!(historical_summaries_proof.len(), 5);
}

#[test]
fn beacon_state_historical_summaries_proof_electra() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/electra/ssz_static/BeaconState/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let beacon_state: BeaconStateElectra = serde_yaml::from_str(&value).unwrap();
    let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
    assert_eq!(historical_summaries_proof.len(), 6);
}

#[test]
fn block_body_execution_payload_proof() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/bellatrix/ssz_static/BeaconBlockBody/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let content: BeaconBlockBodyBellatrix = serde_yaml::from_str(&value).unwrap();
    let expected_execution_payload_proof = [
        "0x2b76d38371c161b639e922b0c42031f99dba98e903dd63ccd21a633143aabbaa",
        "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
        "0xab95e3d062c58f9e1108fc4248ab84a4c87c142ba956ee7e77a6933cf40ea7aa",
    ]
    .map(|x| B256::from_str(x).unwrap());
    let proof = content.build_execution_payload_proof();

    assert_eq!(proof.len(), 4);
    assert_eq!(proof, expected_execution_payload_proof.to_vec());

    let expected_block_hash_proof = [
        "0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1",
        "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "0x661a812e736b705fc21352b256146b2fc7622861a29b4fa774dcd5164543fea3",
        "0xb7a4dae09ab0b87e06da935cc55d6f14a6c85dabc2b5472b44df4c6da99bb078",
    ]
    .map(|x| B256::from_str(x).unwrap())
    .to_vec();
    let proof = content.execution_payload.build_block_hash_proof();

    assert_eq!(proof.len(), 4);
    assert_eq!(proof, expected_block_hash_proof);
}

#[test]
fn execution_payload_block_hash_proof() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/bellatrix/ssz_static/ExecutionPayload/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let content: ExecutionPayloadBellatrix = serde_yaml::from_str(&value).unwrap();
    let expected_block_hash_proof = [
        "0xc566f7b1d6dd0741642653bc97899e35834ee094bda9268aa26dda2098f6907a",
        "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "0xa95095bc1e81cd6802483a2626e04fef9593c4f251dc3aeaa514c5655457719e",
        "0xc93bcadbaef021f4bb488375b95b936e64c88e675ba471d7b417cb2ebf9a3c98",
    ]
    .map(|x| B256::from_str(x).unwrap())
    .to_vec();
    let proof = content.build_block_hash_proof();

    assert_eq!(proof.len(), 4);
    assert_eq!(proof, expected_block_hash_proof);
}

#[test]
fn test_historical_summaries_with_proof() {
    let test_file_str = std::fs::read_to_string(
        "mainnet/tests/mainnet/electra/ssz_static/BeaconState/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");

    let beacon_state: BeaconStateElectra = serde_yaml::from_str(&test_file_str).unwrap();

    let expected_summaries_with_proof = HistoricalSummariesWithProof {
        epoch: beacon_state.slot / 32,
        historical_summaries: beacon_state.historical_summaries.clone(),
        proof: beacon_state.build_historical_summaries_proof(),
    };

    // Test ssz encoding and decoding
    let ssz_bytes = expected_summaries_with_proof.as_ssz_bytes();
    let historical_summaries_with_proof =
        HistoricalSummariesWithProof::from_ssz_bytes(&ssz_bytes).unwrap();
    assert_eq!(
        expected_summaries_with_proof,
        historical_summaries_with_proof
    );
}
