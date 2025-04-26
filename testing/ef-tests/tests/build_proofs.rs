#![cfg(feature = "ef-tests")]

use std::str::FromStr;

use alloy::primitives::B256;
use ethportal_api::consensus::{
    beacon_block::BeaconBlockBellatrix,
    beacon_state::{BeaconStateDeneb, HistoricalBatch},
    body::BeaconBlockBodyBellatrix,
    execution_payload::ExecutionPayloadBellatrix,
    historical_summaries::{HistoricalSummariesStateProof, HistoricalSummariesWithProof},
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
        "0x32b5f53d4b2729823f200eeb36bcf8a78fc1da2d60fef6df87a64a351fce46e7",
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
        "0xad500369fa624b7bb451bf1c5119bb6e5e623bab76a0d06948d04a38f35a740d",
        "0x222151dcdfbace03dd6f2428ee1a12acffaa1ce03e6966aefd4a48282a776e8e",
        "0x28319c59ca450d2fba4b3225eccd994eee98276b7c77e2c3256a3df829767112",
        "0x4cd3f3ff2891ef30542d4ae1530c90120cf7718ae936204aa5b0d67ea07957ef",
        "0xab543cef2058a48bd9d327dce1ee91ac9acf114f7c0b1762689c79b7d10bb363",
        "0x410b45ebb9351cd84dd13a888de4b04d781630df726cec7eb74814f2a00f3c6e",
        "0xd213561e8cff461aa94ee50910381ff1182e3fb90a914e17060f3c0c23522911",
        "0x84b4db81fe167dd181bcab2ca02008b22f0ab11462f8bd4547e29a6b55bb6a11",
        "0x845c6bf5051749dc6b82222c664033ae301fca96c24fd32a63fc3f5adfb1a656",
        "0x19a5290c03daf8156f6941cca8feb5b16e843220e2f9b57647a90d76a459d302",
        "0x9ca2a640c85ce719174ec29710596f3315aedb4b47044f175b2c39f35bf0d15e",
        "0xb7534aed4d180eec8ac7d961e1020028c07d0c83dcdd23f56a7920a08b7393be",
        "0xf8a36457194917609bd16697972d616d8f14e71f4fcfd64666e11544bd5f193e",
        "0x1d28097093ca99336cb6b3e8c8c34d749a3e43efc9bb6fabc2cfd6ffb1701b08",
    ]
    .map(|x| B256::from_str(x).unwrap());

    let proof = content.build_block_root_proof(0);

    assert_eq!(proof.len(), 14);
    assert_eq!(proof, expected_proof.to_vec());
}

#[test]
fn beacon_state_historical_summaries_proof() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/deneb/ssz_static/BeaconState/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let beacon_state: BeaconStateDeneb = serde_yaml::from_str(&value).unwrap();
    let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
    assert_eq!(historical_summaries_proof.len(), 5);
}

#[test]
fn block_body_execution_payload_proof() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/bellatrix/ssz_static/BeaconBlockBody/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let content: BeaconBlockBodyBellatrix = serde_yaml::from_str(&value).unwrap();
    let expected_execution_payload_proof = [
        "0xf5bf9e85dce9cc5f1edbed4085bf4e37da4ddec337483f847cc451f296ff0799",
        "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "0xdb56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71",
        "0x38373fc5d635131b9054c0a97cf1eeb397621f2f6e54ffc54f5f2516088b87d9",
    ]
    .map(|x| B256::from_str(x).unwrap());
    let proof = content.build_execution_payload_proof();

    assert_eq!(proof.len(), 4);
    assert_eq!(proof, expected_execution_payload_proof.to_vec());

    let expected_block_hash_proof = [
        "0x7ffe241ea60187fdb0187bfa22de35d1f9bed7ab061d9401fd47e34a54fbede1",
        "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "0xf00e3441849a7e4228e6f48d5a5b231e153b39cb2ef283febdd9f7df1f777551",
        "0x6911c0b766b06671612d77e8f3061320f2a3471c2ba8d3f8251b53da8efb111a",
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
        "0xc1c51dd941baaa59ef26f7141dc6f1b88e6c30e39c819189fcb515e8bcb41733",
        "0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
        "0x49e643aa5e1626558ec27d657101d5b7b2a0216755659e301e7d3e523bf48b49",
        "0xc81a9c5f1916aba6b34dd4e347fe9adf075debdecebd1eb65db3c1dad6757cd2",
    ]
    .map(|x| B256::from_str(x).unwrap())
    .to_vec();
    let proof = content.build_block_hash_proof();

    assert_eq!(proof.len(), 4);
    assert_eq!(proof, expected_block_hash_proof);
}

#[test]
fn test_historical_summaries_with_proof_deneb() {
    let value = std::fs::read_to_string(
        "mainnet/tests/mainnet/deneb/ssz_static/BeaconState/ssz_random/case_0/value.yaml",
    )
    .expect("cannot find test asset");
    let beacon_state: BeaconStateDeneb = serde_yaml::from_str(&value).unwrap();
    let historical_summaries_proof = beacon_state.build_historical_summaries_proof();
    let historical_summaries_state_proof =
        HistoricalSummariesStateProof::from(historical_summaries_proof);
    let historical_summaries = beacon_state.historical_summaries.clone();

    let historical_summaries_epoch = beacon_state.slot / 32;

    let expected_summaries_with_proof = HistoricalSummariesWithProof {
        epoch: historical_summaries_epoch,
        historical_summaries,
        proof: historical_summaries_state_proof.clone(),
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
