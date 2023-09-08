use crate::config::utils::hex_str_to_bytes;
use eyre::Result;
use serde::de::Error;
use ssz_rs::prelude::*;

use crate::types::Bytes32;

pub type BLSPubKey = Vector<u8, 48>;
pub type SignatureBytes = Vector<u8, 96>;
pub type Address = Vector<u8, 20>;
pub type LogsBloom = Vector<u8, 256>;

#[derive(serde::Deserialize, Debug)]
pub struct Bootstrap {
    #[serde(deserialize_with = "header_deserialize")]
    pub header: Header,
    pub current_sync_committee: SyncCommittee,
    #[serde(deserialize_with = "branch_deserialize")]
    pub current_sync_committee_branch: Vec<Bytes32>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Update {
    #[serde(deserialize_with = "header_deserialize")]
    pub attested_header: Header,
    pub next_sync_committee: SyncCommittee,
    #[serde(deserialize_with = "branch_deserialize")]
    pub next_sync_committee_branch: Vec<Bytes32>,
    #[serde(deserialize_with = "header_deserialize")]
    pub finalized_header: Header,
    #[serde(deserialize_with = "branch_deserialize")]
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate,
    #[serde(deserialize_with = "u64_deserialize")]
    pub signature_slot: u64,
}

#[derive(serde::Deserialize, Debug)]
pub struct FinalityUpdate {
    #[serde(deserialize_with = "header_deserialize")]
    pub attested_header: Header,
    #[serde(deserialize_with = "header_deserialize")]
    pub finalized_header: Header,
    #[serde(deserialize_with = "branch_deserialize")]
    pub finality_branch: Vec<Bytes32>,
    pub sync_aggregate: SyncAggregate,
    #[serde(deserialize_with = "u64_deserialize")]
    pub signature_slot: u64,
}

#[derive(serde::Deserialize, Debug)]
pub struct OptimisticUpdate {
    #[serde(deserialize_with = "header_deserialize")]
    pub attested_header: Header,
    pub sync_aggregate: SyncAggregate,
    #[serde(deserialize_with = "u64_deserialize")]
    pub signature_slot: u64,
}

#[derive(serde::Deserialize, Debug, Clone, Default, SimpleSerialize)]
pub struct Header {
    #[serde(deserialize_with = "u64_deserialize")]
    pub slot: u64,
    #[serde(deserialize_with = "u64_deserialize")]
    pub proposer_index: u64,
    #[serde(deserialize_with = "bytes32_deserialize")]
    pub parent_root: Bytes32,
    #[serde(deserialize_with = "bytes32_deserialize")]
    pub state_root: Bytes32,
    #[serde(deserialize_with = "bytes32_deserialize")]
    pub body_root: Bytes32,
}

#[derive(Debug, Clone, Default, SimpleSerialize, serde::Deserialize)]
pub struct SyncCommittee {
    #[serde(deserialize_with = "pubkeys_deserialize")]
    pub pubkeys: Vector<BLSPubKey, 512>,
    #[serde(deserialize_with = "pubkey_deserialize")]
    pub aggregate_pubkey: BLSPubKey,
}

#[derive(serde::Deserialize, Debug, Clone, Default, SimpleSerialize)]
pub struct SyncAggregate {
    pub sync_committee_bits: Bitvector<512>,
    #[serde(deserialize_with = "signature_deserialize")]
    pub sync_committee_signature: SignatureBytes,
}

pub struct GenericUpdate {
    pub attested_header: Header,
    pub sync_aggregate: SyncAggregate,
    pub signature_slot: u64,
    pub next_sync_committee: Option<SyncCommittee>,
    pub next_sync_committee_branch: Option<Vec<Bytes32>>,
    pub finalized_header: Option<Header>,
    pub finality_branch: Option<Vec<Bytes32>>,
}

impl From<&Update> for GenericUpdate {
    fn from(update: &Update) -> Self {
        Self {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: Some(update.next_sync_committee.clone()),
            next_sync_committee_branch: Some(update.next_sync_committee_branch.clone()),
            finalized_header: Some(update.finalized_header.clone()),
            finality_branch: Some(update.finality_branch.clone()),
        }
    }
}

impl From<&FinalityUpdate> for GenericUpdate {
    fn from(update: &FinalityUpdate) -> Self {
        Self {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: Some(update.finalized_header.clone()),
            finality_branch: Some(update.finality_branch.clone()),
        }
    }
}

impl From<&OptimisticUpdate> for GenericUpdate {
    fn from(update: &OptimisticUpdate) -> Self {
        Self {
            attested_header: update.attested_header.clone(),
            sync_aggregate: update.sync_aggregate.clone(),
            signature_slot: update.signature_slot,
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: None,
            finality_branch: None,
        }
    }
}

fn pubkey_deserialize<'de, D>(deserializer: D) -> Result<BLSPubKey, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let key: String = serde::Deserialize::deserialize(deserializer)?;
    let key_bytes = hex_str_to_bytes(&key).map_err(D::Error::custom)?;
    Ok(Vector::from_iter(key_bytes))
}

fn pubkeys_deserialize<'de, D>(deserializer: D) -> Result<Vector<BLSPubKey, 512>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let keys: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    keys.iter()
        .map(|key| {
            let key_bytes = hex_str_to_bytes(key)?;
            Ok(Vector::from_iter(key_bytes))
        })
        .collect::<Result<Vector<BLSPubKey, 512>>>()
        .map_err(D::Error::custom)
}

fn signature_deserialize<'de, D>(deserializer: D) -> Result<SignatureBytes, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let sig: String = serde::Deserialize::deserialize(deserializer)?;
    let sig_bytes = hex_str_to_bytes(&sig).map_err(D::Error::custom)?;
    Ok(Vector::from_iter(sig_bytes))
}

fn branch_deserialize<'de, D>(deserializer: D) -> Result<Vec<Bytes32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let branch: Vec<String> = serde::Deserialize::deserialize(deserializer)?;
    branch
        .iter()
        .map(|elem| {
            let elem_bytes = hex_str_to_bytes(elem)?;
            Ok(Vector::from_iter(elem_bytes))
        })
        .collect::<Result<_>>()
        .map_err(D::Error::custom)
}

pub fn u64_deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val: String = serde::Deserialize::deserialize(deserializer)?;
    Ok(val.parse().unwrap())
}

fn bytes32_deserialize<'de, D>(deserializer: D) -> Result<Bytes32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let bytes: String = serde::Deserialize::deserialize(deserializer)?;
    let bytes = hex::decode(bytes.strip_prefix("0x").unwrap()).unwrap();
    Ok(bytes.to_vec().try_into().unwrap())
}

fn header_deserialize<'de, D>(deserializer: D) -> Result<Header, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let header: LightClientHeader = serde::Deserialize::deserialize(deserializer)?;

    Ok(match header {
        LightClientHeader::Unwrapped(header) => header,
        LightClientHeader::Wrapped(header) => header.beacon,
    })
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum LightClientHeader {
    Unwrapped(Header),
    Wrapped(Beacon),
}

#[derive(serde::Deserialize)]
struct Beacon {
    beacon: Header,
}
