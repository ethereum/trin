use std::{
    cmp,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use alloy::primitives::B256;
use anyhow::{anyhow, ensure, Result};
use chrono::Duration;
use ethportal_api::{
    consensus::{header::BeaconBlockHeader, signature::BlsSignature},
    light_client::{
        bootstrap::CurrentSyncCommitteeProofLenElectra,
        finality_update::{LightClientFinalityUpdate, LightClientFinalityUpdateElectra},
        optimistic_update::{LightClientOptimisticUpdate, LightClientOptimisticUpdateElectra},
        store::LightClientStore,
        update::{FinalizedRootProofLenElectra, LightClientUpdateElectra},
    },
    utils::bytes::hex_encode,
};
use milagro_bls::PublicKey;
use ssz_types::{typenum, BitVector, FixedVector};
use tracing::{debug, info, warn};
use tree_hash::TreeHash;

use super::{errors::ConsensusError, rpc::ConsensusRpc, types::*, utils::*};
use crate::{
    config::client_config::Config,
    consensus::{
        constants::MAX_REQUEST_LIGHT_CLIENT_UPDATES, rpc::portal_rpc::expected_current_slot,
    },
};

// https://github.com/ethereum/consensus-specs/blob/dev/specs/altair/light-client/sync-protocol.md
// does not implement force updates

#[derive(Debug)]
pub struct ConsensusLightClient<R: ConsensusRpc> {
    rpc: R,
    store: LightClientStore,
    initial_checkpoint: Vec<u8>,
    pub last_checkpoint: Option<Vec<u8>>,
    pub config: Arc<Config>,
}

impl<R: ConsensusRpc> ConsensusLightClient<R> {
    pub fn new(
        rpc: &str,
        checkpoint_block_root: &[u8],
        config: Arc<Config>,
    ) -> Result<ConsensusLightClient<R>> {
        let rpc = R::new(rpc);

        Ok(ConsensusLightClient {
            rpc,
            store: LightClientStore::default(),
            last_checkpoint: None,
            config,
            initial_checkpoint: checkpoint_block_root.to_vec(),
        })
    }

    pub fn with_custom_rpc(rpc: R, checkpoint_block_root: &[u8], config: Arc<Config>) -> Self {
        ConsensusLightClient {
            rpc,
            store: LightClientStore::default(),
            last_checkpoint: None,
            config,
            initial_checkpoint: checkpoint_block_root.to_vec(),
        }
    }

    pub async fn check_rpc(&self) -> Result<()> {
        let chain_id = self.rpc.chain_id().await?;

        if chain_id != self.config.chain.chain_id {
            Err(ConsensusError::IncorrectRpcNetwork.into())
        } else {
            Ok(())
        }
    }

    pub fn get_header(&self) -> &BeaconBlockHeader {
        &self.store.optimistic_header
    }

    pub fn get_finalized_header(&self) -> &BeaconBlockHeader {
        &self.store.finalized_header
    }

    pub async fn get_finality_update(&self) -> Result<LightClientFinalityUpdate> {
        self.rpc
            .get_finality_update()
            .await
            .map(|update| update.into())
    }

    pub async fn get_optimistic_update(&self) -> Result<LightClientOptimisticUpdate> {
        self.rpc
            .get_optimistic_update()
            .await
            .map(|update| update.into())
    }

    pub fn get_light_client_store(&self) -> &LightClientStore {
        &self.store
    }

    pub async fn sync(&mut self) -> Result<()> {
        self.bootstrap().await?;

        let bootstrap_period = calc_sync_period(self.store.finalized_header.slot);

        let mut updates = Vec::new();

        // If we are using the portal network, we need to request updates for all periods one by one
        if &self.rpc.name() == "portal" {
            // Get expected current period
            let current_period = calc_sync_period(expected_current_slot());

            // Create a range of periods to request updates for
            let periods = bootstrap_period..current_period;

            for period in periods {
                let mut period_update = self.rpc.get_updates(period, 1).await?;
                updates.append(&mut period_update);
            }
        } else {
            let mut result = self
                .rpc
                .get_updates(bootstrap_period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
                .await?;

            updates.append(&mut result);
        }

        for update in updates {
            self.verify_update(&update)?;
            self.apply_update(&update);
        }

        match self.rpc.get_finality_update().await {
            Ok(finality_update) => {
                self.verify_finality_update(&finality_update)?;
                self.apply_finality_update(&finality_update);
            }
            Err(err) => {
                debug!("Could not fetch finality update: {err}")
            }
        }

        let optimistic_update = self.rpc.get_optimistic_update().await?;
        self.verify_optimistic_update(&optimistic_update)?;
        self.apply_optimistic_update(&optimistic_update);

        info!(
            "Light client in sync with checkpoint: {}",
            hex_encode(&self.initial_checkpoint)
        );

        Ok(())
    }

    pub async fn advance(&mut self) -> Result<()> {
        match self.rpc.get_finality_update().await {
            Ok(finality_update) => {
                debug!(
                    "Processing finality update with finalized slot {}",
                    finality_update.finalized_header.beacon.slot
                );
                self.verify_finality_update(&finality_update)?;
                self.apply_finality_update(&finality_update);
            }
            Err(err) => {
                warn!("Could not fetch finality update: {err}")
            }
        }

        let optimistic_update = self.rpc.get_optimistic_update().await?;
        self.verify_optimistic_update(&optimistic_update)?;
        self.apply_optimistic_update(&optimistic_update);

        if self.store.next_sync_committee.is_none() {
            debug!("checking for sync committee update");
            let current_period = calc_sync_period(self.store.finalized_header.slot);
            let mut updates = self.rpc.get_updates(current_period, 1).await?;

            if updates.len() == 1 {
                let update = updates.get_mut(0).expect("vec must have one element");
                let res = self.verify_update(update);

                if res.is_ok() {
                    info!("updating sync committee");
                    self.apply_update(update);
                }
            }
        }

        Ok(())
    }

    async fn bootstrap(&mut self) -> Result<()> {
        let bootstrap = self
            .rpc
            .get_bootstrap(&self.initial_checkpoint)
            .await
            .map_err(|err| anyhow!("could not fetch bootstrap: {err}"))?;

        let is_valid = self.is_valid_checkpoint(bootstrap.header.beacon.slot);

        if !is_valid {
            if self.config.strict_checkpoint_age {
                return Err(ConsensusError::CheckpointTooOld.into());
            } else {
                warn!("checkpoint too old, consider using a more recent block");
            }
        }

        let committee_valid = is_current_committee_proof_valid(
            &bootstrap.header.beacon,
            &bootstrap.current_sync_committee,
            &bootstrap.current_sync_committee_branch,
        );

        let header_hash = hex_encode(bootstrap.header.beacon.tree_hash_root());
        let expected_hash = hex_encode(&self.initial_checkpoint);
        let header_valid = header_hash == expected_hash;

        if !header_valid {
            return Err(ConsensusError::InvalidHeaderHash(expected_hash, header_hash).into());
        }

        if !committee_valid {
            return Err(ConsensusError::InvalidCurrentSyncCommitteeProof.into());
        }

        self.store = LightClientStore {
            finalized_header: bootstrap.header.beacon.clone(),
            current_sync_committee: bootstrap.current_sync_committee,
            next_sync_committee: None,
            optimistic_header: bootstrap.header.beacon,
            previous_max_active_participants: 0,
            current_max_active_participants: 0,
        };

        Ok(())
    }

    fn verify_update(&self, update: &LightClientUpdateElectra) -> Result<()> {
        let update = GenericUpdate::from(update);
        let expected_current_slot = expected_current_slot();
        let genesis_root = &self.config.chain.genesis_root;
        verify_generic_update(
            &self.store,
            &update,
            expected_current_slot,
            genesis_root,
            &self.config.fork_version(update.signature_slot),
        )
    }

    fn verify_finality_update(&self, update: &LightClientFinalityUpdateElectra) -> Result<()> {
        let update = GenericUpdate::from(update);
        let expected_current_slot = expected_current_slot();
        let genesis_root = &self.config.chain.genesis_root;
        verify_generic_update(
            &self.store,
            &update,
            expected_current_slot,
            genesis_root,
            &self.config.fork_version(update.signature_slot),
        )
    }

    fn verify_optimistic_update(&self, update: &LightClientOptimisticUpdateElectra) -> Result<()> {
        let update = GenericUpdate::from(update);
        let expected_current_slot = expected_current_slot();
        let genesis_root = &self.config.chain.genesis_root;
        verify_generic_update(
            &self.store,
            &update,
            expected_current_slot,
            genesis_root,
            &self.config.fork_version(update.signature_slot),
        )
    }

    // implements state changes from apply_light_client_update and process_light_client_update in
    // the specification
    fn apply_generic_update(&mut self, update: &GenericUpdate) {
        let committee_bits = get_bits(&update.sync_aggregate.sync_committee_bits);

        self.store.current_max_active_participants =
            u64::max(self.store.current_max_active_participants, committee_bits);

        let should_update_optimistic = committee_bits > self.safety_threshold()
            && update.attested_header.slot > self.store.optimistic_header.slot;

        if should_update_optimistic {
            self.store.optimistic_header = update.attested_header.clone();
            self.log_optimistic_update(update);
        }

        let update_attested_period = calc_sync_period(update.attested_header.slot);

        let update_finalized_slot = update
            .finalized_header
            .as_ref()
            .map(|h| h.slot)
            .unwrap_or(0);

        let update_finalized_period = calc_sync_period(update_finalized_slot);

        let update_has_finalized_next_committee = self.store.next_sync_committee.is_none()
            && self.has_sync_update(update)
            && self.has_finality_update(update)
            && update_finalized_period == update_attested_period;

        let should_apply_update = {
            let has_majority = committee_bits * 3 >= 512 * 2;
            if !has_majority {
                debug!(update = ?update, "Skipping update with low vote count");
            }
            let update_is_newer = update_finalized_slot > self.store.finalized_header.slot;
            let good_update = update_is_newer || update_has_finalized_next_committee;

            has_majority && good_update
        };

        if should_apply_update {
            let store_period = calc_sync_period(self.store.finalized_header.slot);

            if self.store.next_sync_committee.is_none() {
                self.store
                    .next_sync_committee
                    .clone_from(&update.next_sync_committee);
            } else if update_finalized_period == store_period + 1 {
                info!("sync committee updated");
                self.store.current_sync_committee = self
                    .store
                    .next_sync_committee
                    .clone()
                    .expect("we know that this is `Some`");
                self.store
                    .next_sync_committee
                    .clone_from(&update.next_sync_committee);
                self.store.previous_max_active_participants =
                    self.store.current_max_active_participants;
                self.store.current_max_active_participants = 0;
            }

            if update_finalized_slot > self.store.finalized_header.slot {
                self.store.finalized_header = update
                    .finalized_header
                    .as_ref()
                    .expect("`update_finalized_slot` > 0, so it's expected to exist")
                    .clone();
                self.log_finality_update(update);

                if self.store.finalized_header.slot % 32 == 0 {
                    let checkpoint = self.store.finalized_header.tree_hash_root();
                    self.last_checkpoint = Some(checkpoint.as_slice().to_vec());
                }

                if self.store.finalized_header.slot > self.store.optimistic_header.slot {
                    self.store.optimistic_header = self.store.finalized_header.clone();
                }
            }
        }
    }

    fn apply_update(&mut self, update: &LightClientUpdateElectra) {
        let update = GenericUpdate::from(update);
        self.apply_generic_update(&update);
    }

    fn apply_finality_update(&mut self, update: &LightClientFinalityUpdateElectra) {
        let update = GenericUpdate::from(update);
        self.apply_generic_update(&update);
    }

    fn log_finality_update(&self, update: &GenericUpdate) {
        let participation =
            get_bits(&update.sync_aggregate.sync_committee_bits) as f32 / 512_f32 * 100f32;
        let decimals = if participation == 100.0 { 1 } else { 2 };
        let age = self.age(self.store.finalized_header.slot);

        info!(
            "finalized slot             slot={}  confidence={:.decimals$}%  age={:02}:{:02}:{:02}:{:02}",
            self.store.finalized_header.slot,
            participation,
            age.num_days(),
            age.num_hours() % 24,
            age.num_minutes() % 60,
            age.num_seconds() % 60,
        );
    }

    fn apply_optimistic_update(&mut self, update: &LightClientOptimisticUpdateElectra) {
        let update = GenericUpdate::from(update);
        self.apply_generic_update(&update);
    }

    fn log_optimistic_update(&self, update: &GenericUpdate) {
        let participation =
            get_bits(&update.sync_aggregate.sync_committee_bits) as f32 / 512_f32 * 100f32;
        let decimals = if participation == 100.0 { 1 } else { 2 };
        let age = self.age(self.store.optimistic_header.slot);

        info!(
            "updated head               slot={}  confidence={:.decimals$}%  age={:02}:{:02}:{:02}:{:02}",
            self.store.optimistic_header.slot,
            participation,
            age.num_days(),
            age.num_hours() % 24,
            age.num_minutes() % 60,
            age.num_seconds() % 60,
        );
    }

    fn has_finality_update(&self, update: &GenericUpdate) -> bool {
        update.finalized_header.is_some() && update.finality_branch.is_some()
    }

    fn has_sync_update(&self, update: &GenericUpdate) -> bool {
        update.next_sync_committee.is_some() && update.next_sync_committee_branch.is_some()
    }

    fn safety_threshold(&self) -> u64 {
        cmp::max(
            self.store.current_max_active_participants,
            self.store.previous_max_active_participants,
        ) / 2
    }

    fn age(&self, slot: u64) -> Duration {
        let expected_time = self.slot_timestamp(slot);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("`now` is ahead of `UNIX_EPOCH`");
        let delay = now - std::time::Duration::from_secs(expected_time);
        chrono::Duration::from_std(delay)
            .expect("it's safe to assume that `delay` fits into a `chrono::Duration`")
    }

    pub fn expected_current_slot(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("`now` is ahead of `UNIX_EPOCH`");
        let genesis_time = self.config.chain.genesis_time;
        let since_genesis = now - std::time::Duration::from_secs(genesis_time);

        since_genesis.as_secs() / 12
    }

    /// Gets the duration until the next update
    /// Updates are scheduled for 4 seconds into each slot
    pub fn duration_until_next_update(&self) -> Duration {
        let current_slot = self.expected_current_slot();
        let next_slot = current_slot + 1;
        let next_slot_timestamp = self.slot_timestamp(next_slot);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("`now` is ahead of `UNIX_EPOCH`")
            .as_secs();

        let time_to_next_slot = next_slot_timestamp - now;
        let next_update = time_to_next_slot + 8;

        Duration::seconds(next_update as i64)
    }

    // Determines blockhash_slot age and returns true if it is less than 14 days old
    fn is_valid_checkpoint(&self, blockhash_slot: u64) -> bool {
        let current_slot = self.expected_current_slot();
        let current_slot_timestamp = self.slot_timestamp(current_slot);
        let blockhash_slot_timestamp = self.slot_timestamp(blockhash_slot);

        let slot_age = current_slot_timestamp - blockhash_slot_timestamp;

        slot_age < self.config.max_checkpoint_age
    }

    fn slot_timestamp(&self, slot: u64) -> u64 {
        slot * 12 + self.config.chain.genesis_time
    }
}

// implements checks from validate_light_client_update and process_light_client_update in the
// specification
pub fn verify_generic_update(
    store: &LightClientStore,
    update: &GenericUpdate,
    expected_slot: u64,
    genesis_root: &[u8],
    fork_version: &[u8],
) -> Result<()> {
    let bits = get_bits(&update.sync_aggregate.sync_committee_bits);
    ensure!(bits > 0, ConsensusError::InsufficientParticipation);

    let update_finalized_slot = update.finalized_header.clone().unwrap_or_default().slot;
    let valid_time = expected_slot >= update.signature_slot
        && update.signature_slot > update.attested_header.slot
        && update.attested_header.slot >= update_finalized_slot;
    ensure!(valid_time, ConsensusError::InvalidTimestamp);

    let store_period = calc_sync_period(store.finalized_header.slot);
    let update_sig_period = calc_sync_period(update.signature_slot);
    let valid_period = if store.next_sync_committee.is_some() {
        update_sig_period == store_period || update_sig_period == store_period + 1
    } else {
        update_sig_period == store_period
    };
    ensure!(valid_period, ConsensusError::InvalidPeriod);

    let update_attested_period = calc_sync_period(update.attested_header.slot);
    let update_has_next_committee = store.next_sync_committee.is_none()
        && update.next_sync_committee.is_some()
        && update_attested_period == store_period;
    ensure!(
        update.attested_header.slot > store.finalized_header.slot || update_has_next_committee,
        ConsensusError::NotRelevant
    );

    if update.finalized_header.is_some() && update.finality_branch.is_some() {
        let is_valid = is_finality_proof_valid(
            &update.attested_header,
            update
                .finalized_header
                .as_ref()
                .expect("finalized_header should be `Some`"),
            update
                .finality_branch
                .as_ref()
                .expect("finality_branch should be `Some`"),
        );
        ensure!(is_valid, ConsensusError::InvalidFinalityProof);
    }

    if update.next_sync_committee.is_some() && update.next_sync_committee_branch.is_some() {
        let is_valid = is_next_committee_proof_valid(
            &update.attested_header,
            update
                .next_sync_committee
                .as_ref()
                .expect("next_sync_committee should be `Some`"),
            update
                .next_sync_committee_branch
                .as_ref()
                .expect("next_sync_committee_branch ahould be`Some`"),
        );
        ensure!(is_valid, ConsensusError::InvalidNextSyncCommitteeProof);
    }

    let sync_committee = if update_sig_period == store_period {
        &store.current_sync_committee
    } else {
        store
            .next_sync_committee
            .as_ref()
            .expect("we know that this is `Some` because we are in `valid_period`")
    };

    let public_keys =
        get_participating_keys(sync_committee, &update.sync_aggregate.sync_committee_bits)?;
    let is_valid_signature = verify_sync_committee_signature(
        &public_keys,
        &update.attested_header,
        &update.sync_aggregate.sync_committee_signature,
        genesis_root,
        fork_version,
    );
    ensure!(is_valid_signature, ConsensusError::InvalidSignature);

    Ok(())
}

fn compute_committee_sign_root(
    genesis_root: &[u8],
    header: B256,
    fork_version: &[u8],
) -> Result<B256> {
    let genesis_root = B256::from_slice(genesis_root);
    let domain_type = &hex::decode("07000000")?[..];
    let fork_version = FixedVector::from(fork_version.to_vec());
    let domain = compute_domain(domain_type, fork_version, genesis_root)?;
    Ok(compute_signing_root(header, domain))
}

fn get_participating_keys(
    committee: &SyncCommittee,
    bitfield: &BitVector<typenum::U512>,
) -> Result<Vec<PublicKey>> {
    let mut public_keys: Vec<PublicKey> = Vec::new();
    bitfield.iter().enumerate().for_each(|(i, bit)| {
        if bit {
            let pk = &committee.pubkeys[i];
            let pk = PublicKey::from_bytes_unchecked(pk.as_ref()).expect("invalid pubkey bytes");
            public_keys.push(pk);
        }
    });

    Ok(public_keys)
}

fn get_bits(bitfield: &BitVector<typenum::U512>) -> u64 {
    let mut count = 0;
    bitfield.iter().for_each(|bit| {
        if bit {
            count += 1;
        }
    });

    count
}

fn verify_sync_committee_signature(
    pks: &[PublicKey],
    attested_header: &BeaconBlockHeader,
    signature: &BlsSignature,
    genesis_root: &[u8],
    fork_version: &[u8],
) -> bool {
    let res: Result<bool> = (move || {
        let public_keys: Vec<&PublicKey> = pks.iter().collect();
        let header_root = attested_header.tree_hash_root();
        let signing_root = compute_committee_sign_root(genesis_root, header_root, fork_version)?;

        Ok(is_aggregate_valid(
            signature,
            signing_root.as_slice(),
            &public_keys,
        ))
    })();

    res.unwrap_or_default()
}

fn is_finality_proof_valid(
    attested_header: &BeaconBlockHeader,
    finality_header: &BeaconBlockHeader,
    finality_branch: &FixedVector<B256, FinalizedRootProofLenElectra>,
) -> bool {
    is_proof_valid(attested_header, finality_header, finality_branch, 7, 41)
}

fn is_next_committee_proof_valid(
    attested_header: &BeaconBlockHeader,
    next_committee: &SyncCommittee,
    next_committee_branch: &FixedVector<B256, CurrentSyncCommitteeProofLenElectra>,
) -> bool {
    is_proof_valid(
        attested_header,
        next_committee,
        next_committee_branch,
        6,
        23,
    )
}

fn is_current_committee_proof_valid(
    attested_header: &BeaconBlockHeader,
    current_committee: &SyncCommittee,
    current_committee_branch: &FixedVector<B256, CurrentSyncCommitteeProofLenElectra>,
) -> bool {
    is_proof_valid(
        attested_header,
        current_committee,
        current_committee_branch,
        6,
        22,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ethportal_api::consensus::{
        header::BeaconBlockHeader, pubkey::PubKey, signature::BlsSignature,
    };

    use crate::{
        config::{client_config::Config, networks},
        consensus::{
            consensus_client::ConsensusLightClient,
            constants::MAX_REQUEST_LIGHT_CLIENT_UPDATES,
            errors::ConsensusError,
            rpc::{mock_rpc::MockRpc, ConsensusRpc},
            utils::calc_sync_period,
        },
    };

    async fn get_client(strict_checkpoint_age: bool) -> ConsensusLightClient<MockRpc> {
        let base_config = networks::mainnet();
        let config = Config {
            consensus_rpc: String::new(),
            chain: base_config.chain,
            forks: base_config.forks,
            strict_checkpoint_age,
            ..Default::default()
        };

        let checkpoint =
            hex::decode("787b52add77e871f1cdffbc7f36e84a923f95f8a75c61dc410af24030d74d45c")
                .unwrap();

        let mut client =
            ConsensusLightClient::new("testdata/", &checkpoint, Arc::new(config)).unwrap();
        client.bootstrap().await.unwrap();
        client
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_update() {
        let client = get_client(false).await;
        let period = calc_sync_period(client.store.finalized_header.slot);
        let updates = client
            .rpc
            .get_updates(period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
            .await
            .unwrap();

        let update = updates[0].clone();
        client.verify_update(&update).unwrap();
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_update_invalid_committee() {
        let client = get_client(false).await;
        let period = calc_sync_period(client.store.finalized_header.slot);
        let mut updates = client
            .rpc
            .get_updates(period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
            .await
            .unwrap();

        updates[0].next_sync_committee.pubkeys[0] = PubKey::default();

        let err = client.verify_update(&updates[0]).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidNextSyncCommitteeProof.to_string()
        );
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_update_invalid_finality() {
        let client = get_client(false).await;
        let period = calc_sync_period(client.store.finalized_header.slot);
        let updates = client
            .rpc
            .get_updates(period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
            .await
            .unwrap();

        let mut update = updates[0].clone();
        update.finalized_header.beacon = BeaconBlockHeader::default();

        let err = client.verify_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidFinalityProof.to_string()
        );
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_update_invalid_sig() {
        let client = get_client(false).await;
        let period = calc_sync_period(client.store.finalized_header.slot);
        let mut updates = client
            .rpc
            .get_updates(period, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
            .await
            .unwrap();

        updates[0].sync_aggregate.sync_committee_signature = BlsSignature::default();

        let err = client.verify_update(&updates[0]).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_finality() {
        let mut client = get_client(false).await;
        client.sync().await.unwrap();

        let update = client.rpc.get_finality_update().await.unwrap();

        client.verify_finality_update(&update).unwrap();
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_finality_invalid_finality() {
        let mut client = get_client(false).await;
        client.sync().await.unwrap();

        let mut update = client.rpc.get_finality_update().await.unwrap();

        update.finalized_header.beacon = BeaconBlockHeader::default();

        let err = client.verify_finality_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidFinalityProof.to_string()
        );
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_finality_invalid_sig() {
        let mut client = get_client(false).await;
        client.sync().await.unwrap();

        let mut update = client.rpc.get_finality_update().await.unwrap();
        update.sync_aggregate.sync_committee_signature = BlsSignature::default();

        let err = client.verify_finality_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_optimistic() {
        let mut client = get_client(false).await;
        client.sync().await.unwrap();

        let update = client.rpc.get_optimistic_update().await.unwrap();
        client.verify_optimistic_update(&update).unwrap();
    }

    #[tokio::test]
    #[ignore = "Missing Pectra test vectors"]
    async fn test_verify_optimistic_invalid_sig() {
        let mut client = get_client(false).await;
        client.sync().await.unwrap();

        let mut update = client.rpc.get_optimistic_update().await.unwrap();
        update.sync_aggregate.sync_committee_signature = BlsSignature::default();

        let err = client.verify_optimistic_update(&update).err().unwrap();
        assert_eq!(
            err.to_string(),
            ConsensusError::InvalidSignature.to_string()
        );
    }

    #[tokio::test]
    #[should_panic]
    async fn test_verify_checkpoint_age_invalid() {
        get_client(true).await;
    }
}
