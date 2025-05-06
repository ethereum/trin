use std::sync::{Arc, LazyLock};

use alloy_hardforks::{EthereumChainHardforks, EthereumHardfork, EthereumHardforks, ForkCondition};
use anyhow::anyhow;
use bimap::BiHashMap;
use discv5::Enr;
use once_cell::sync::Lazy;
use parking_lot::RwLock;

use super::{
    network::{Network, Subnetwork},
    protocol_versions::{
        ProtocolVersion, ProtocolVersionError, ProtocolVersionList, ENR_PROTOCOL_VERSION_KEY,
    },
};

/// Beacon chain mainnet genesis time: Tue Dec 01 2020 12:00:23 GMT+0000
const MAINNET_BEACON_GENESIS_TIMESTAMP: u64 = 1606824023;

/// Beacon chain sepolia genesis time: Jun-20-2022 02:00:00 PM +UTC
const SEPOLIA_BEACON_GENESIS_TIMESTAMP: u64 = 1655733600;

static NETWORK_SPEC: LazyLock<RwLock<Arc<NetworkSpec>>> =
    LazyLock::new(|| RwLock::new(MAINNET.clone()));

/// Should be called only once at the start of the application to initialize static [NetworkSpec].
///
/// The static `NetworkSpec` can be accessed using [network_spec].
///
/// Tests can also use this, but should be more careful. See [NetworkSpec] for details.
pub fn set_network_spec(network_spec: Arc<NetworkSpec>) {
    *NETWORK_SPEC.write() = network_spec;
}

pub fn network_spec() -> Arc<NetworkSpec> {
    NETWORK_SPEC.read().clone()
}

/// It includes the mapping of subnetworks to protocol id hex strings, supported protocol versions,
/// and hardforks.
///
/// It should be initialized at the start of the application using [set_network_spec] and can be
/// accessed from anywhere using [network_spec]. The tests are exception to this case, as they
/// can set value at the start (if they test something other than mainnet data) and reset the value
/// at the end, while making sure that they are no other tests running in parallel (e.g. using
/// `serial_test` crate).
#[derive(Clone, Debug)]
pub struct NetworkSpec {
    network: Network,
    /// mapping of subnetworks to protocol id hex strings
    portal_subnetworks: BiHashMap<Subnetwork, String>,
    supported_protocol_versions: ProtocolVersionList,
    hardforks: EthereumChainHardforks,
    beacon_genesis_timestamp: u64,
}

impl NetworkSpec {
    pub fn new(
        portal_subnetworks: BiHashMap<Subnetwork, String>,
        network: Network,
        supported_protocol_versions: ProtocolVersionList,
        hardforks: EthereumChainHardforks,
        beacon_genesis_timestamp: u64,
    ) -> anyhow::Result<Self> {
        // Ensure supported protocol versions are ordered chronologically with no duplicates.
        supported_protocol_versions.is_strictly_sorted_and_specified();

        Ok(Self {
            portal_subnetworks,
            network,
            supported_protocol_versions,
            hardforks,
            beacon_genesis_timestamp,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn supported_protocol_versions(&self) -> &ProtocolVersionList {
        &self.supported_protocol_versions
    }

    pub fn get_subnetwork_from_protocol_identifier(&self, hex: &str) -> anyhow::Result<Subnetwork> {
        self.portal_subnetworks
            .get_by_right(hex)
            .copied()
            .ok_or(anyhow!("Invalid subnetwork identifier: {hex}"))
    }

    pub fn get_protocol_identifier_from_subnetwork(
        &self,
        subnetwork: &Subnetwork,
    ) -> anyhow::Result<String> {
        self.portal_subnetworks
            .get_by_left(subnetwork)
            .cloned()
            .ok_or(anyhow!(
                "Cannot find protocol identifier for subnetwork: {subnetwork}"
            ))
    }

    pub fn latest_common_protocol_version(
        &self,
        enr: &Enr,
    ) -> Result<ProtocolVersion, ProtocolVersionError> {
        let Some(other_supported_versions) = enr
            .get_decodable::<ProtocolVersionList>(ENR_PROTOCOL_VERSION_KEY)
            .transpose()
            .map_err(|_| ProtocolVersionError::FailedToDecode)?
        else {
            return Ok(ProtocolVersion::V0);
        };

        // The NetworkSpec's `supported_protocol_versions` are ordered chronologically.
        // Hence, we iterate in reverse order to find the latest common version.
        self.supported_protocol_versions
            .iter()
            .rev()
            .find(|v| other_supported_versions.contains(v))
            .copied()
            .ok_or(ProtocolVersionError::NoMatchingVersion)
    }

    pub fn slot_to_timestamp(&self, slot: u64) -> u64 {
        self.beacon_genesis_timestamp + slot * 12
    }
}

impl EthereumHardforks for NetworkSpec {
    fn ethereum_fork_activation(&self, fork: EthereumHardfork) -> ForkCondition {
        self.hardforks.ethereum_fork_activation(fork)
    }
}

pub static MAINNET: Lazy<Arc<NetworkSpec>> = Lazy::new(|| {
    let mut portal_subnetworks = BiHashMap::new();
    portal_subnetworks.insert(Subnetwork::State, "0x500A".to_string());
    portal_subnetworks.insert(Subnetwork::History, "0x500B".to_string());
    portal_subnetworks.insert(Subnetwork::Beacon, "0x500C".to_string());
    portal_subnetworks.insert(Subnetwork::CanonicalIndices, "0x500D".to_string());
    portal_subnetworks.insert(Subnetwork::VerkleState, "0x500E".to_string());
    portal_subnetworks.insert(Subnetwork::TransactionGossip, "0x500F".to_string());
    portal_subnetworks.insert(Subnetwork::Utp, "0x757470".to_string());

    NetworkSpec::new(
        portal_subnetworks,
        Network::Mainnet,
        ProtocolVersionList::new(vec![ProtocolVersion::V0, ProtocolVersion::V1]),
        EthereumChainHardforks::mainnet(),
        MAINNET_BEACON_GENESIS_TIMESTAMP,
    )
    .expect("Failed to create mainnet network spec")
    .into()
});

pub static ANGELFOOD: Lazy<Arc<NetworkSpec>> = Lazy::new(|| {
    let mut portal_subnetworks = BiHashMap::new();
    portal_subnetworks.insert(Subnetwork::State, "0x504A".to_string());
    portal_subnetworks.insert(Subnetwork::History, "0x504B".to_string());
    portal_subnetworks.insert(Subnetwork::Beacon, "0x504C".to_string());
    portal_subnetworks.insert(Subnetwork::CanonicalIndices, "0x504D".to_string());
    portal_subnetworks.insert(Subnetwork::VerkleState, "0x504E".to_string());
    portal_subnetworks.insert(Subnetwork::TransactionGossip, "0x504F".to_string());
    portal_subnetworks.insert(Subnetwork::Utp, "0x757470".to_string());
    NetworkSpec::new(
        portal_subnetworks,
        Network::Angelfood,
        ProtocolVersionList::new(vec![ProtocolVersion::V0]),
        EthereumChainHardforks::mainnet(),
        MAINNET_BEACON_GENESIS_TIMESTAMP,
    )
    .expect("Failed to create angelfood network spec")
    .into()
});

pub static SEPOLIA: Lazy<Arc<NetworkSpec>> = Lazy::new(|| {
    let mut portal_subnetworks = BiHashMap::new();
    portal_subnetworks.insert(Subnetwork::State, "0x504A".to_string());
    portal_subnetworks.insert(Subnetwork::History, "0x504B".to_string());
    portal_subnetworks.insert(Subnetwork::Beacon, "0x504C".to_string());
    portal_subnetworks.insert(Subnetwork::CanonicalIndices, "0x504D".to_string());
    portal_subnetworks.insert(Subnetwork::VerkleState, "0x504E".to_string());
    portal_subnetworks.insert(Subnetwork::TransactionGossip, "0x504F".to_string());
    portal_subnetworks.insert(Subnetwork::Utp, "0x757470".to_string());
    NetworkSpec::new(
        portal_subnetworks,
        Network::Sepolia,
        ProtocolVersionList::new(vec![ProtocolVersion::V1]),
        EthereumChainHardforks::sepolia(),
        SEPOLIA_BEACON_GENESIS_TIMESTAMP,
    )
    .expect("Failed to create sepolia network spec")
    .into()
});

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;

    #[test_log::test]
    fn subnetwork_invalid() {
        let hex = "0x504F";
        assert!(!MAINNET.portal_subnetworks.contains_right(hex));
    }

    #[test_log::test]
    fn subnetwork_encoding() {
        let hex = "0x500A";
        let protocol_id = MAINNET
            .get_subnetwork_from_protocol_identifier(hex)
            .unwrap();
        let expected_hex = MAINNET
            .get_protocol_identifier_from_subnetwork(&protocol_id)
            .unwrap();
        assert_eq!(hex, expected_hex);
    }
}
