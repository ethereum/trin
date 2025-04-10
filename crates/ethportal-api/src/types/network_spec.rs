use std::sync::Arc;

use anyhow::anyhow;
use bimap::BiHashMap;
use discv5::Enr;
use once_cell::sync::Lazy;

use super::{
    network::{Network, Subnetwork},
    protocol_versions::{
        ProtocolVersion, ProtocolVersionError, ProtocolVersionList, ENR_PROTOCOL_VERSION_KEY,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSpec {
    network: Network,
    /// mapping of subnetworks to protocol id hex strings
    portal_subnetworks: BiHashMap<Subnetwork, String>,
    supported_protocol_versions: ProtocolVersionList,
}

impl NetworkSpec {
    pub fn new(
        portal_subnetworks: BiHashMap<Subnetwork, String>,
        network: Network,
        supported_protocol_versions: ProtocolVersionList,
    ) -> anyhow::Result<Self> {
        // Ensure supported protocol versions are ordered chronologically with no duplicates.
        supported_protocol_versions.is_strictly_sorted_and_specified();

        Ok(Self {
            portal_subnetworks,
            network,
            supported_protocol_versions,
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
    )
    .expect("Failed to create angelfood network spec")
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
