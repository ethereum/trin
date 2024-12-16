use std::fmt;

use ethportal_api::types::{
    distance::Distance, enr::Enr, ping_extensions::custom_payload_format::Extensions,
};

/// A node in the overlay network routing table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    /// The node's ENR.
    pub enr: Enr,

    /// The node's data radius.
    pub data_radius: Distance,

    /// The node's capabilities.
    pub capabilities: Option<Vec<Extensions>>,

    /// The node's ephemeral header count (only used for History Network)
    pub ephemeral_header_count: Option<u16>,
}

impl Node {
    /// Creates a new node.
    pub fn new(enr: Enr, data_radius: Distance) -> Node {
        Node {
            enr,
            data_radius,
            capabilities: None,
            ephemeral_header_count: None,
        }
    }

    /// Returns the ENR of the node.
    pub fn enr(&self) -> Enr {
        self.enr.clone()
    }

    /// Returns the data radius of the node.
    pub fn data_radius(&self) -> Distance {
        self.data_radius
    }

    /// Returns the capabilities of the node.
    pub fn capabilities(&self) -> Option<&[Extensions]> {
        self.capabilities.as_deref()
    }

    /// Compares the capabilities of the node with the given capabilities.
    /// Returns true if the capabilities are the same.
    pub fn compare_capabilities(&self, capabilities: &[Extensions]) -> bool {
        if let Some(node_capabilities) = &self.capabilities {
            capabilities.iter().all(|c| node_capabilities.contains(c))
        } else {
            false
        }
    }

    /// Returns the ephemeral header count of the node.
    pub fn ephemeral_header_count(&self) -> Option<u16> {
        self.ephemeral_header_count
    }

    /// Sets the ENR of the node.
    pub fn set_enr(&mut self, enr: Enr) {
        self.enr = enr;
    }

    /// Sets the data radius of the node.
    pub fn set_data_radius(&mut self, radius: Distance) {
        self.data_radius = radius;
    }

    /// Sets the capabilities of the node.
    pub fn set_capabilities(&mut self, capabilities: Vec<Extensions>) {
        self.capabilities = Some(capabilities);
    }

    /// Sets the ephemeral header count of the node.
    pub fn set_ephemeral_header_count(&mut self, count: u16) {
        self.ephemeral_header_count = Some(count);
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Node(node_id={}, radius={})",
            self.enr.node_id(),
            self.data_radius,
        )
    }
}
