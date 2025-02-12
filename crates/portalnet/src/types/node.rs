use std::fmt;

use ethportal_api::types::{
    distance::Distance, enr::Enr, node_contact::NodeContact,
    ping_extensions::extension_types::Extensions,
};

/// A node in the overlay network routing table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    /// The node's NodeContact.
    pub node_contact: NodeContact,

    /// The node's data radius.
    pub data_radius: Distance,

    /// The node's capabilities.
    pub capabilities: Option<Vec<Extensions>>,

    /// The node's ephemeral header count (only used for History Network)
    pub ephemeral_header_count: Option<u16>,
}

impl Node {
    /// Creates a new node.
    pub fn new(node_contact: NodeContact, data_radius: Distance) -> Node {
        Node {
            node_contact,
            data_radius,
            capabilities: None,
            ephemeral_header_count: None,
        }
    }

    /// Returns the NodeContact of the node.
    pub fn node_contact(&self) -> NodeContact {
        self.node_contact.clone()
    }

    /// Returns the ENR of the node.
    pub fn enr(&self) -> &Enr {
        &self.node_contact.enr
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

    /// Sets the NodeContact of the node.
    pub fn set_node_contact(&mut self, node_contact: NodeContact) {
        self.node_contact = node_contact;
    }

    /// Sets the ENR of the node.
    pub fn set_enr(&mut self, enr: Enr) {
        self.node_contact.enr = enr;
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
            self.node_contact.enr.node_id(),
            self.data_radius,
        )
    }
}
