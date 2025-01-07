use std::fmt;

use ethportal_api::types::{distance::Distance, enr::Enr};

/// A node in the overlay network routing table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Node {
    /// The node's ENR.
    pub enr: Enr,
    /// The node's data radius.
    pub data_radius: Distance,
}

impl Node {
    /// Creates a new node.
    pub fn new(enr: Enr, data_radius: Distance) -> Node {
        Node { enr, data_radius }
    }

    /// Returns the ENR of the node.
    pub fn enr(&self) -> Enr {
        self.enr.clone()
    }

    /// Returns the data radius of the node.
    pub fn data_radius(&self) -> Distance {
        self.data_radius
    }

    /// Sets the ENR of the node.
    pub fn set_enr(&mut self, enr: Enr) {
        self.enr = enr;
    }

    /// Sets the data radius of the node.
    pub fn set_data_radius(&mut self, radius: Distance) {
        self.data_radius = radius;
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
