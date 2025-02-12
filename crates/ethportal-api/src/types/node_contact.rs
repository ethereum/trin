use std::{
    hash::{Hash, Hasher},
    net::{Ipv4Addr, SocketAddr},
};

use discv5::{
    enr::{CombinedKey, CombinedPublicKey},
    handler::NodeContact as Discv5NodeContact,
    Enr,
};
use rand::Rng;

/// The contact info for a remote node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeContact {
    /// Key to use for communications with this node.
    pub public_key: CombinedPublicKey,
    /// The node's ENR.
    pub enr: Enr,
    /// The node's observed socket address.
    pub socket_addr: SocketAddr,
}

impl Hash for NodeContact {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.enr.hash(state);
    }
}

impl From<NodeContact> for Discv5NodeContact {
    fn from(value: NodeContact) -> Self {
        Discv5NodeContact::new(value.public_key, value.socket_addr, Some(value.enr))
    }
}

pub fn generate_random_remote_node_contact() -> (CombinedKey, NodeContact) {
    let key = CombinedKey::generate_secp256k1();
    let mut rng = rand::thread_rng();

    // Generate an IP between 1.0.0.0 and 223.255.255.255
    // We don't want to generate a multicast address (224.0.0.0 - 239.255.255.255)
    let ip = Ipv4Addr::from(rng.gen_range(0x1000000..=0xDFFFFFFF)); // 0xDFFFFFFF == 223.255.255.255

    let enr = Enr::builder()
        .ip(ip.into())
        .udp4(8000)
        .build(&key)
        .expect("Failed to generate random ENR.");

    let socket_addr = enr
        .udp4_socket()
        .map(SocketAddr::V4)
        .expect("Failed to generate socket address.");

    (
        key,
        NodeContact {
            public_key: enr.public_key(),
            enr,
            socket_addr,
        },
    )
}
