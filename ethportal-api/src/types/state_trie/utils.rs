use eth_trie::node::Node;
use keccak_hash::{keccak, H256};
use rlp::RlpStream;

/// Our own implementation for encoding the node.
///
/// It is almost identical copy from the `eth_trie` crate, because that one is not reusable.
pub fn encode_node(node: &Node) -> Vec<u8> {
    encode_raw(node)
}

enum EncodedNode {
    Hash(H256),
    Inline(Vec<u8>),
}

const HASHED_LENGTH: usize = 32;

fn write_node(to_encode: &Node) -> EncodedNode {
    // Returns the hash value directly to avoid double counting.
    if let Node::Hash(hash_node) = to_encode {
        return EncodedNode::Hash(hash_node.hash);
    }

    let data = encode_raw(to_encode);
    // Nodes smaller than 32 bytes are stored inside their parent,
    // Nodes equal to 32 bytes are returned directly
    if data.len() < HASHED_LENGTH {
        EncodedNode::Inline(data)
    } else {
        EncodedNode::Hash(keccak(&data))
    }
}

fn encode_raw(node: &Node) -> Vec<u8> {
    match node {
        Node::Empty => rlp::NULL_RLP.to_vec(),
        Node::Leaf(leaf) => {
            let mut stream = RlpStream::new_list(2);
            stream.append(&leaf.key.encode_compact());
            stream.append(&leaf.value);
            stream.out().to_vec()
        }
        Node::Branch(branch) => {
            let borrow_branch = branch.read().expect("to read branch node");

            let mut stream = RlpStream::new_list(17);
            for i in 0..16 {
                let n = &borrow_branch.children[i];
                match write_node(n) {
                    EncodedNode::Hash(hash) => stream.append(&hash.as_bytes()),
                    EncodedNode::Inline(data) => stream.append_raw(&data, 1),
                };
            }

            match &borrow_branch.value {
                Some(v) => stream.append(v),
                None => stream.append_empty_data(),
            };
            stream.out().to_vec()
        }
        Node::Extension(ext) => {
            let borrow_ext = ext.read().expect("to read extension node");

            let mut stream = RlpStream::new_list(2);
            stream.append(&borrow_ext.prefix.encode_compact());
            match write_node(&borrow_ext.node) {
                EncodedNode::Hash(hash) => stream.append(&hash.as_bytes()),
                EncodedNode::Inline(data) => stream.append_raw(&data, 1),
            };
            stream.out().to_vec()
        }
        Node::Hash(_hash) => unreachable!("encode_raw shouldn't be called for the Node::Hash (it should be handled by write_node logic)"),
    }
}
