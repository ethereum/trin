use alloy_primitives::B256;
use alloy_rlp::{Encodable, Header, EMPTY_STRING_CODE};
use bytes::BufMut;
use eth_trie::node::Node;
use keccak_hash::keccak;

/// Our own implementation for encoding the node.
///
/// It is almost identical copy from the `eth_trie` crate, because that one is not reusable.
pub fn encode_node(node: &Node) -> Vec<u8> {
    encode_raw(node)
}

enum EncodedNode {
    Hash(B256),
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
        EncodedNode::Hash(keccak(&data).as_fixed_bytes().into())
    }
}

fn encode_raw(node: &Node) -> Vec<u8> {
    match node {
        Node::Empty => vec![EMPTY_STRING_CODE],
        Node::Leaf(leaf) => {
            let mut buf = Vec::<u8>::new();
            let mut list = Vec::<u8>::new();
            leaf.key.encode_compact().as_slice().encode(&mut list);
            leaf.value.as_slice().encode(&mut list);
            let header = Header {
                list: true,
                payload_length: list.len(),
            };
            header.encode(&mut buf);
            buf.extend_from_slice(&list);
            buf
        }
        Node::Branch(branch) => {
            let borrow_branch = branch.read().expect("to read branch node");
            let mut buf = Vec::<u8>::new();
            let mut list = Vec::<u8>::new();
            for i in 0..16 {
                let n = &borrow_branch.children[i];
                match write_node(n) {
                    EncodedNode::Hash(hash) => hash.as_slice().encode(&mut list),
                    EncodedNode::Inline(data) => list.extend_from_slice(data.as_slice()),
                };
            }

            match &borrow_branch.value {
                Some(v) => v.as_slice().encode(&mut list),
                None => list.put_u8(EMPTY_STRING_CODE),
            };
            let header = Header {
                list: true,
                payload_length: list.len(),
            };
            header.encode(&mut buf);
            buf.extend_from_slice(&list);
            buf
        }
        Node::Extension(ext) => {
            let borrow_ext = ext.read().expect("to read extension node");
            let mut buf = Vec::<u8>::new();
            let mut list = Vec::<u8>::new();
            borrow_ext
                .prefix
                .encode_compact()
                .as_slice()
                .encode(&mut list);
            match write_node(&borrow_ext.node) {
                EncodedNode::Hash(hash) => hash.0.as_slice().encode(&mut list),
                EncodedNode::Inline(data) => list.extend_from_slice(data.as_slice()),
            };
            let header = Header {
                list: true,
                payload_length: list.len(),
            };
            header.encode(&mut buf);
            buf.extend_from_slice(&list);
            buf
        }
        Node::Hash(_hash) => unreachable!("encode_raw shouldn't be called for the Node::Hash (it should be handled by write_node logic)"),
    }
}
