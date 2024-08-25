use alloy_primitives::{Bytes, B256};
use eth_trie::node::Node;
use thiserror::Error;

/// The explanation of how we reached empty node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmptyNodeInfo {
    /// Reached [Node::Empty].
    EmptyNode,
    /// Consumed entire path to reach branch node without value.
    EmptyBranchValue,
    /// Reached extension node whose prefix is not prefix of the remaining path.
    DifferentExtensionPrefix,
    /// Reached leaf node whose prefix doesn't match remaining path.
    DifferentLeafPrefix,
}

/// The error that can happen while traversing the node.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TraversalError {
    #[error("The extension node has empty prefix.")]
    EmptyExtensionPrefix,
    #[error("The leaf node has empty key.")]
    EmptyLeafKey,
    #[error("The leaf node has invalid key.")]
    InvalidLeafKey,
    #[error("Error reading node data: read-write lock is poisoned")]
    ReadLockPoisoned,
}

/// Contains information needed for continuing the trie traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextTraversalNode<'path> {
    /// The Hash of the next node.
    pub hash: B256,
    /// The path that was not consumed during traversal
    pub remaining_path: &'path [u8],
}

/// The result of the node traversal along given path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraversalResult<'path> {
    /// Path leads to empty node.
    Empty(EmptyNodeInfo),
    /// Path leads to value.
    Value(Bytes),
    /// Path leads to a next node.
    Node(NextTraversalNode<'path>),
    /// Unexpected error happened, most likely malformed node or programmers error.
    Error(TraversalError),
}

/// The trait for traversing Merkle Patricia Trie node.
pub trait NodeTraversal {
    /// Traverses the node and returns the result.
    fn traverse<'path>(&self, path: &'path [u8]) -> TraversalResult<'path>;
}

impl NodeTraversal for Node {
    fn traverse<'path>(&self, path: &'path [u8]) -> TraversalResult<'path> {
        match self {
            Node::Empty => TraversalResult::Empty(EmptyNodeInfo::EmptyNode),
            Node::Leaf(leaf_node) => {
                let Some((last, nibbles)) = leaf_node.key.get_data().split_last() else {
                    return TraversalResult::Error(TraversalError::InvalidLeafKey);
                };
                if *last != 16 {
                    return TraversalResult::Error(TraversalError::InvalidLeafKey);
                }
                if nibbles.is_empty() {
                    return TraversalResult::Error(TraversalError::EmptyLeafKey);
                }
                if nibbles != path {
                    TraversalResult::Empty(EmptyNodeInfo::DifferentLeafPrefix)
                } else {
                    TraversalResult::Value(Bytes::from_iter(&leaf_node.value))
                }
            }
            Node::Extension(extension_node) => {
                let Ok(extension_node) = extension_node.read() else {
                    return TraversalResult::Error(TraversalError::ReadLockPoisoned);
                };
                let prefix = extension_node.prefix.get_data();
                if prefix.is_empty() {
                    return TraversalResult::Error(TraversalError::EmptyExtensionPrefix);
                }
                match path.strip_prefix(prefix) {
                    Some(remaining_path) => extension_node.node.traverse(remaining_path),
                    None => TraversalResult::Empty(EmptyNodeInfo::DifferentExtensionPrefix),
                }
            }
            Node::Branch(branch_node) => {
                let Ok(branch_node) = branch_node.read() else {
                    return TraversalResult::Error(TraversalError::ReadLockPoisoned);
                };
                match path.split_first() {
                    Some((first, remaining_path)) => {
                        branch_node.children[*first as usize].traverse(remaining_path)
                    }
                    None => match &branch_node.value {
                        Some(value) => TraversalResult::Value(Bytes::from_iter(value)),
                        None => TraversalResult::Empty(EmptyNodeInfo::EmptyBranchValue),
                    },
                }
            }
            Node::Hash(hash) => TraversalResult::Node(NextTraversalNode {
                hash: hash.hash,
                remaining_path: path,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::array;

    use eth_trie::{nibbles::Nibbles, node::empty_children};
    use rstest::rstest;

    use super::*;

    #[test]
    fn direct_hash() {
        let hash = B256::random();
        let path = [];
        let node = Node::from_hash(hash);
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Node(NextTraversalNode {
                hash,
                remaining_path: &path,
            })
        );
    }

    #[test]
    fn direct_hash_with_path() {
        let hash = B256::random();
        let path = [1, 2, 3];
        let node = Node::from_hash(hash);
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Node(NextTraversalNode {
                hash,
                remaining_path: &path,
            })
        );
    }

    #[test]
    fn branch_to_hash() {
        let hash = B256::random();
        let path = [1, 2, 3];
        let node = create_branch_with_child(path[0], Node::from_hash(hash));
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Node(NextTraversalNode {
                hash,
                remaining_path: &path[1..],
            })
        );
    }

    #[test]
    fn extension_to_hash() {
        let hash = B256::random();
        let path = [1, 2, 3, 4, 5];
        let node = create_extension(&path[..2], Node::from_hash(hash));
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Node(NextTraversalNode {
                hash,
                remaining_path: &path[2..],
            })
        );
    }

    #[test]
    fn extension_to_branch_to_hash() {
        let hash = B256::random();
        let path = [1, 2, 3, 4, 5];
        let node = create_extension(
            &path[..2],
            create_branch_with_child(path[2], Node::from_hash(hash)),
        );
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Node(NextTraversalNode {
                hash,
                remaining_path: &path[3..],
            })
        );
    }

    #[test]
    fn extension_empty_path() {
        let hash = B256::random();
        let path = [1];
        let node = create_extension(&[], Node::from_hash(hash));
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Error(TraversalError::EmptyExtensionPrefix)
        );
    }

    #[test]
    fn leaf_empty_path() {
        let path = [];
        let node = create_leaf(&[]);
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Error(TraversalError::EmptyLeafKey)
        );
    }

    #[test]
    fn extension_missmatched_path() {
        let hash = B256::random();
        let path = [1, 2, 3];
        let node = create_extension(&path[1..], Node::from_hash(hash));
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Empty(EmptyNodeInfo::DifferentExtensionPrefix),
        );
    }

    #[test]
    fn leaf_missmatched_path() {
        let path = [1, 2, 3];
        let node = create_leaf(&path[..2]);
        assert_eq!(
            node.traverse(&path),
            TraversalResult::Empty(EmptyNodeInfo::DifferentLeafPrefix),
        );
    }

    #[test]
    fn branch_empty_path() {
        let hash = B256::random();
        let node = create_branch_with_child(1, Node::from_hash(hash));
        assert_eq!(
            node.traverse(&[]),
            TraversalResult::Empty(EmptyNodeInfo::EmptyBranchValue)
        );
    }

    #[rstest]
    #[case::empty(Node::Empty, &[])]
    #[case::branch_to_empty(Node::from_branch(empty_children(), None), &[1])]
    #[case::extension_to_branch_to_empty(
        create_extension(&[1], Node::from_branch(empty_children(), None)),
        &[1, 2],
    )]
    fn to_empty_node(#[case] node: Node, #[case] path: &[u8]) {
        assert_eq!(
            node.traverse(path),
            TraversalResult::Empty(EmptyNodeInfo::EmptyNode)
        );
    }

    const VALUE: &[u8] = &[100, 101, 102, 103, 104, 105, 106, 107, 108, 109];

    #[rstest]
    #[case::branch(create_branch_with_value(), &[])]
    #[case::leaf(create_leaf(&[1, 2]), &[1, 2])]
    #[case::branch_to_branch(
        create_branch_with_child(1, create_branch_with_value()),
        &[1])]
    #[case::branch_to_leaf(
        create_branch_with_child(1, create_leaf(&[2, 3, 4])),
        &[1, 2, 3, 4])]
    #[case::extension_to_branch(
        create_extension(&[1, 2, 3], create_branch_with_value()),
        &[1, 2, 3],
    )]
    #[case::extension_to_branch_to_leaf(
        create_extension(&[1, 2], create_branch_with_child(3, create_leaf(&[4, 5]))),
        &[1, 2, 3, 4, 5],
    )]
    fn to_value(#[case] node: Node, #[case] path: &[u8]) {
        assert_eq!(
            node.traverse(path),
            TraversalResult::Value(Bytes::from_static(VALUE))
        )
    }

    // Util functions for creating Trie nodes

    fn create_branch_with_child(child_index: u8, child: Node) -> Node {
        let mut children = array::from_fn(|_| Node::from_hash(B256::random()));
        children[child_index as usize] = child;
        Node::from_branch(children, None)
    }

    fn create_branch_with_value() -> Node {
        Node::from_branch(
            array::from_fn(|_| Node::from_hash(B256::random())),
            Some(VALUE.to_vec()),
        )
    }

    fn create_leaf(path: &[u8]) -> Node {
        let mut nibbles = Nibbles::from_hex(path);
        // The `Nibbles` in the eth-trie crate add 16 at the end to indicate that it's leaf.
        nibbles.push(16);
        Node::from_leaf(nibbles, VALUE.to_vec())
    }

    fn create_extension(path: &[u8], node: Node) -> Node {
        let nibbles = Nibbles::from_hex(path);
        Node::from_extension(nibbles, node)
    }
}
