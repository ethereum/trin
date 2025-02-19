use alloy::{
    primitives::{Bytes, B256},
    rlp::Decodable,
};
use ethportal_api::types::state_trie::{
    account_state::AccountState,
    nibbles::Nibbles,
    trie_traversal::{NextTraversalNode, NodeTraversal, TraversalResult},
    EncodedTrieNode, TrieProof,
};

use super::error::{check_node_hash, StateValidationError};

/// Validate the trie proof.
pub fn validate_node_trie_proof(
    root_hash: Option<B256>,
    node_hash: B256,
    path: &Nibbles,
    proof: &TrieProof,
) -> Result<(), StateValidationError> {
    let (last_node, remaining_path) = validate_trie_proof(root_hash, path.nibbles(), proof)?;

    // Check that we used entire path
    if !remaining_path.is_empty() {
        return Err(StateValidationError::PathTooLong);
    }

    // Check that node hash is correct
    check_node_hash(last_node, &node_hash)?;

    Ok(())
}

/// Validate the trie proof associated with the account state.
pub fn validate_account_state(
    root_hash: Option<B256>,
    address_hash: &B256,
    proof: &TrieProof,
) -> Result<AccountState, StateValidationError> {
    let path = Nibbles::unpack_nibbles(address_hash.as_slice());

    // Validate the proof
    let (last_node, remaining_path) = validate_trie_proof(root_hash, &path, proof)?;

    // Decode last node and extract value
    let last_node = last_node.as_trie_node()?;
    let traversal_result = last_node.traverse(remaining_path);
    let value = check_traversal_result_is_value(traversal_result)?;

    // Decode account state
    Ok(AccountState::decode(&mut value.as_ref())?)
}

/// Validates the Trie Proof.
///
/// If successful, it returns tuple of:
///
/// - last node in the proof (whose presence we are proving)
/// - remaining (unused) nibbles from the path
fn validate_trie_proof<'proof, 'path>(
    root_hash: Option<B256>,
    path: &'path [u8],
    proof: &'proof TrieProof,
) -> Result<(&'proof EncodedTrieNode, &'path [u8]), StateValidationError> {
    // Make sure there is at least one node in proof
    let Some((first_node, nodes)) = proof.split_first() else {
        return Err(StateValidationError::EmptyTrieProof);
    };

    // Check root hash
    if let Some(root_hash) = &root_hash {
        check_node_hash(first_node, root_hash)?;
    }

    let mut node = first_node;
    let mut remaining_path = path;

    for next_node in nodes {
        // Traverse the node
        let traversal_result = node.as_trie_node()?.traverse(remaining_path);
        let next_traversal_node = check_traversal_result_is_node(traversal_result)?;

        // Check the hash of the next node matches
        check_node_hash(next_node, &next_traversal_node.hash)?;

        // Update node and remaining_path for next iteration
        node = next_node;
        remaining_path = next_traversal_node.remaining_path;
    }

    Ok((node, remaining_path))
}

fn check_traversal_result_is_node(
    traversal_result: TraversalResult,
) -> Result<NextTraversalNode, StateValidationError> {
    match traversal_result {
        TraversalResult::Empty(empty_node_info) => {
            Err(StateValidationError::UnexpectedEmptyNode(empty_node_info))
        }
        TraversalResult::Value(_) => Err(StateValidationError::UnexpectedValue),
        TraversalResult::Node(next_node) => Ok(next_node),
        TraversalResult::Error(error) => Err(error.into()),
    }
}

fn check_traversal_result_is_value(
    traversal_result: TraversalResult,
) -> Result<Bytes, StateValidationError> {
    match traversal_result {
        TraversalResult::Empty(empty_node_info) => {
            Err(StateValidationError::UnexpectedEmptyNode(empty_node_info))
        }
        TraversalResult::Value(value) => Ok(value),
        TraversalResult::Node(_) => Err(StateValidationError::LeafNodeExpected),
        TraversalResult::Error(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use std::{array, str::FromStr};

    use alloy::primitives::{keccak256, Address, U256};
    use anyhow::Result;
    use eth_trie::{
        nibbles::Nibbles as EthTrieNibbles,
        node::{empty_children, Node},
    };
    use ethportal_api::utils::bytes::hex_decode;

    use super::*;

    fn create_branch() -> Node {
        let children = array::from_fn(|_| Node::from_hash(B256::random()));
        Node::from_branch(children, None)
    }

    fn create_branch_with_child(child: Node, child_index: usize) -> Node {
        let mut children = array::from_fn(|_| Node::from_hash(B256::random()));
        children[child_index] = child;
        Node::from_branch(children, None)
    }

    fn create_leaf(path: &[u8], value: &[u8]) -> Node {
        let mut nibbles = EthTrieNibbles::from_hex(path);
        // The `Nibbles` in the eth-trie crate add 16 at the end to indicate that it's leaf.
        nibbles.push(16);
        Node::from_leaf(nibbles, value.into())
    }

    fn create_extension(path: &[u8], node: Node) -> Node {
        let nibbles = EthTrieNibbles::from_hex(path);
        Node::from_extension(nibbles, node)
    }

    #[test]
    fn validate_node_trie_proof_single() {
        let node = EncodedTrieNode::from(&create_branch());
        let node_hash = node.node_hash();

        let path = Nibbles::try_from_unpacked_nibbles(&[]).unwrap();
        let proof = TrieProof::from(vec![node.clone()]);

        assert!(validate_node_trie_proof(Some(node_hash), node_hash, &path, &proof).is_ok());
    }

    #[test]
    fn validate_node_trie_proof_simple() {
        let last_node = EncodedTrieNode::from(&create_leaf(&[3, 2, 1], &[0x11, 0x22, 0x33]));
        let root_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(last_node.node_hash()),
            4,
        ));

        let path = Nibbles::try_from_unpacked_nibbles(&[4]).unwrap();
        let proof = TrieProof::from(vec![root_node.clone(), last_node.clone()]);

        assert!(validate_node_trie_proof(
            Some(root_node.node_hash()),
            last_node.node_hash(),
            &path,
            &proof,
        )
        .is_ok());
    }

    #[test]
    fn validate_node_trie_proof_complex() {
        let last_node = EncodedTrieNode::from(&create_leaf(&[3, 2, 1], &[0x11, 0x22, 0x33]));
        let branch_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(last_node.node_hash()),
            4,
        ));
        let extension_node = EncodedTrieNode::from(&create_extension(
            &[6, 5],
            Node::from_hash(branch_node.node_hash()),
        ));
        let root_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(extension_node.node_hash()),
            7,
        ));

        let path = Nibbles::try_from_unpacked_nibbles(&[7, 6, 5, 4]).unwrap();
        let proof = TrieProof::from(vec![
            root_node.clone(),
            extension_node,
            branch_node,
            last_node.clone(),
        ]);

        assert!(validate_node_trie_proof(
            Some(root_node.node_hash()),
            last_node.node_hash(),
            &path,
            &proof,
        )
        .is_ok());
    }

    #[test]
    #[should_panic = "PathTooLong"]
    fn validate_node_trie_proof_path_too_long() {
        let last_node = EncodedTrieNode::from(&create_leaf(&[3, 2, 1], &[0x11, 0x22, 0x33]));
        let root_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(last_node.node_hash()),
            4,
        ));

        let path = Nibbles::try_from_unpacked_nibbles(&[4, 3, 2, 1]).unwrap();
        let proof = TrieProof::from(vec![root_node.clone(), last_node.clone()]);

        validate_node_trie_proof(
            Some(root_node.node_hash()),
            last_node.node_hash(),
            &path,
            &proof,
        )
        .unwrap();
    }

    #[test]
    #[should_panic = "InvalidNodeHash"]
    fn validate_node_trie_proof_invalid_node_hash() {
        let last_node = EncodedTrieNode::from(&create_leaf(&[3, 2, 1], &[0x11, 0x22, 0x33]));
        let root_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(last_node.node_hash()),
            4,
        ));

        let path = Nibbles::try_from_unpacked_nibbles(&[4]).unwrap();
        let proof = TrieProof::from(vec![root_node.clone(), last_node.clone()]);

        // This should be the hash of the last_node, and it should fail if it is anything else
        let wrong_last_node_hash = root_node.node_hash();
        validate_node_trie_proof(
            Some(root_node.node_hash()),
            wrong_last_node_hash,
            &path,
            &proof,
        )
        .unwrap();
    }

    #[test]
    fn validate_account_state_test_vector() -> Result<()> {
        // Data copied from: https://github.com/ethereum/portal-network-specs/blob/04cc360179aeda179e0b1cac6fea900a74e87f2b/state-network-test-vectors.md
        let state_root =
            B256::from_str("0x1ad7b80af0c28bc1489513346d2706885be90abb07f23ca28e50482adb392d61")?;
        let address = Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")?;
        let address_hash = keccak256(address);
        let account_state = AccountState {
            nonce: 1,
            balance: U256::from(3272363543482522011582395_u128),
            storage_root: B256::from_str(
                "0x46d5eb15d44b160805e80d05e2a47d434053e6c4b3ef9d1111773039e9586661",
            )?,
            code_hash: B256::from_str(
                "0xd0a06b12ac47863b5c7be4185c2deaad1c61557033f56c7d4ea74429cbb25e23",
            )?,
        };
        let account_proof = [
            "0xf90211a0491f396d5d4768a01ee4282a3ab1127f2a4dc7d42e6c1dbb3e71ad4e9299f5e7a05b4645219e614b388ba9672452b40f291987b15e35bdbd3dfebfac9a085aeab2a0979ebca2a6a0df389fdfef5bfa4a31f2efa8d385bf2f43cd69c27e61165c3667a01bbe04543bb6bf8026ee3ec2a3ec3d6173a60c090008b59779f767e5769d7a0aa051d347ec61c7dde5c4149a943d0aa489544cbea511ed3d7f4fc6aaa52a420d3ea05358bc8e1e1f20e510887226d67efee73769d0b13ebb24a3e750c2214ef090d5a04df1c24ebf40befce60c8eb30a31894102881454fcdeb6f7b83e1fb916c953a8a00a85e04f30a4978712c58a825e7bd2f8a83731ab1aa3e234a0207e918790505fa0778a45437218486b7849aef890d483dcc2deb1423cb81e488b7be2921d505bf4a051dbaef3c3d3fe82bd1484954f38508f651d867f387f71dedbfb0f7355987ed5a061679f43f3db26673bb687c584f30ae3cff7261e71acf07ed1feaecae098fc79a099761ea7d94e01b14285b7ced7dcd1677fbd3ce093a627a8e1472074baad8bd9a0bb6d269fc61443aa28b14af0448aaf6f1f570477d8b4ef2eb7d31543202ce602a06c41cd2d1701b058853591a2f306ddcfd1e55d3e12011cadb100e7c525aaf460a0bcf37abaac566bb98e091575af403804dbb278fbfa5547de6805cbaa529ae137a0de9918a2a976a2b0b3f4aeff801fc79557426b19c15d414ddf8fae843785b0b780",
            "0xf90211a0be51f8518274d3e1beeaaa8cebe00428d5fd388e5a2a50404a4278e4dbb822b8a0c89fe8e16d89a82d5dcde02ef4a861c49549f23caa89c6772cd3e046924170a2a09d3e56c85bde8ff3e48f1029a3ed19f6cc1657ea7148396264117128916bf192a0dfe966436ccd76314d1ff27c3f314ba4bd67cdbb84bf6e7aa838407acd31f8c2a02a4659357dbb06d71dc46b900459e5bff6f3e49e4ef001cf4c8a2c62a7a227f9a02db2fff7623b55bef3e3e97d4596d35bf648209ed27a1dfa4574a950e76e9866a0e9b7cec39e827b538d84d697c774c2415d4c779b4633e3512b1b3b037e5be466a024a73f497d6080270bd263da5eb8c65a8495202d23880bb332a5fc7c4b18c4a8a08461ab3f12ab5d327b9496351467b25b27fab2e83c0c05618eb1fc20611f1958a022c7ff9562e90fee635a098995fb60330f313c683bf387b16e36f3ed01df69cca068c8d94e7b4b8a512cc108fd5fc723c53524f18d15c5aa354a5ed4076d5818a6a0d8162bc7fbbc17e616c126ba764cc4117ff3ec948a3bd588ea3287f8b901c4a7a0292d04df2f33b68e0033209c36035212c23581c8be47c5e0ea67e18fe8521f58a0e7ae2ece7c4c44a19a4d576904e39574030d6f739b450e75f36c59c83ae91829a0d577206430b32c22323816ba5309a85e5f71954e2bf5c755f5e33ee00f0de899a0f1f58b86f4addc6c095586a5333d6816b9b8a6d97b486798442863ea9615ae1380",
            "0xf90211a0256e27eecd0670e56ade58d99348a11f6fa4985d1f7b23143c61ee0a04a5a053a050b3d0ae7fdcad74ee9e322bb5b5fedb329db8b5bb95b281ee6d5b090314520ea07800c5365602d0c6eed658ee1056a0a2576809372757b1a42bafcc98438aebdba09bb7c947da462574a0fc0ae5608c25ac3272bb8fe3f2e619b20a10ced54738cfa0f73e7c44ce8ab0bc3495eba1aa7e2a0db44505d690e9d2daf4fab856cff999e2a022820f57846aa9ca4d0ebab020327b14178da53c2e006aaf5a22cc6648bc055ca0989235e562ad6e89656e7b8ccb301c300138d1eceddc2cfb724799a13f089783a0aa9b63d694d348219c0fb7f77b45e0e6835c99cda60a8f2030f0f712716b3751a0a34922189d09d23f5e0c8ff2f0b2407ff98a308cb3e8a9239cd4c776cee1e23ea06af9c10b566519fbbeb36dd1b3458b23fd25aeef27275a88df2d7662c2084ca9a05ce8b9e271738c6c52b1078ec04566681c8f11f679eeb2e83197431798cae230a05bfd293e2680e5c45fba826bb768e4d2cad9ab1451a712e98b0cdfba4d31b3f7a0f3ca96a33140e3e0e6ed23e857b6e5c5c7bdb77d7ef520aa4e10213d525bae84a003de0c0d867465dbb29e938fe08f3a508b26abacf7fdf8e02ffb485229195f14a0141a995d94148f08196179583fc853e65f18c338b1afe93b948701b795720960a01a35da701f908a90c16c4cc97de451ac2c35d52b019a58a078e61afe0b9a1cd480",
            "0xf90211a019c38310558d06bcbb4da68f64e61f2e6ee0f9bf3f6d643099e2e5c537294f6ba03a2ea461fdc547b6f72bc5d0b6f0a350aea0cb4b8ce1b036d123a5a00ec58b4aa07804bb6a71cf8c1153df5aa4ef84a409f26dd96c376e793da8cf9bcc802b4c26a076b61be012d6c7494b54c77a2dc6fcfe5568eef756d7a9b827c71ff25849dd87a0c8e8448bf1fbb0511823f5a92ff0febd7cad713967b5bbd0a4603d4ef2b9ef01a04c6d270a17b8fc136e0741940349c43d1e4ca894f191eefa13851da489de99d5a01076e9645c48dfed84933a8fae6016be4d47946f8105ccbc892ab0ae6ccf837aa0c6fea6b5dd5a7bae7e3c2ffae6841b292b613bf4c7421bdb90226f53e9eebc51a073b6c1de7658ec6f66fd52f1d66ac278ed0f3db37201981a9ca4b64a951fc52ba00bc5ecf44d423b4b6e0030d057939b739b85981c2bf2b4ad4f968bebd83cba7da0ed7e7a51c44fc09f230853a018c49eb711fbfa439904fd5ceb99c00b166f3ac7a005bf4f540bbc5bd6731dd89f4ff0a28c8ad8ee39d9611ef4bda0e2016bbd644ea0a1e0d3c4b952dce2233de45cca6e6c771e3f552ff6ff0194ff3d1b44d620683ea081e8d789f13dac46de04320c3a9c7d3e488ec667a619c21a020f95a41093e338a0dc9b8851a29da9247a4423fdcc689ae44c7843d31a891a067509780a2664c0a6a064f75b0a17b502154c6d316e7244bfde51a39b211484d311be73b80fbb93fd9c80",
            "0xf90211a09c0680faf2d7a9a79b5eedf6a8f846b95431cf91391973f6d1a6ec66dc7c3c24a02fd29886972cc78eab95ef19fd5cdd434e8d60c79b7d7aaff5b183469b848892a0cd246c92230812e63f13e8fddf2d0a0a976fde22e78256f9f3c7fd8219c71494a0f1d0b771957fe8d4c908d4ca730deca96c4ead47a9cde9648dd371da93bedbfca0de3910f22bd6ac087a1f778dfb20c7df43f7b3177e1abfe89d76d094dbd5753ba034b9341a9dad17687f5c22155e87ddbfea86dc0374e2071c6fac2a34fed5d7eea015eb41b2ece7cffbeaa040429aea2c73cf1c97a79282522f9eb25fcad1379b03a032214af47db0deb697b79ab12adc1b92cbace8395c8772544e803f33496c8073a01ac13a790f63114ce9bde82925bb5be8f4a09ee8ecf086d7675517248f8b8d4da04fe95c1a0f329cbf6b40efb608497e1d35f86919270a1c3b0a5b8f5c4675fbd6a0649e3ea0c951c4a16658f463755df800dd83f331f25a37275476877ce2eed44ea0157f094338c21f03a13a16793af96cc11a8f8a4a23b1f6105816833f603eabd0a086913ed8ad6c2c5d3d1e37b18bf7522aa080c04f3acd32a521efc7297653b658a0ed086a76c87f4654a164d1c4ec2626743cfa89bc1c4af41eba7369b42708c690a0c6730ce5e1df17601ac55b243bcba90a9f49dc835044bda9e2d7a76885b36598a0368943b40d006cdd58e0f576314c626fae7bc832d9451c5758a15c03e0bd08f680",
            "0xf90211a0515cb567f896e05d10003f6fff6b848448ecdfa82d6f854a8bf0058a57f53563a03661a6bd0c24511a05b40f8ae74c737f47d0df70bbf3c7a0816810ed90a84426a0c4d94bcf7df0b9c6707deb12770d992c1e60724ec2f40633a02ef1c4375326bba06af61ac19cd4496fb6d376dc38a8165a2561022866ce6fef41f8ade0fd2a407ba003a8b55e6cf12c06d0962f587bc293bca33303b7cc747f4ffbd17332cdbb33dda04f96708c335dd6364f8c5b4fc62edf32f5fd9a7107a99be1e9f6914b4093b88ca0e3981f17dbc1a00258432c0e34232f267d05e271590ee7a9783a51870f9873c8a03f2b45b47cdc12f020c55f6da3f7a348ec409de53a618b9cda4523c97d754b82a0935bc9189b81bb782d6b4d1451ab3d165b94a6fc4de4ab275528c06d9a128729a0c07c4048481c07b118748b2a30e851cf5c6c87af6212257f8845eb9ce07a02e4a0012fab999f402d6b302a07d3f7973ee8c357d5db8c7991903bd54d54d507cc23a05923155adc8cd3aceaf27c07858d290a3b85fc378fdd98e9f4f7f70d157f28baa0c55b2981a6fe08260cb6a076c76858d56aafdf255d0a12a2c50abe35d468c7e7a0e85b45f9a72f3abf2758687f2bdc33deab733aa4ef769bd5648f6a55ae1fb123a06ef38fec665b8eb25934622af1112b9a9d52408c94d2c0124d6e24b7ff4296c0a0867f6119f66c88787520dc8899d07d0e49598fa8dde1f33e611871eff6cd049680",
            "0xf8f1a0ca06c2b4c97d9941e56c3c752abe4c2b0b2cd162e22a5d25f61774dc453deedfa0344f34e01710ba897da06172844f373b281598b859086cf00c546594b955b87080a09bc4a42b6376f15f2639c98ad195b6fb948459cca93c568eacb33574b826a7af80a0525e7dd1bf391cf7df9ffaaa07093363a2c7a1c7d467d01403e368bd8c1f4e56808080808080a0758bf45f49922e3f1273d3e589753038a18ce3bbd961e3493f276eb7c5d04a3fa0235db60b9fecfc721d53cb6624da22433e765569a8312e86a6f0b47faf4a2a23a02f35f91fe878f56f1dd0b738bd12d9c8ed0f9b0f6be4146b66ae2c5625cc156b8080",
            "0xf85180a07f152c1e0fbe4b406b9a774b132347f174f02f3c2d6d1d4ad005c979996754b28080808080808080808080a06225fcc63b22b80301d9f2582014e450e91f9b329b7cc87ad16894722fff5296808080",
            "0xf8719d20a65bd257638cf8cf09b8238888947cc3c0bea2aa2cc3f1c4ac7a3002b851f84f018b02b4f32ee2f03d31ee3fbba046d5eb15d44b160805e80d05e2a47d434053e6c4b3ef9d1111773039e9586661a0d0a06b12ac47863b5c7be4185c2deaad1c61557033f56c7d4ea74429cbb25e23"
          ].map(|trie_node| EncodedTrieNode::from(hex_decode(trie_node).unwrap()));

        assert_eq!(
            validate_account_state(
                Some(state_root),
                &address_hash,
                &account_proof.to_vec().into()
            )?,
            account_state
        );

        Ok(())
    }

    #[test]
    fn validate_account_state_just_leaf() {
        let address_hash = B256::random();
        let path = Nibbles::unpack_nibbles(address_hash.as_slice());
        let account_state = AccountState {
            nonce: 1,
            balance: U256::from_be_slice(B256::random().as_slice()),
            storage_root: B256::random(),
            code_hash: B256::random(),
        };
        let node = EncodedTrieNode::from(&create_leaf(&path, &alloy::rlp::encode(&account_state)));
        assert_eq!(
            validate_account_state(Some(node.node_hash()), &address_hash, &vec![node].into())
                .unwrap(),
            account_state
        );
    }

    #[test]
    #[should_panic = "LeafNodeExpected"]
    fn validate_account_state_last_node_is_not_leaf() {
        let address_hash = B256::random();
        let node = EncodedTrieNode::from(&create_branch());
        validate_account_state(Some(node.node_hash()), &address_hash, &vec![node].into()).unwrap();
    }

    #[test]
    #[should_panic = "DifferentLeafPrefix"]
    fn validate_account_state_invalid_leaf_path() {
        let address_hash = B256::random();
        let mut path = Nibbles::unpack_nibbles(address_hash.as_slice());
        // use one less nibble in the path to make it invalid
        path.pop();

        let account_state = AccountState {
            nonce: 1,
            balance: U256::from_be_slice(B256::random().as_slice()),
            storage_root: B256::random(),
            code_hash: B256::random(),
        };
        let node = EncodedTrieNode::from(&create_leaf(&path, &alloy::rlp::encode(account_state)));
        validate_account_state(Some(node.node_hash()), &address_hash, &vec![node].into()).unwrap();
    }

    #[test]
    #[should_panic = "DecodingAccountState"]
    fn validate_account_state_non_decodable_account_state() {
        let address_hash = B256::random();
        let path = Nibbles::unpack_nibbles(address_hash.as_slice());
        let node = EncodedTrieNode::from(&create_leaf(&path, &[0x12, 0x34]));
        validate_account_state(Some(node.node_hash()), &address_hash, &vec![node].into()).unwrap();
    }

    #[test]
    #[should_panic = "DecodingNode"]
    fn validate_account_state_non_decodable_leaf() {
        let address_hash = B256::random();
        let node = EncodedTrieNode::from(vec![0x12, 0x34]);
        validate_account_state(Some(node.node_hash()), &address_hash, &vec![node].into()).unwrap();
    }

    #[test]
    fn validate_trie_proof_single_node() {
        let node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(B256::random()),
            1,
        ));

        let proof = TrieProof::from(vec![node.clone()]);
        let path = [2, 3, 4];
        let validation_info = validate_trie_proof(Some(node.node_hash()), &path, &proof).unwrap();

        assert_eq!(validation_info, (&node, path.as_slice()));
    }

    #[test]
    fn validate_trie_proof_single_node_with_root_hash() {
        let node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(B256::random()),
            1,
        ));

        let proof = TrieProof::from(vec![node.clone()]);
        let path = [2, 3, 4];
        let validation_info = validate_trie_proof(Some(node.node_hash()), &path, &proof).unwrap();

        assert_eq!(validation_info, (&node, path.as_slice()));
    }

    #[test]
    fn validate_trie_proof_all() {
        let last_node = EncodedTrieNode::from(&create_leaf(&[3, 2, 1], &[0x11, 0x22, 0x33]));
        let branch_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(last_node.node_hash()),
            4,
        ));
        let extension_node = EncodedTrieNode::from(&create_extension(
            &[6, 5],
            Node::from_hash(branch_node.node_hash()),
        ));
        let root_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(extension_node.node_hash()),
            7,
        ));

        let path = [7, 6, 5, 4, 3, 2];
        let proof = TrieProof::from(vec![
            root_node.clone(),
            extension_node,
            branch_node,
            last_node.clone(),
        ]);
        let validation_info =
            validate_trie_proof(Some(root_node.node_hash()), &path, &proof).unwrap();

        assert_eq!(validation_info, (&last_node, &path[4..]));
    }

    #[test]
    fn validate_trie_proof_wrong_order_of_nodes() {
        let last_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(B256::random()),
            1,
        ));
        let root_node = EncodedTrieNode::from(&create_branch_with_child(
            Node::from_hash(last_node.node_hash()),
            2,
        ));

        // First verify that correct order pass the validation
        let proof = TrieProof::from(vec![root_node.clone(), last_node.clone()]);
        assert!(validate_trie_proof(Some(root_node.node_hash()), &[2, 1], &proof).is_ok());

        // Now verify that wrong order fails because root hash doesn't match
        let proof = TrieProof::from(vec![last_node.clone(), root_node.clone()]);
        let error = validate_trie_proof(Some(root_node.node_hash()), &[2, 1], &proof).unwrap_err();
        assert!(matches!(
            error,
            StateValidationError::InvalidNodeHash {
                node_hash: _,
                expected_node_hash,
            } if expected_node_hash == root_node.node_hash()
        ));

        // And that if fails even if root hash that corresponds to the first node is given
        let proof = TrieProof::from(vec![last_node.clone(), root_node.clone()]);
        let error = validate_trie_proof(Some(last_node.node_hash()), &[2, 1], &proof).unwrap_err();
        assert!(matches!(
            error,
            StateValidationError::InvalidNodeHash {
                node_hash: _,
                expected_node_hash,
            } if expected_node_hash != last_node.node_hash()
        ));

        // And that it fails even if we reverse order in path
        let error = validate_trie_proof(Some(last_node.node_hash()), &[1, 2], &proof).unwrap_err();
        assert!(matches!(
            error,
            StateValidationError::InvalidNodeHash {
                node_hash: _,
                expected_node_hash,
            } if expected_node_hash != last_node.node_hash()
        ));
    }

    #[test]
    #[should_panic = "EmptyTrieProof"]
    fn validate_trie_proof_empty_proof() {
        validate_trie_proof(Some(B256::random()), &[], &TrieProof::default()).unwrap();
    }

    #[test]
    #[should_panic = "InvalidNodeHash"]
    fn validate_trie_proof_invalid_root_hash() {
        let node = Node::from_branch(empty_children(), None);
        let proof = TrieProof::from(vec![EncodedTrieNode::from(&node)]);
        validate_trie_proof(Some(B256::random()), &[], &proof).unwrap();
    }
}
