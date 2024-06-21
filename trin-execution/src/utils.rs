use alloy_primitives::{keccak256, Address, B256};

pub fn full_nibble_path_to_address_hash(key_path: &[u8]) -> B256 {
    if key_path.len() != 64 {
        panic!("Key path should always be 64 bytes long.")
    }

    let mut raw_address_hash = vec![];
    for i in 0..key_path.len() {
        if i % 2 == 0 {
            raw_address_hash.push(key_path[i] << 4);
        } else {
            raw_address_hash[i / 2] |= key_path[i];
        }
    }
    B256::from_slice(&raw_address_hash)
}

pub fn address_to_nibble_path(address: Address) -> Vec<u8> {
    keccak256(address)
        .into_iter()
        .flat_map(|b| [b >> 4, b & 0xF])
        .collect()
}

#[cfg(test)]
mod tests {
    use eth_trie::nibbles::Nibbles as EthNibbles;
    use revm_primitives::{keccak256, Address};

    use crate::utils::{address_to_nibble_path, full_nibble_path_to_address_hash};

    #[test]
    fn test_eth_trie_and_ethportalapi_nibbles() {
        let address = Address::random();
        let address_hash = keccak256(address);

        let mut eth_trie_nibbles = EthNibbles::from_raw(address_hash.as_slice(), true);
        eth_trie_nibbles.pop();
        let path: Vec<u8> = address_to_nibble_path(address);
        assert_eq!(eth_trie_nibbles.get_data(), &path);
    }

    #[test]
    fn test_key_path_to_address_hash() {
        let address = Address::random();
        let address_hash = keccak256(address);
        let path: Vec<u8> = address_to_nibble_path(address);
        let generated_address_hash = full_nibble_path_to_address_hash(&path);
        assert_eq!(address_hash, generated_address_hash);
    }
}
