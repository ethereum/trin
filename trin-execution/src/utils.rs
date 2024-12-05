use alloy::primitives::{keccak256, Address, B256};

fn compress_nibbles(nibbles: &[u8]) -> Vec<u8> {
    let mut compressed_nibbles = vec![];
    for i in 0..nibbles.len() {
        if i % 2 == 0 {
            compressed_nibbles.push(nibbles[i] << 4);
        } else {
            compressed_nibbles[i / 2] |= nibbles[i];
        }
    }
    compressed_nibbles
}

pub fn full_nibble_path_to_address_hash(key_path: &[u8]) -> B256 {
    if key_path.len() != 64 {
        panic!(
            "Key path should always be 64 bytes long: {}",
            key_path.len()
        );
    }

    B256::from_slice(&compress_nibbles(key_path))
}

pub fn partial_nibble_path_to_right_padded_b256(partial_nibble_path: &[u8]) -> B256 {
    B256::right_padding_from(&compress_nibbles(partial_nibble_path))
}

pub fn address_to_nibble_path(address: Address) -> Vec<u8> {
    keccak256(address)
        .into_iter()
        .flat_map(|b| [b >> 4, b & 0xF])
        .collect()
}

#[cfg(test)]
mod tests {
    use alloy::hex::FromHex;
    use eth_trie::nibbles::Nibbles as EthNibbles;
    use revm_primitives::{keccak256, Address, B256};

    use crate::utils::{
        address_to_nibble_path, full_nibble_path_to_address_hash,
        partial_nibble_path_to_right_padded_b256,
    };

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

    #[test]
    fn test_partial_nibble_path_to_right_padded_b256() {
        let partial_nibble_path = vec![0xf, 0xf, 0x0, 0x1, 0x0, 0x2, 0x0, 0x3];
        let partial_path = partial_nibble_path_to_right_padded_b256(&partial_nibble_path);
        assert_eq!(
            partial_path,
            B256::from_hex("0xff01020300000000000000000000000000000000000000000000000000000000")
                .unwrap()
        );
    }
}
