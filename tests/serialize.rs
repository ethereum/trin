// tests all Portal Network JSON-RPC Specification types
// these tests will most likely always be required, so there shouldn't be a reason to remove them
#[cfg(test)]
mod test {
    use ethereum_types::H256;
    use ethportal_api::utils::bytes::hex_decode;
    use ethportal_api::{
        BlockBodyKey, BlockHeaderKey, BlockReceiptsKey, Enr, EpochAccumulatorKey,
        HistoryContentKey, NodeId,
    };
    use std::net::Ipv4Addr;

    #[test]
    fn test_enr_ser_de() {
        let enr_base64 = r#""enr:-I24QAnHRBtPxxqnrZ0A9Xw1GV0cr3g178FcLutgd1DcG8a1FjOoRooOleI79K2NvTXYpOpkbe_NN-VqNZqS2a_Bo40BY4d0IDAuMS4wgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQIJSs6oF8rPca9GjRV6tNaJ2YfZb5nNQjui2VUloBleH4N1ZHCCIyo""#;
        let expected_node_id = [
            176, 202, 35, 254, 68, 245, 224, 61, 174, 106, 81, 237, 41, 88, 144, 15, 55, 58, 125,
            119, 228, 39, 201, 211, 154, 95, 148, 198, 212, 185, 175, 219,
        ];
        let expected_ip4 = Some(Ipv4Addr::from([127, 0, 0, 1]));

        let enr: Enr = serde_json::from_str(enr_base64).unwrap();
        assert_eq!(enr.node_id(), expected_node_id);
        assert_eq!(enr.ip4(), expected_ip4);

        let decoded_enr = serde_json::to_string(&enr).unwrap();
        assert_eq!(decoded_enr, enr_base64);
    }

    #[test]
    fn test_node_id_ser_de() {
        let node_id = NodeId([
            176, 202, 35, 254, 68, 245, 224, 61, 174, 106, 81, 237, 41, 88, 144, 15, 55, 58, 125,
            119, 228, 39, 201, 211, 154, 95, 148, 198, 212, 185, 175, 219,
        ]);

        let node_id_string = serde_json::to_string(&node_id).unwrap();

        assert_eq!(node_id, serde_json::from_str(&node_id_string).unwrap());
    }

    const BLOCK_HASH: [u8; 32] = [
        0xd1, 0xc3, 0x90, 0x62, 0x4d, 0x3b, 0xd4, 0xe4, 0x09, 0xa6, 0x1a, 0x85, 0x8e, 0x5d, 0xcc,
        0x55, 0x17, 0x72, 0x9a, 0x91, 0x70, 0xd0, 0x14, 0xa6, 0xc9, 0x65, 0x30, 0xd6, 0x4d, 0xd8,
        0x62, 0x1d,
    ];

    #[test]
    fn ser_de_block_header() {
        let content_key_json =
            "\"0x00d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockHeaderWithProof(BlockHeaderKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_body_failure_prints_debuggable_data() {
        let content_key_json = "\"0x0123456789\"";
        let content_key_result = serde_json::from_str::<HistoryContentKey>(content_key_json);
        // Test the error Display representation
        assert_eq!(
            content_key_result.as_ref().unwrap_err().to_string(),
            "unable to decode key SSZ bytes 0x0123456789 due to InvalidByteLength { len: 4, expected: 32 }"
        );
    }

    #[test]
    fn ser_de_block_body() {
        let content_key_json =
            "\"0x01d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockBody(BlockBodyKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_block_receipts() {
        let content_key_json =
            "\"0x02d1c390624d3bd4e409a61a858e5dcc5517729a9170d014a6c96530d64dd8621d\"";
        let expected_content_key = HistoryContentKey::BlockReceipts(BlockReceiptsKey {
            block_hash: BLOCK_HASH,
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }

    #[test]
    fn ser_de_epoch_accumulator() {
        let content_key_json =
            "\"0x03e242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491\"";
        let epoch_hash =
            hex_decode("0xe242814b90ed3950e13aac7e56ce116540c71b41d1516605aada26c6c07cc491")
                .unwrap();
        let expected_content_key = HistoryContentKey::EpochAccumulator(EpochAccumulatorKey {
            epoch_hash: H256::from_slice(&epoch_hash),
        });

        let content_key: HistoryContentKey = serde_json::from_str(content_key_json).unwrap();

        assert_eq!(content_key, expected_content_key);
        assert_eq!(
            serde_json::to_string(&content_key).unwrap(),
            content_key_json
        );
    }
}
