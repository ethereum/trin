use crate::types::{block_header::Header, bytes::Bytes};
use eth_trie::{EthTrie, MemoryDB, Trie, TrieError};
use ethereum_types::{Address, H256, U256, U64};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use ssz::{Decode, Encode, SszDecoderBuilder, SszEncoder};
use ssz_types::{typenum, VariableList};
use std::sync::Arc;

// MAX_ENCODED_UNCLES_LENGTH = 131072
type MaxEncodedUnclesLength = typenum::U131072;

/// BlockBody portal history content type
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockBody {
    pub all_transactions: Vec<Transaction>,
    pub uncles: Vec<Header>,
}

impl BlockBody {
    pub fn transactions_root(&self) -> Result<H256, TrieError> {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut trie = EthTrie::new(memdb);

        // Insert txs into tx tree
        for (index, tx) in self.all_transactions.iter().enumerate() {
            let path = rlp::encode(&index).freeze().to_vec();
            let encoded_tx = rlp::encode(tx);
            trie.insert(&path, &encoded_tx)?
        }

        trie.root_hash()
    }

    pub fn uncles_root(&self) -> keccak_hash::H256 {
        // generate rlp encoded list of uncles
        let mut stream = RlpStream::new();
        stream.append_list(&self.uncles);
        let uncles_rlp = stream.out().freeze();

        // hash rlp uncles
        keccak_hash::keccak(&uncles_rlp)
    }
}

impl Encode for BlockBody {
    // note: MAX_LENGTH attributes (defined in portal history spec) are not currently enforced
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let encoded_txs: Vec<Vec<u8>> = self
            .all_transactions
            .iter()
            .map(|tx| rlp::encode(tx).to_vec())
            .collect();

        let rlp_uncles: Vec<u8> = rlp::encode_list(&self.uncles).to_vec();
        let rlp_uncles: VariableList<u8, MaxEncodedUnclesLength> = VariableList::from(rlp_uncles);

        let offset = <Vec<Vec<u8>> as Encode>::ssz_fixed_len()
            + <VariableList<u8, typenum::U131072> as Encode>::ssz_fixed_len();

        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&encoded_txs);
        encoder.append(&rlp_uncles);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

impl Decode for BlockBody {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);

        builder.register_type::<Vec<Vec<u8>>>()?;
        builder.register_type::<Vec<u8>>()?;

        let mut decoder = builder.build()?;

        let encoded_txs: Vec<Vec<u8>> = decoder.decode_next()?;
        let rlp_uncles: Vec<u8> = decoder.decode_next()?;

        let txs: Vec<Transaction> = encoded_txs
            .iter()
            .map(|bytes| {
                let tx: Transaction = rlp::decode(bytes).unwrap();
                tx
            })
            .collect();

        let uncles: VariableList<u8, MaxEncodedUnclesLength> = VariableList::from(rlp_uncles);
        let uncles: Vec<Header> = rlp::decode_list(&uncles);

        Ok(Self {
            all_transactions: txs,
            uncles,
        })
    }
}

impl Serialize for BlockBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let ssz_block_body = self.as_ssz_bytes();
        serializer.serialize_str(&format!("0x{}", hex::encode(ssz_block_body)))
    }
}

impl<'de> Deserialize<'de> for BlockBody {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let block_body = BlockBody::from_ssz_bytes(
            &hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(de::Error::custom)?,
        )
        .map_err(|_| de::Error::custom("Unable to ssz decode BlockBody bytes"))?;

        Ok(block_body)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable)]
#[serde(rename_all = "camelCase")]
pub struct AccessListEntry {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

#[derive(
    Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RlpEncodable, RlpDecodable,
)]
#[serde(rename_all = "camelCase")]
pub struct LegacyTransaction {
    pub nonce: U256,
    pub gas_price: U256,
    pub gas: U256,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub v: U64,
    pub r: U256,
    pub s: U256,
}

#[derive(Eq, Debug, Clone, PartialEq, Serialize, Deserialize, RlpDecodable, RlpEncodable)]
#[serde(rename_all = "camelCase")]
pub struct AccessListTransaction {
    pub chain_id: U256,
    pub nonce: U256,
    pub gas_price: U256,
    pub gas_limit: U256,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub access_list: Vec<AccessListEntry>,
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

#[derive(Eq, Debug, Clone, PartialEq, Serialize, Deserialize, RlpDecodable, RlpEncodable)]
#[serde(rename_all = "camelCase")]
pub struct EIP1559Transaction {
    pub chain_id: U256,
    pub nonce: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
    pub access_list: Vec<AccessListEntry>,
    pub y_parity: U64,
    pub r: U256,
    pub s: U256,
}

/// Type representing an ethereum transaction
#[derive(Eq, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Transaction {
    #[serde(rename = "0x0")]
    Legacy(LegacyTransaction),
    #[serde(rename = "0x1")]
    AccessList(AccessListTransaction),
    #[serde(rename = "0x2")]
    EIP1559(EIP1559Transaction),
}

#[derive(Eq, Hash, Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
/// The typed transaction ID
pub enum TransactionId {
    EIP1559 = 0x02,
    AccessList = 0x01,
    Legacy = 0x00,
}

impl TryFrom<u8> for TransactionId {
    type Error = DecoderError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            id if id == TransactionId::EIP1559 as u8 => Ok(Self::EIP1559),
            id if id == TransactionId::AccessList as u8 => Ok(Self::AccessList),
            id if (id & 0x80) != 0x00 => Ok(Self::Legacy),
            _ => Err(DecoderError::Custom(
                "Invalid byte selector for transaction type.",
            )),
        }
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        match self {
            Self::Legacy(tx) => {
                tx.rlp_append(s);
            }
            Self::AccessList(tx) => {
                (TransactionId::AccessList as u8).rlp_append(s);
                tx.rlp_append(s);
            }
            Self::EIP1559(tx) => {
                (TransactionId::EIP1559 as u8).rlp_append(s);
                tx.rlp_append(s);
            }
        }
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        // at least one byte needs to be present
        if rlp.is_empty() {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        let id = TransactionId::try_from(rlp.as_raw()[0])
            .map_err(|_| DecoderError::Custom("Unknown transaction id"))?;
        match id {
            TransactionId::EIP1559 => Ok(Self::EIP1559(rlp::decode(&rlp.as_raw()[1..])?)),
            TransactionId::AccessList => Ok(Self::AccessList(rlp::decode(&rlp.as_raw()[1..])?)),
            TransactionId::Legacy => Ok(Self::Legacy(rlp::decode(rlp.as_raw())?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;
    use rstest::rstest;
    use serde_json::json;

    // Encoded transactions generated from block 14764013
    const TX1: &str = "02f9035201668457ad3fe4851cd25659958304631494881d40237659c251811cec9c364ef91dc08d300c80b902e55f5755290000000000000000000000000000000000000000000000000000000000000080000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000136f6e65496e6368563446656544796e616d6963000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000011cc8b8cfdb883030000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000002843109459ec64000000000000000000000000f326e4de8f66a0bdc0970b79e0924e33c79f1915000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c82e95b6c8000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700000000000000000000000000000000000000000000000000000000979aedeb00000000000000000000000000000000000000000000000011f4c44ef64691ba00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000001c0000000000000003b6d034074c99f3f5331676f6aec2756e1f39b4fc029a83eab4991fe000000000000000000000000000000000000000000000000d4c001a0483403982ac32060b5f72505cef9ad80e0be4ace6e474db4dc958e9742a9c8a89f67af938d037a3c6d902c0369c5e7a6c192dfd60b4cea8089bd23bd08f168c8";
    const TX2: &str = "02f87901820436847c41b83e851f398a0fe6826d2294c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2880e92596fd629000084d0e30db0c080a032f695b1360bf53805ed9d2691b8dfb9a8359475a4a0e6f658d3bef18f95bd2aa03b4d36626c574c4314238f72596a0b6c9f25b568282fecf4db4f1e77aa610cef";
    const TX3: &str = "02f8b2018201c68480bf26298522b1f34f9182b5d79495ad61b0a150d79219dcf64e1e6cc01f0b64c4ce80b844095ea7b3000000000000000000000000881d40237659c251811cec9c364ef91dc08d300cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc001a038a32136c77eb9e81bff5bd620ab3e5efb49fa009039df0ee381463719f93b73a02997a3c639342f56c4093985fb1fcffe22d310ed86ee8a66e8cfad6f06cc8338";
    const TX4: &str = "02f904b5018201c7846a330b96851f8a7e38b98304ecd394881d40237659c251811cec9c364ef91dc08d300c80b904455f575529000000000000000000000000000000000000000000000000000000000000008000000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000000c307846656544796e616d69630000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000036000000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000000000000000000000000000000000000bff2873f00000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000001bf2c340000000000000000000000002acf35c9a3f4c5c3f4c78ef5fb64c3ee82f07c4500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000228aa77476c000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4800000000000000000000000095ad61b0a150d79219dcf64e1e6cc01f0b64c4ce00000000000000000000000000000000000000000000000000000000c7a17304000000000000000000000000000000000000000000fe30137375b8c39c8a555700000000000000000000000056178a0d5f301baf6cf3e1cd53d9863437345bf90000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ed6021c55398a3690c2ac3ae45c65decbd36c83d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000627d9b4901ffffffffffffffffffffffffffffffffffffff38758e89627d9ab30000000f0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000001bba36c2753466094d672305b48ba9f4138ca26324ea598c5bde3b2b6d0186a9841c0bc111cd1d1452e2c40179895bb9ef095003596e89e55a1dc3793129df0e88000000000000000000000000000000000000000000fe30137375b8c39c8a5557869584cd00000000000000000000000011ededebf63bef0ea2d2d071bdf88f71543ec6fb00000000000000000000000000000000000000000000005d39cafba7627d9ab4000000000000000000000000000000000000000000000000b0c080a0b47105e77f8f54501363e1197c88bfb7ad08168457228656085267e9c171bc87a022061ebf3549c12ceb22cf351b5443fdb3ff66822e28641f62d2a538e471d028";
    const TX5: &str = "02f8c00182113e85488e3003c385488e3003c38302896f9444283a0ed172410212762f8dce09e6ea27db830b83e147ecb84d0a0000000033799c715cbac2589a0cc6791a5409ce3547f1f1d00e058c79d0a72c7a5ae802895d5f90b6edbafc870fd348fba2a3d20000000034261d99cef3835800000000000000034fbc5bc2c001a0c40b05baa3d1c7b4e86d7a4558510aca525481b1168318e78e41544251e16c12a0705c682addcb379212870ab04b1a973e4e1fab4a4b0fe10046c700d83a0545d2";
    const TX6: &str = "02f904300182a3d685373af8d94885373af8d9488303f56794000000000035b5e5ad9019092c665357240f594e80b8c40000000e9f9076aeb011eeaab8bf0c6de75510128da95498e4b7e67f0000000000000000f79fc43494ce8a4613cb0b2a67a1b1207fd05d27002710000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000000000000000000000000000004d224452801aced8b2f0aebe155379bb5d594381000000000000000027a463bf7d808f0e000000000000002580b707d5f025b87e000000000000000000000000000000000000000000000000282e06b9a6b590d5f902faf9018394f79fc43494ce8a4613cb0b2a67a1b1207fd05d27f9016ba0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0406a0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0405a00000000000000000000000000000000000000000000000000000000000000048a09c04773acff4c5c42718bd0120c72761f458e43068a3961eb935577d1ed4effba00000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000047a0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0407a0136e0edbc21af44a15788a0aa7307a3a81c5300ecdd1b0f03230344d1aeb0408a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000004f859944d224452801aced8b2f0aebe155379bb5d594381f842a02cd9fc82425a6b359c4bb15ae29636d339e83bcfa49e02ed97ed949ebd2af66ba05ce5caccbd06bf94e383da1e424cdd9ef4c371e1cf5aa91fbed31c4320eba1e2f87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0201253027fac026aee58f7b09418e76d7cc44d80dbc60df41fff49090f910d6ca0773a7876937c5ed0f82d77c27cb4373ce23050c0426752349794d61a1fbf51c6a01f064f92372c844ba1cb3c63bf4c654d9a8580b0355025447769b3db4e26968cf89b94b011eeaab8bf0c6de75510128da95498e4b7e67ff884a0000000000000000000000000000000000000000000000000000000000000000ca00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000006a0000000000000000000000000000000000000000000000000000000000000000780a096ed4e12cc3eebeba39e5563ff1139617e967125794407a52140a0a76b6d731fa0581fa5d015a9a4eea9eb353e16a44ae4d0c11510409b6a4589e5fd1ff278ae3a";
    const TX7: &str = "f87083020778852aa7599fe283015f90944c875e8bd31969f4b753b3ab1611e29f270ba47e880ae53c4a5528c0008025a0cf87b29833f82179a1d3bf30127d9512f392e9ac17375133e0a3ffff05995aa2a0055ee353df5d12f046a2d041b11dffa3d0a166253f5bf05c1264b99b32ed88fa";
    const TX8: &str = "f8ac824ae9851e449a9400830186a094dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb00000000000000000000000088bd4648737098aa9096bfba765dec014d2a11c10000000000000000000000000000000000000000000000000000000010ea71c025a0b7d4735b245fc516206e34396896e30c5c76a76dc4b9e4116342297e5a324ec3a05f1597d8c66e0fadfd6b1bafbf0ad263aed9610f60210c3b78be85df5e816432";
    const TX9: &str = "f8ac824aea851e449a9400830186a094dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000000f893a99b0165d3c92bc7d578afbc2104500761a000000000000000000000000000000000000000000000000000000002f71ff0026a00fc557ecb386c2075114804f913a638f826c379ce6c875f01f0bc74a55a15b82a01a975031836a4bd0f9f84995277c1112f4efe515497897305e5cf03c5497c172";
    const TX10: &str = "02f8d5018303df9b85024d7d6c8085e8d4a51000830129bd94dac17f958d2ee523a2206206994597c13d831ec780b86423b872dd000000000000000000000000b24abf582bab677c3bc8aa60706d212284a35b510000000000000000000000007abe0ce388281d2acf297cb089caef3819b134480000000000000000000000000000000000000000000000000000002fcc3cce80c080a04e00eddba90216b710b07c3725523848b4bf7288cfbbcdc3f84d70fe11c3e36fa01a6cb515d48c3c60b8cebecc6994f5829d6a879c4cbb0de187856eb2c926be8f";
    const TX11: &str = "02f87701831d1e57850241ddf5c085e8d4a5100082f618940329eadd881a8684b20254ccb66c2ae46791e3578808c8dd7dcb7a600080c080a0749657d0c76b979aa9f9c83c2f6943c954bf8afaa8ca0b0db06cd6bd00c0358ba070b198a397d47089e368a8f3dc8446a15e960e4b71b2b12f5b77964c5d8fd49c";
    const TX12: &str = "02f87701830391ed85012a05f2008520c70cfd6b82520894520ae6107ce868e69558ae3424b2cd3369048b2788095cc584c23433c680c001a03794e57db633834aac5311cf0bb7cc9f8c34b9a80485b225eb61abc98869e001a06f134e07cbe905ca81f4e8d3f04c565494f796edd02bdec11991d5acc59ff3a2";
    const TX13: &str = "02f90534018219f284931405ec851e9bd9af618307a120945edd5f803b831b47715ad3e11a90dd244f0cd0a980b904c4c98075390000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000003e0000001010101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002600000000000000000000000723b92452ba80acd1bfd31e98693a5110001249e010408000b05020c070f090a0106030e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000f00000000000000000000000000000000000000000000000000000000025d005000000000000000000000000000000000000000000000000000000000025eb3a800000000000000000000000000000000000000000000000000000000025f4e9d0000000000000000000000000000000000000000000000000000000002616fa00000000000000000000000000000000000000000000000000000000002662a9000000000000000000000000000000000000000000000000000000000026dcbb000000000000000000000000000000000000000000000000000000000027409890000000000000000000000000000000000000000000000000000000002740989000000000000000000000000000000000000000000000000000000000274098900000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027621e400000000000000000000000000000000000000000000000000000000027818c00000000000000000000000000000000000000000000000000000000002920c5a0000000000000000000000000000000000000000000000000000000002920c5a00000000000000000000000000000000000000000000000000000000000000064d9ad85acc4d85b8edd0f07e4910b18c7f60798ea51a9f56deceebd2e3e5e50c6777638458fdcb09a990994bf4842e379bda7d460ebc813f042a23a74956bee22195759fbf4ab55c15d1fa9aacdd6e7775697b49c3a1375639216be095f0d17dabb4937871eea45cc53b22e383efae526f363b6408fe54214b7a7d5d7cd83426f2e73d0fdf8c24f9340e5166ac6f16d80f6aae43a8b7dbc578730e64816f5cc45ead065e26dbca6fdf3e7d564bc13123d0d8e9b8ec72ec0ac85a8633aec867c7000000000000000000000000000000000000000000000000000000000000000651904651ac1c8769ea7e9e143f28c4a57a6ac3b2098cceee5e180cd28b242bb15c379383a79cabfc7b7ac020cab51e07cfbeabdc9b08608aef4edb8c143f28406f728717c324bc6fdbc6f0bc5691169124a62d2c4f4a5c5398298406f5329a7110a4b7d3bd027ce822c3410c896d99a8352f0a816f81e22dd0ae4ddbf4370d6d5fd0adc258df3db664ac3db802aba7665b6d1562c751ca5e0bdd096a7ee2a73f538c88e9d9cc5432b62b32ffa90778e1f66aafa96b220f30aa960de47c2ed19fc001a05c99f4b3ee9e8db9c1f07230d06246dc129151cc7812113992563d5b34908c90a0040d0cefaf2a1eb400914c59e97c7b5adb93ee1225d92b24a51a1e0b2ce508c5";
    const TX14: &str = "02f8b4018337e8aa8477359400851e80355e008303291894a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb000000000000000000000000f841a830cd94f6f00be674c81f57d5fcbbee2857000000000000000000000000000000000000000000000000000000038869ffb0c001a096cac1bcd991d9503a57399a58bee1194f4a3a6a0d19b153de41e6fc9596757fa04e0675dc544bec595be34d0e39c8d263648e8e17d09b6d78824bef18b536e5e9";
    const TX15: &str = "02f8b4018317930e8477359400852fbaf3c2008303d09094a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb0000000000000000000000008954b57277a9d7260bb5535afa83d53bf343637c000000000000000000000000000000000000000000000000000000001e742c50c001a0c8702617b1a770e5794633b3a5f6dd33a73e0f7d8a6a5d0b896f2730cc434ba0a0322e4d1c9023b44018a62b636fc1c8161f21624ab38fda44ba940417e46d3236";
    const TX16: &str = "02f8b4018334dce88477359400851e80355e008303291894dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000004bb8adce5e7297f2d8c5a2302a68d65eb44158cd000000000000000000000000000000000000000000000000000000000d41fae9c080a041f221a5760e73d3fc8da88f7fe403bf77a6c73e3ed99f97b8cc6d987778ba9aa01bb10c3860a66bb15056d1f8a09ac99273cfde235cb70473b905d0491f26c7be";
    const TX17: &str = "02f8b4018317930f8477359400852fbaf3c2008303d0909488df592f8eb5d7bd38bfef7deb0fbc02cf3778a080b844a9059cbb0000000000000000000000004b7575ef97285f846c944eee2e155bd3ceb65343000000000000000000000000000000000000000000000025e320a2817417f400c080a00bf596f61796e79c557e0d22c1759598ac1dd087d17b897d8a78aaa35ac05b7ea04b9fa664b59577ecc288f1bb10ce093d8085e1bce1648272ec8845155ad588cb";
    const TX18: &str = "02f8d1010c847735940085202170e40083013f3e94084b1c3c81545d370f3634392de611caabff814880b864c47f00270000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000b68696c676572742e657468000000000000000000000000000000000000000000c001a04aced752908560cc21797496850e75ce2a1d106cb8253b40521f7447879d3d75a03e792044fec76604f516c3ee955af79c7b24a6c9639760ad81110329b6c2c0d1";
    const TX19: &str = "02f87201018477359400852ad741300082520894a090e606e30bd747d4e6245a1517ebe430f0057e878791c90b4cd41280c080a0a94c2c0391828e9b9b807fa9c1259cdb8b40ce5e223370271e9a59c9db6120f4a05bfe7aa8a8cdac5d906857a5504ea4ac8e67effb04302fb2957067d9bdd84723";
    const UNCLE: &str = "f90216f90213a09f9076aeb7438dc9e3927bbcff88b1980381d8a5591a5e2323759355dd9ef0a8a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea674fdde714fd979de3edf0f56aa9716b898ec8a0343afe56216c786a7da762b125afbab17f7087d4d91973c8882a14839faf7fd4a01dafcd8f132425d9193c8acf6f62276135cc97e6aff9018590ce10711d66684aa0f169809ffad04f682ea4ac33d7a4287609f133b0767ad873dafdfb755657f7d2b901007f6ef7b9b1b7ff57b7dd24dbfd5ddffe1c4597947b37bbfccf65a17f3df97f9bfe3cbfffdb6ff1503419ffdaea7fc5941fbaf92738affb07ca7f7fd1ffef6f29e5d2e1edff7dabfffbaf7f0f7d29e6e046f7fe056f586ff15b74f7a0e68e2ff1ff7b175db73f96f6e7d7ff88fb3e69fbb3fe3ef8febcefecf6f7deb313ca71f2c1fcefcbcbdf7bf056ee7ddb35be27df7e8f4dad7f703d9b2ffbf87f7cbcbd6d5f8f8befffbefe3aeff5f9f0fbdbffbc7bcfdbd4e3bfab1fe7bffffe53eedd785b3ff6cfec5b6df73d93f9f81a8fd66e597432f73eefbf9b59ebe936ff7a24238efaabdfef25afa7fdffbbe5bdf75badfc72efe1f97dc57e7fe9dfff5f5bdfa7873281e8bc688acd83e147ec8401c9c3808401c5a38f84627d9ae08a75732d77657374312d35a01598b74d7f90530f02c9035719061bfec794df6f5a4183aa95ba940c521472168845fe0e67ba2cd6b18517ba6d35fc";

    fn get_14764013_block_body() -> BlockBody {
        let txs: Vec<Transaction> = vec![
            rlp::decode(&hex::decode(TX1).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX2).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX3).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX4).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX5).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX6).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX7).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX8).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX9).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX10).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX11).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX12).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX13).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX14).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX15).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX16).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX17).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX18).unwrap()).unwrap(),
            rlp::decode(&hex::decode(TX19).unwrap()).unwrap(),
        ];
        let uncles_rlp = &hex::decode(UNCLE).unwrap();
        let uncles: Vec<Header> = rlp::decode_list(uncles_rlp);
        BlockBody {
            all_transactions: txs,
            uncles,
        }
    }

    #[test]
    fn test_tx_ser_de() {
        let tx = Transaction::Legacy(LegacyTransaction{
            nonce: 12_u64.into(),
            gas: 21000_u64.into(),
            gas_price: 20_000_000_000_u64.into(),
            to: hex!("727fc6a68321b754475c668a6abfb6e9e71c169a").into(),
            value: U256::from(10) * 1_000_000_000 * 1_000_000_000,
            data: hex!("a9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc971600000000000000000000015af1d78b58c4000").to_vec().into(),
            v: 40_u64.into(),
            r: hex!("be67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717").into(),
            s: hex!("2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718").into(),
        });

        let serialized = json!({
            "type": "0x0",
            "nonce": "0xc",
            "to": "0x727fc6a68321b754475c668a6abfb6e9e71c169a",
            "gas": "0x5208",
            "gasPrice":"0x4a817c800",
            "value":"0x8ac7230489e80000",
            "data":"0xa9059cbb000000000213ed0f886efd100b67c7e4ec0a85a7d20dc971600000000000000000000015af1d78b58c4000",
            "v":"0x28",
            "r":"0xbe67e0a07db67da8d446f76add590e54b6e92cb6b8f9835aeb67540579a27717",
            "s":"0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7bd718",
        });

        assert_eq!(serde_json::to_value(&tx).unwrap(), serialized);
        assert_eq!(
            serde_json::from_value::<Transaction>(serialized).unwrap(),
            tx
        );
    }

    // tx data from: https://etherscan.io/txs?block=14764013
    #[rstest]
    // Legacy
    #[case(TX7, 132984)]
    #[case(TX8, 19177)]
    #[case(TX9, 19178)]
    // EIP1559
    #[case(TX4, 455)]
    #[case(TX5, 4414)]
    #[case(TX17, 1544975)]
    // EIP1559 w/ populated access list
    #[case(TX6, 41942)]
    fn rlp_encode_decode_tx(#[case] tx: &str, #[case] expected_nonce: u32) {
        let tx_rlp = hex::decode(tx).unwrap();
        let tx: Transaction = rlp::decode(&tx_rlp).expect("error rlp decoding tx");
        let expected_nonce = U256::from(expected_nonce);

        match &tx {
            Transaction::Legacy(tx) => assert_eq!(tx.nonce, expected_nonce),
            Transaction::AccessList(tx) => assert_eq!(tx.nonce, expected_nonce),
            Transaction::EIP1559(tx) => assert_eq!(tx.nonce, expected_nonce),
        }
        let encoded_tx = rlp::encode(&tx);
        assert_eq!(hex::encode(tx_rlp), hex::encode(encoded_tx));
    }

    #[test]
    fn block_body_ssz_encode_decode() {
        let block_body = get_14764013_block_body();
        let encoded = block_body.as_ssz_bytes();
        let expected: Vec<u8> = std::fs::read("./src/assets/test/block_body_14764013.bin").unwrap();

        assert_eq!(hex::encode(&encoded), hex::encode(expected));

        let decoded = BlockBody::from_ssz_bytes(&encoded).unwrap();
        assert_eq!(block_body, decoded);
    }

    #[test]
    fn block_body_ser_de() {
        let block_body = get_14764013_block_body();
        let block_body_json = json!(format!("0x{}", hex::encode(block_body.as_ssz_bytes())));

        let block_body: BlockBody = serde_json::from_value(block_body_json.clone()).unwrap();

        assert_eq!(
            serde_json::to_string(&block_body_json).unwrap(),
            serde_json::to_string(&block_body).unwrap()
        )
    }

    #[test]
    fn block_body_validates_uncles_root() {
        let block_body = get_14764013_block_body();
        let expected_uncles_root =
            "58a694212e0416353a4d3865ccf475496b55af3a3d3b002057000741af973191".to_owned();
        assert_eq!(hex::encode(block_body.uncles_root()), expected_uncles_root);
    }

    #[test]
    fn block_body_roots_invalidates_uncles_root() {
        let block_body = get_14764013_block_body();
        // invalid uncles
        let uncles = vec![block_body.uncles[0].clone(), block_body.uncles[0].clone()];

        let invalid_block_body = BlockBody {
            all_transactions: block_body.all_transactions,
            uncles,
        };
        let expected_uncles_root =
            "58a694212e0416353a4d3865ccf475496b55af3a3d3b002057000741af973191".to_owned();

        assert_ne!(
            expected_uncles_root,
            hex::encode(invalid_block_body.uncles_root())
        );
    }

    #[test]
    fn block_body_validates_transactions_root() {
        let block_body = get_14764013_block_body();
        let expected_tx_root =
            "18a2978fc62cd1a23e90de920af68c0c3af3330327927cda4c005faccefb5ce7".to_owned();
        assert_eq!(
            hex::encode(block_body.transactions_root().unwrap()),
            expected_tx_root
        );
    }

    #[test]
    fn block_body_roots_invalidates_transactions_root() {
        let mut block_body = get_14764013_block_body();
        // invalid txs
        block_body.all_transactions.truncate(1);
        let invalid_block_body = BlockBody {
            all_transactions: block_body.all_transactions,
            uncles: block_body.uncles,
        };

        let expected_tx_root =
            "18a2978fc62cd1a23e90de920af68c0c3af3330327927cda4c005faccefb5ce7".to_owned();
        assert_ne!(
            expected_tx_root,
            hex::encode(invalid_block_body.transactions_root().unwrap())
        );
    }
}
