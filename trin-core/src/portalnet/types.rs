use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use base64;
use hex::FromHexError;
use rlp::Encodable;
use serde_json::Value;
use ssz;
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use thiserror::Error;

use super::overlay_service::OverlayRequestError;
use super::{Enr, U256};

pub type ByteList = VariableList<u8, typenum::U2048>;

#[derive(Error, Debug)]
pub enum MessageDecodeError {
    #[error("Failed to decode message from SSZ bytes")]
    Ssz,

    #[error("Unknown message id")]
    MessageId,

    #[error("Failed to decode message from empty bytes")]
    Empty,

    #[error("Invalid message type")]
    Type,
}

impl From<DecodeError> for MessageDecodeError {
    fn from(_err: DecodeError) -> Self {
        Self::Ssz
    }
}

#[derive(Error, Debug)]
pub enum DiscoveryRequestError {
    #[error("Invalid discv5 request message")]
    InvalidMessage,
}

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub private_key: Option<HexData>,
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
    pub internal_ip: bool,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            private_key: None,
            listen_port: 4242,
            bootnode_enrs: Vec::<Enr>::new(),
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
            internal_ip: false,
        }
    }
}

#[derive(Error, Debug)]
pub enum ProtocolIdError {
    #[error("Unable to decode protocol id to bytes: {0}")]
    Decode(FromHexError),

    #[error("invalid protocol id")]
    Invalid,
}

/// Protocol identifiers
#[derive(Debug, Clone)]
pub enum ProtocolId {
    State,
    History,
    TransactionGossip,
    HeaderGossip,
    CanonicalIndices,
    Utp,
}

/// Encode hex string to protocol id
impl FromStr for ProtocolId {
    type Err = ProtocolIdError;

    fn from_str(input: &str) -> Result<ProtocolId, Self::Err> {
        match input {
            "500A" => Ok(ProtocolId::State),
            "500B" => Ok(ProtocolId::History),
            "500C" => Ok(ProtocolId::TransactionGossip),
            "500D" => Ok(ProtocolId::HeaderGossip),
            "500E" => Ok(ProtocolId::CanonicalIndices),
            "757470" => Ok(ProtocolId::Utp),
            _ => Err(ProtocolIdError::Invalid),
        }
    }
}

/// Decode ProtocolId to raw bytes
impl TryFrom<ProtocolId> for Vec<u8> {
    type Error = ProtocolIdError;

    fn try_from(protocol_id: ProtocolId) -> Result<Self, Self::Error> {
        let bytes = match protocol_id {
            ProtocolId::State => hex::decode("500A"),
            ProtocolId::History => hex::decode("500B"),
            ProtocolId::TransactionGossip => hex::decode("500C"),
            ProtocolId::HeaderGossip => hex::decode("500D"),
            ProtocolId::CanonicalIndices => hex::decode("500E"),
            ProtocolId::Utp => hex::decode("757470"),
        };

        match bytes {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(ProtocolIdError::Decode(e)),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ProtocolMessage {
    message_id: u8,
    encoded_message: Message,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Message {
    Request(Request),
    Response(Response),
}

impl Message {
    /// Return the byte representation of the Message by prefixing the `message_id`
    /// with the message payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Message::Request(req) => {
                let mut payload = vec![req.message_id()];
                match req {
                    Request::Ping(p) => payload.append(&mut p.as_ssz_bytes()),
                    Request::FindNodes(p) => payload.append(&mut p.as_ssz_bytes()),
                    Request::FindContent(p) => payload.append(&mut p.as_ssz_bytes()),
                }
                payload
            }
            Message::Response(resp) => {
                let mut payload = vec![resp.message_id()];
                match resp {
                    Response::Pong(p) => payload.append(&mut p.as_ssz_bytes()),
                    Response::Nodes(p) => payload.append(&mut p.as_ssz_bytes()),
                    Response::FoundContent(p) => payload.append(&mut p.as_ssz_bytes()),
                }
                payload
            }
        }
    }

    /// Decode a `Message` type from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageDecodeError> {
        if let Some(message_id) = bytes.first() {
            match message_id {
                // Requests
                1 => Ok(Message::Request(Request::Ping(
                    Ping::from_ssz_bytes(&bytes[1..]).map_err(|e| MessageDecodeError::from(e))?,
                ))),
                3 => Ok(Message::Request(Request::FindNodes(
                    FindNodes::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| MessageDecodeError::from(e))?,
                ))),
                5 => Ok(Message::Request(Request::FindContent(
                    FindContent::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| MessageDecodeError::from(e))?,
                ))),
                2 => Ok(Message::Response(Response::Pong(
                    Pong::from_ssz_bytes(&bytes[1..]).map_err(|e| MessageDecodeError::from(e))?,
                ))),
                4 => Ok(Message::Response(Response::Nodes(
                    Nodes::from_ssz_bytes(&bytes[1..]).map_err(|e| MessageDecodeError::from(e))?,
                ))),
                6 => Ok(Message::Response(Response::FoundContent(
                    FoundContent::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| MessageDecodeError::from(e))?,
                ))),
                _ => Err(MessageDecodeError::MessageId),
            }
        } else {
            Err(MessageDecodeError::Empty)
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Request {
    Ping(Ping),
    FindNodes(FindNodes),
    FindContent(FindContent),
}

impl Request {
    fn message_id(&self) -> u8 {
        match self {
            Request::Ping(_) => 1,
            Request::FindNodes(_) => 3,
            Request::FindContent(_) => 5,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Response {
    Pong(Pong),
    Nodes(Nodes),
    FoundContent(FoundContent),
}

impl Response {
    fn message_id(&self) -> u8 {
        match self {
            Response::Pong(_) => 2,
            Response::Nodes(_) => 4,
            Response::FoundContent(_) => 6,
        }
    }
}

/// Custom payload element of Ping and Pong messages
#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct CustomPayload;

impl CustomPayload {
    pub fn new(payload: Vec<u8>) -> ByteList {
        let ssz_list = VariableList::from(payload);
        ByteList::from(ssz_list)
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Ping {
    pub enr_seq: u64,
    pub custom_payload: ByteList,
}

impl fmt::Display for Ping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ping(enr_seq={}, radius={})",
            self.enr_seq,
            hex::encode(self.custom_payload.as_ssz_bytes())
        )
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Pong {
    pub enr_seq: u64,
    pub custom_payload: ByteList,
}

impl fmt::Display for Pong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pong(enr_seq={}, radius={})",
            self.enr_seq,
            hex::encode(self.custom_payload.as_ssz_bytes())
        )
    }
}

impl TryFrom<&Vec<u8>> for Pong {
    type Error = OverlayRequestError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() == 0 {
            return Err(OverlayRequestError::EmptyResponse);
        }
        let message = match Message::from_bytes(&value) {
            Ok(val) => val,
            Err(_) => return Err(OverlayRequestError::DecodeError),
        };
        let response = match message {
            Message::Response(val) => val,
            _ => return Err(OverlayRequestError::InvalidResponse),
        };
        match response {
            Response::Pong(val) => Ok(val),
            _ => return Err(OverlayRequestError::InvalidResponse),
        }
    }
}

impl TryInto<Value> for Pong {
    type Error = String;

    fn try_into(self) -> Result<Value, Self::Error> {
        match self.payload {
            Some(val) => Ok(Value::String(format!("{:?}", val))),
            None => Err("Invalid pong payload: None".to_owned()),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct FindNodes {
    // TODO: Make this an ssz list
    pub distances: Vec<u16>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Nodes {
    pub total: u8,
    pub enrs: Vec<SszEnr>,
}

#[derive(Debug, Encode, Decode)]
struct NodesHelper {
    total: u8,
    enrs: Vec<Vec<u8>>,
}

impl From<&Nodes> for NodesHelper {
    fn from(nodes: &Nodes) -> Self {
        Self {
            total: nodes.total,
            enrs: nodes
                .enrs
                .iter()
                .map(|enr| enr.rlp_bytes().to_vec())
                .collect(),
        }
    }
}

impl TryFrom<NodesHelper> for Nodes {
    type Error = DecodeError;

    fn try_from(helper: NodesHelper) -> Result<Self, Self::Error> {
        let enrs: Vec<Enr> = helper
            .enrs
            .into_iter()
            .map(|bytes| {
                rlp::decode(&bytes)
                    .map_err(|e| DecodeError::BytesInvalid(format!("rlp decoding failed: {}", e)))
            })
            .collect::<Result<_, _>>()?;

        let enrs: Vec<SszEnr> = enrs
            .iter()
            .map(|enr| SszEnr::new(enr.clone()))
            .collect::<Vec<SszEnr>>();
        Ok(Self {
            total: helper.total,
            enrs,
        })
    }
}

// TODO: check correctness and if there's a better way
// to impl Encode
impl ssz::Encode for Nodes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        NodesHelper::from(self).ssz_append(buf)
    }

    fn ssz_bytes_len(&self) -> usize {
        self.as_ssz_bytes().len()
    }
}

// TODO: check correctness and if there's a better way
// to impl Decode
impl ssz::Decode for Nodes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        NodesHelper::from_ssz_bytes(bytes)?.try_into()
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct FindContent {
    // TODO: Use some version of H256
    pub content_key: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct FoundContent {
    pub connection_id: Option<u16>,
    pub enrs: Option<Vec<SszEnr>>,
    pub content: Option<ByteList>,
    // private field used to enforce struct initialization via new()
    union_flag: bool,
}

impl FoundContent {
    // Enforce union-like behavior for FoundContent
    pub fn new(
        connection_id: Option<u16>,
        enrs: Option<Vec<SszEnr>>,
        content: Option<ByteList>,
    ) -> Self {
        let mut count = 0;
        if connection_id.is_some() {
            count += 1;
        }
        if enrs.is_some() {
            count += 1;
        }
        if content.is_some() {
            count += 1;
        }
        match count {
            1 => Self {
                connection_id,
                enrs,
                content,
                union_flag: true,
            },
            _ => panic!("Invalid fields for FoundContent union."),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SszEnr(Enr);

impl SszEnr {
    pub fn new(enr: Enr) -> SszEnr {
        SszEnr(enr)
    }
}

impl Deref for SszEnr {
    type Target = Enr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SszEnr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl ssz::Decode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let string = base64::encode_config(&bytes, base64::URL_SAFE);
        Ok(SszEnr(Enr::from_str(&string).unwrap()))
    }
}

impl ssz::Encode for SszEnr {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.rlp_bytes().to_vec());
    }

    fn ssz_bytes_len(&self) -> usize {
        self.rlp_bytes().to_vec().ssz_bytes_len()
    }
}

// custom type required for special union ssz encoding/decoding
// not supported in ssz library
pub struct UnionVecEnr {
    enrs: Vec<SszEnr>,
}

impl UnionVecEnr {
    pub fn new(enrs: Vec<SszEnr>) -> Self {
        Self { enrs }
    }
}

impl ssz::Encode for UnionVecEnr {
    fn ssz_bytes_len(&self) -> usize {
        self.enrs.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.enrs.ssz_append(buf)
    }

    // this is true so var offset is not encoded, which is not used in unions
    fn is_ssz_fixed_len() -> bool {
        true
    }
}

impl ssz::Decode for UnionVecEnr {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        // this is a hack to transform union -> container by adding var length offset
        let mut thing: Vec<u8> = vec![4u8, 0u8, 0u8, 0u8];
        thing.extend_from_slice(bytes);
        let mut builder = SszDecoderBuilder::new(&thing);
        builder.register_type::<Vec<SszEnr>>().unwrap();
        let mut decoder = builder.build()?;
        Ok(Self {
            enrs: decoder.decode_next()?,
        })
    }
}

// custom type required for special union ssz encoding/decoding
// not supported in ssz library
pub struct UnionByteList {
    content: ByteList,
}

impl UnionByteList {
    pub fn new(content: ByteList) -> Self {
        Self { content }
    }
}

impl ssz::Encode for UnionByteList {
    fn ssz_bytes_len(&self) -> usize {
        self.content.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        self.content.ssz_append(buf)
    }

    // this is true so var offset is not encoded, which is not used in unions
    fn is_ssz_fixed_len() -> bool {
        true
    }
}

impl ssz::Encode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        if self.enrs.is_some() {
            let offset = <u8 as Encode>::ssz_fixed_len() + <Vec<SszEnr> as Encode>::ssz_fixed_len();
            let mut encoder = SszEncoder::container(buf, offset);
            let enrs = UnionVecEnr::new(self.enrs.clone().unwrap());
            // append union selector flag and then content
            encoder.append(&2u8);
            encoder.append(&enrs);
            encoder.finalize();
        } else if self.content.is_some() {
            let offset = <u8 as Encode>::ssz_fixed_len() + <ByteList as Encode>::ssz_fixed_len();
            let mut encoder = SszEncoder::container(buf, offset);
            let union_content: UnionByteList = UnionByteList::new(self.content.clone().unwrap());
            // append union selector flag and then content
            encoder.append(&1u8);
            encoder.append(&union_content);
            encoder.finalize();
        } else if self.connection_id.is_some() {
            let offset = <u16 as Encode>::ssz_fixed_len();
            let mut encoder = SszEncoder::container(buf, offset);
            // append union selector flag and then content
            encoder.append(&0u8);
            encoder.append(self.connection_id.as_ref().unwrap());
            encoder.finalize();
        } else {
            panic!("Invalid FoundContent union: cannot convert to bytes.")
        }
    }

    fn ssz_bytes_len(&self) -> usize {
        if self.enrs.is_some() {
            self.enrs.as_ref().unwrap().ssz_bytes_len()
        } else {
            self.content.as_ref().unwrap().ssz_bytes_len()
        }
    }
}

impl ssz::Decode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let (flag, bytes) = bytes.split_at(1);

        match flag {
            [0u8] => {
                // write tests for these
                let result = match bytes.len() {
                    2 => u16::from_le_bytes([bytes[0], bytes[1]]),
                    _ => {
                        return Err(DecodeError::BytesInvalid(format!(
                            "Invalid connection id: {:?}",
                            bytes
                        )))
                    }
                };
                Ok(Self::new(Some(result), None, None))
            }
            [1u8] => {
                let result = ByteList::from(VariableList::from(bytes.to_vec()));
                Ok(Self::new(None, None, Some(result)))
            }
            [2u8] => {
                let result = <UnionVecEnr as ssz::Decode>::from_ssz_bytes(bytes).unwrap();
                Ok(Self::new(None, Some(result.enrs), None))
            }
            _ => Err(DecodeError::BytesInvalid(format!(
                "Invalid FoundContent union type flag: {:?}",
                flag
            ))),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct HexData(pub Vec<u8>);

impl FromStr for HexData {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::decode(s).map(HexData)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use discv5::enr::{CombinedKey, EnrBuilder};
    use rstest::rstest;
    use std::net::Ipv4Addr;

    fn enr_one_key() -> CombinedKey {
        CombinedKey::secp256k1_from_bytes(vec![1; 32].as_mut_slice()).unwrap()
    }

    fn enr_two_key() -> CombinedKey {
        CombinedKey::secp256k1_from_bytes(vec![2; 32].as_mut_slice()).unwrap()
    }

    fn build_enr(enr_key: CombinedKey) -> Enr {
        let ip = Ipv4Addr::new(192, 168, 0, 1);
        EnrBuilder::new("v4")
            .ip(ip.into())
            .tcp(8000)
            .build(&enr_key)
            .unwrap()
    }

    #[rstest]
    #[case(None, None, None)]
    #[case(Some(0u16), None, Some(ByteList::from(VariableList::from(vec![0u8]))))]
    #[should_panic(expected = "Invalid fields for FoundContent union.")]
    fn test_found_content_enforces_union_behavior(
        #[case] connection_id: Option<u16>,
        #[case] enrs: Option<Vec<SszEnr>>,
        #[case] content: Option<ByteList>,
    ) {
        FoundContent::new(connection_id, enrs, content);
    }

    #[test]
    fn test_found_content_encodes_content() {
        let some_content = Some(ByteList::from(VariableList::from(vec![1; 33])));
        let msg = FoundContent::new(None, None, some_content.clone());
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.content, some_content);
        // add one to account for union flag byte
        assert_eq!(actual.len(), msg.ssz_bytes_len() + 1);
    }

    #[test]
    fn test_found_content_encodes_single_enr() {
        let enr = build_enr(enr_one_key());
        let msg = FoundContent::new(None, Some(vec![SszEnr(enr.clone())]), None);
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert!(SszEnr(enr).eq(decoded.enrs.unwrap().first().unwrap()));
        // add one to account for union flag byte
        assert_eq!(actual.len(), msg.ssz_bytes_len() + 1);
    }

    #[test]
    fn test_found_content_encodes_double_enrs() {
        let enr_one = build_enr(enr_one_key());
        let enr_two = build_enr(enr_two_key());

        let msg = FoundContent::new(
            None,
            Some(vec![SszEnr(enr_one.clone()), SszEnr(enr_two.clone())]),
            None,
        );
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert!(SszEnr(enr_one).eq(decoded.enrs.as_ref().unwrap().first().unwrap()));
        assert!(SszEnr(enr_two).eq(&decoded.enrs.unwrap().into_iter().nth(1).unwrap()));
        // add one to account for union flag byte
        assert_eq!(actual.len(), msg.ssz_bytes_len() + 1);
    }

    #[test]
    fn test_nodes_encodes_empty() {
        let empty_enrs: Vec<SszEnr> = vec![];
        let total: u8 = 0;
        let msg = Nodes {
            enrs: empty_enrs.clone(),
            total,
        };
        let actual = msg.as_ssz_bytes();
        let decoded = Nodes::from_ssz_bytes(&actual).unwrap();

        assert_eq!(decoded, msg);
        assert_eq!(decoded.enrs, empty_enrs);
        assert_eq!(decoded.total, 0);
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_nodes_encodes_single_enr() {
        let enr = build_enr(enr_one_key());
        let total: u8 = 1;
        let msg = Nodes {
            enrs: vec![SszEnr(enr.clone())],
            total,
        };
        let actual = msg.as_ssz_bytes();
        let decoded = Nodes::from_ssz_bytes(&actual).unwrap();

        assert_eq!(decoded, msg);
        assert!(enr.eq(decoded.enrs.first().unwrap()));
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_nodes_encodes_double_enrs() {
        let enr_one = build_enr(enr_one_key());
        let enr_two = build_enr(enr_two_key());
        let total: u8 = 1;
        let msg = Nodes {
            enrs: vec![SszEnr(enr_one.clone()), SszEnr(enr_two.clone())],
            total,
        };
        let actual = msg.as_ssz_bytes();
        let decoded = Nodes::from_ssz_bytes(&actual).unwrap();

        assert_eq!(decoded, msg);
        assert!(enr_one.eq(decoded.enrs.first().unwrap()));
        assert!(enr_two.eq(&decoded.enrs.into_iter().nth(1).unwrap()));
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn protocol_id_encode_decode() {
        let original_hex = "500A";
        let protocol_id = ProtocolId::from_str(original_hex).unwrap();
        let expected_hex = hex::encode_upper(Vec::try_from(protocol_id).unwrap());

        assert_eq!(original_hex, expected_hex);
    }

    #[test]
    #[should_panic]
    fn invalid_protocol_id() {
        let hex_string = "500F";
        ProtocolId::from_str(hex_string).unwrap();
    }

    // test vectors sourced from
    // https://github.com/ethereum/portal-network-specs/blob/master/portal-wire-test-vectors.md
    #[test]
    fn test_vector_ping() {
        let enr_seq = 1u64;
        let data_radius = U256::MAX - U256::from(1);
        let custom_payload = CustomPayload::new(data_radius.as_ssz_bytes());
        let expected = "0101000000000000000c000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let message = Message::Request(Request::Ping(Ping {
            enr_seq,
            custom_payload,
        }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_pong() {
        let enr_seq = 1;
        let data_radius: U256 = U256::max_value() / 2;
        let custom_payload = CustomPayload::new(data_radius.as_ssz_bytes());
        let expected = "0201000000000000000c000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        let message = Message::Response(Response::Pong(Pong {
            enr_seq,
            custom_payload,
        }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_find_nodes() {
        let distances = vec![256, 255];
        let expected = "03040000000001ff00";
        let message = Message::Request(Request::FindNodes(FindNodes { distances }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_nodes_empty() {
        let enrs = vec![];
        let total = 1;
        let expected = "040105000000";
        let message = Message::Response(Response::Nodes(Nodes { total, enrs }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_nodes_multiple_enrs() {
        let enr_one = SszEnr(Enr::from_str("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg").unwrap());
        let enr_two = SszEnr(Enr::from_str("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU").unwrap());
        let enrs = vec![enr_one, enr_two];
        let total = 1;
        let expected = "040105000000080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        let message = Message::Response(Response::Nodes(Nodes { total, enrs }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_find_content() {
        let content_key = hex::decode("706f7274616c").unwrap();
        let expected = "0504000000706f7274616c";
        let message = Message::Request(Request::FindContent(FindContent { content_key }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_found_content_connection_id() {
        let raw = [01u8, 02u8];
        let connection_id = Some(u16::from_le_bytes(raw));
        let expected = "06000102";
        let message = Message::Response(Response::FoundContent(FoundContent::new(
            connection_id,
            None,
            None,
        )));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_found_content_content() {
        let content = Some(ByteList::from(VariableList::from(
            hex::decode("7468652063616b652069732061206c6965").unwrap(),
        )));
        let expected = "06017468652063616b652069732061206c6965";
        let message = Message::Response(Response::FoundContent(FoundContent::new(
            None, None, content,
        )));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_found_content_enrs() {
        let enr_one = SszEnr(Enr::from_str("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg").unwrap());
        let enr_two = SszEnr(Enr::from_str("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU").unwrap());
        let enrs = Some(vec![enr_one, enr_two]);
        let expected = "0602080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        let message =
            Message::Response(Response::FoundContent(FoundContent::new(None, enrs, None)));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }
}
