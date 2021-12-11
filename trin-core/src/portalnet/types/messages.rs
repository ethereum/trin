use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use base64;
use hex::FromHexError;
use rlp::Encodable;
use serde_json::Value;
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};
use thiserror::Error;

use crate::portalnet::overlay_service::OverlayRequestError;
use crate::portalnet::{types::uint::U256, Enr};

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
                    Response::Content(p) => payload.append(&mut p.as_ssz_bytes()),
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
                0 => Ok(Message::Request(Request::Ping(
                    Ping::from_ssz_bytes(&bytes[1..]).map_err(|e| MessageDecodeError::from(e))?,
                ))),
                2 => Ok(Message::Request(Request::FindNodes(
                    FindNodes::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| MessageDecodeError::from(e))?,
                ))),
                4 => Ok(Message::Request(Request::FindContent(
                    FindContent::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| MessageDecodeError::from(e))?,
                ))),
                1 => Ok(Message::Response(Response::Pong(
                    Pong::from_ssz_bytes(&bytes[1..]).map_err(|e| MessageDecodeError::from(e))?,
                ))),
                3 => Ok(Message::Response(Response::Nodes(
                    Nodes::from_ssz_bytes(&bytes[1..]).map_err(|e| MessageDecodeError::from(e))?,
                ))),
                5 => Ok(Message::Response(Response::Content(
                    Content::from_ssz_bytes(&bytes[1..])
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
            Request::Ping(_) => 0,
            Request::FindNodes(_) => 2,
            Request::FindContent(_) => 4,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Response {
    Pong(Pong),
    Nodes(Nodes),
    Content(Content),
}

impl Response {
    fn message_id(&self) -> u8 {
        match self {
            Response::Pong(_) => 1,
            Response::Nodes(_) => 3,
            Response::Content(_) => 5,
        }
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

impl Into<Value> for Pong {
    fn into(self) -> Value {
        Value::String(format!("{:?}", self.custom_payload))
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

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum Content {
    ConnectionId(u16),
    Content(ByteList),
    Enrs(Vec<SszEnr>),
}

impl Content {
    pub fn connection_id(self) -> Result<u16, MessageDecodeError> {
        if let Content::ConnectionId(val) = self {
            Ok(val)
        } else {
            Err(MessageDecodeError::Type)
        }
    }

    pub fn content(self) -> Result<ByteList, MessageDecodeError> {
        if let Content::Content(val) = self {
            Ok(val)
        } else {
            Err(MessageDecodeError::Type)
        }
    }

    pub fn enrs(self) -> Result<Vec<SszEnr>, MessageDecodeError> {
        if let Content::Enrs(val) = self {
            Ok(val)
        } else {
            Err(MessageDecodeError::Type)
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

    #[test]
    fn test_content_encodes_content() {
        let some_content = ByteList::from(VariableList::from(vec![1; 33]));
        let msg = Content::Content(some_content.clone());
        let actual = msg.as_ssz_bytes();
        let decoded = Content::from_ssz_bytes(&actual).unwrap();
        assert_eq!(decoded.content().unwrap(), some_content);
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_content_encodes_single_enr() {
        let enr = build_enr(enr_one_key());
        let msg = Content::Enrs(vec![SszEnr(enr.clone())]);
        let actual = msg.as_ssz_bytes();
        let decoded = Content::from_ssz_bytes(&actual).unwrap();
        assert!(SszEnr(enr).eq(decoded.enrs().unwrap().first().unwrap()));
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_content_encodes_double_enrs() {
        let enr_one = build_enr(enr_one_key());
        let enr_two = build_enr(enr_two_key());

        let msg = Content::Enrs(vec![SszEnr(enr_one.clone()), SszEnr(enr_two.clone())]);
        let actual = msg.as_ssz_bytes();
        let decoded_enrs = Content::from_ssz_bytes(&actual).unwrap().enrs().unwrap();
        assert!(SszEnr(enr_one).eq(decoded_enrs.first().unwrap()));
        assert!(SszEnr(enr_two).eq(&decoded_enrs.into_iter().nth(1).unwrap()));
        assert_eq!(actual.len(), msg.ssz_bytes_len());
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
        let custom_payload = ByteList::from(data_radius.as_ssz_bytes());
        let expected = "0001000000000000000c000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
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
        let custom_payload = ByteList::from(data_radius.as_ssz_bytes());
        let expected = "0101000000000000000c000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
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
        let expected = "02040000000001ff00";
        let message = Message::Request(Request::FindNodes(FindNodes { distances }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_nodes_empty() {
        let enrs = vec![];
        let total = 1;
        let expected = "030105000000";
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
        let expected = "030105000000080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        let message = Message::Response(Response::Nodes(Nodes { total, enrs }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_find_content() {
        let content_key = hex::decode("706f7274616c").unwrap();
        let expected = "0404000000706f7274616c";
        let message = Message::Request(Request::FindContent(FindContent { content_key }));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_content_with_connection_id() {
        let raw = [01u8, 02u8];
        let connection_id = u16::from_le_bytes(raw);
        let expected = "05000102";
        let message = Message::Response(Response::Content(Content::ConnectionId(connection_id)));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_content_with_content() {
        let content = ByteList::from(VariableList::from(
            hex::decode("7468652063616b652069732061206c6965").unwrap(),
        ));
        let expected = "05017468652063616b652069732061206c6965";
        let message = Message::Response(Response::Content(Content::Content(content)));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_vector_content_with_enrs() {
        let enr_one = SszEnr(Enr::from_str("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg").unwrap());
        let enr_two = SszEnr(Enr::from_str("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU").unwrap());
        let enrs = vec![enr_one, enr_two];
        let expected = "0502080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        let message = Message::Response(Response::Content(Content::Enrs(enrs)));
        assert_eq!(hex::encode(message.to_bytes()), expected);
        let decoded = Message::from_bytes(message.to_bytes().as_slice()).unwrap();
        assert_eq!(decoded, message);
    }
}
