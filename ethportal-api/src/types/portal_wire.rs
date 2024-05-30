use std::{
    convert::{TryFrom, TryInto},
    fmt,
    ops::Deref,
    sync::Arc,
};

use alloy_primitives::U256;
use bimap::BiHashMap;
use once_cell::sync::Lazy;
use rlp::Encodable;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, BitList};
use thiserror::Error;
use validator::ValidationError;

use crate::{
    types::{
        bytes::ByteList2048,
        distance::Distance,
        enr::{Enr, SszEnr},
    },
    utils::bytes::{hex_decode, hex_encode, ByteUtilsError},
    RawContentKey,
};

/// The maximum size of a Discv5 packet.
pub(crate) const MAX_DISCV5_PACKET_SIZE: usize = 1280;

/// The maximum size of a Discv5 talk request payload.
///
/// Discv5 talk request overhead:
///   * masking IV length: 16
///   * static header (protocol ID || version || flag || nonce || authdata-size) length: 23
///   * authdata length: 32
///   * HMAC length: 16
///   * (max) talk request ID length: 8
///   * (max assumed) talk request protocol length: 8
///   * RLP byte array overhead: 6
pub(crate) const MAX_DISCV5_TALK_REQ_PAYLOAD_SIZE: usize =
    MAX_DISCV5_PACKET_SIZE - 16 - 23 - 32 - 16 - 8 - 8 - 6;

// NOTE: The wire constants below rely on the following SSZ constants:
//   * `ssz::BYTES_PER_UNION_SELECTOR`: 1
//   * `ssz::BYTES_PER_LENGTH_OFFSET`: 4

/// The maximum size of a portal NODES `enrs` payload.
///
/// Portal wire overhead:
///   * portal message SSZ union selector
///   * NODES `total` field: 1
///   * NODES SSZ length offset for List `enrs`
pub const MAX_PORTAL_NODES_ENRS_SIZE: usize = MAX_DISCV5_TALK_REQ_PAYLOAD_SIZE
    - ssz::BYTES_PER_UNION_SELECTOR
    - 1
    - ssz::BYTES_PER_LENGTH_OFFSET;

/// The maximum size of a portal CONTENT payload. At the time of writing, this payload either
/// corresponds to a `connection_id`, `enrs`, or `content` payload.
///
/// Portal wire overhead:
///   * portal message SSZ union selector
///   * CONTENT SSZ union selector
///   * CONTENT SSZ length offset for List `enrs` or `content`
pub const MAX_PORTAL_CONTENT_PAYLOAD_SIZE: usize = MAX_DISCV5_TALK_REQ_PAYLOAD_SIZE
    - (ssz::BYTES_PER_UNION_SELECTOR * 2)
    - ssz::BYTES_PER_LENGTH_OFFSET;

/// Custom payload element of Ping and Pong overlay messages
#[derive(Debug, PartialEq, Clone)]
pub struct CustomPayload {
    payload: ByteList2048,
}

impl TryFrom<&Value> for CustomPayload {
    type Error = ValidationError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let value = value
            .as_str()
            .ok_or_else(|| ValidationError::new("Custom payload value is not a string!"))?;
        let payload = match hex_decode(value) {
            Ok(payload) => payload,
            Err(_) => Err(ValidationError::new(
                "Unable to decode hex payload into bytes",
            ))?,
        };
        Ok(Self {
            payload: ByteList2048::from(payload),
        })
    }
}

impl From<Vec<u8>> for CustomPayload {
    fn from(ssz_bytes: Vec<u8>) -> Self {
        Self {
            payload: ByteList2048::from(ssz_bytes),
        }
    }
}

impl From<CustomPayload> for Distance {
    fn from(val: CustomPayload) -> Self {
        let bytes = val.payload;
        U256::from_le_slice(bytes.deref()).into()
    }
}

impl ssz::Decode for CustomPayload {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Self {
            payload: ByteList2048::from(bytes.to_vec()),
        })
    }
}

impl ssz::Encode for CustomPayload {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.append(&mut self.payload.as_ssz_bytes());
    }

    fn ssz_bytes_len(&self) -> usize {
        self.payload.as_ssz_bytes().len()
    }
}

#[derive(Error, Debug)]
pub enum MessageDecodeError {
    #[error("Failed to decode message from SSZ bytes")]
    Ssz { decode_err: DecodeError },

    #[error("Unknown message id")]
    MessageId,

    #[error("Failed to decode message from empty bytes")]
    Empty,

    #[error("Invalid message type")]
    Type,
}

#[derive(Error, Debug)]
pub enum DiscoveryRequestError {
    #[error("Invalid discv5 request message")]
    InvalidMessage,
}

#[derive(Error, Debug)]
pub enum ProtocolIdError {
    #[error("Unable to decode protocol id to bytes")]
    Decode(ByteUtilsError),

    #[error("invalid protocol id")]
    Invalid,
}

/// Protocol identifiers
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProtocolId {
    State,
    VerkleState,
    History,
    TransactionGossip,
    CanonicalIndices,
    Beacon,
    Utp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkSpec {
    network_name: String,
    portal_networks: BiHashMap<ProtocolId, String>,
}

impl NetworkSpec {
    pub fn get_network_name(&self) -> &str {
        &self.network_name
    }

    pub fn get_protocol_id_from_hex(&self, hex: &str) -> Result<ProtocolId, ProtocolIdError> {
        self.portal_networks
            .get_by_right(hex)
            .copied()
            .ok_or(ProtocolIdError::Invalid)
    }

    pub fn get_protocol_hex_from_id(
        &self,
        protocol_id: &ProtocolId,
    ) -> Result<String, ProtocolIdError> {
        self.portal_networks
            .get_by_left(protocol_id)
            .cloned()
            .ok_or(ProtocolIdError::Invalid)
    }
}

pub static MAINNET: Lazy<Arc<NetworkSpec>> = Lazy::new(|| {
    let mut portal_networks = BiHashMap::new();
    portal_networks.insert(ProtocolId::State, "0x500A".to_string());
    portal_networks.insert(ProtocolId::History, "0x500B".to_string());
    portal_networks.insert(ProtocolId::Beacon, "0x500C".to_string());
    portal_networks.insert(ProtocolId::CanonicalIndices, "0x500D".to_string());
    portal_networks.insert(ProtocolId::VerkleState, "0x500E".to_string());
    portal_networks.insert(ProtocolId::TransactionGossip, "0x500F".to_string());
    portal_networks.insert(ProtocolId::Utp, "0x757470".to_string());
    NetworkSpec {
        portal_networks,
        network_name: "mainnet".to_string(),
    }
    .into()
});

pub static ANGELFOOD: Lazy<Arc<NetworkSpec>> = Lazy::new(|| {
    let mut portal_networks = BiHashMap::new();
    portal_networks.insert(ProtocolId::State, "0x504A".to_string());
    portal_networks.insert(ProtocolId::History, "0x504B".to_string());
    portal_networks.insert(ProtocolId::Beacon, "0x504C".to_string());
    portal_networks.insert(ProtocolId::CanonicalIndices, "0x504D".to_string());
    portal_networks.insert(ProtocolId::VerkleState, "0x504E".to_string());
    portal_networks.insert(ProtocolId::TransactionGossip, "0x504F".to_string());
    portal_networks.insert(ProtocolId::Utp, "0x757470".to_string());
    NetworkSpec {
        portal_networks,
        network_name: "angelfood".to_string(),
    }
    .into()
});

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let protocol = match self {
            ProtocolId::State => "State",
            ProtocolId::VerkleState => "Verkle State",
            ProtocolId::History => "History",
            ProtocolId::TransactionGossip => "Transaction Gossip",
            ProtocolId::CanonicalIndices => "Canonical Indices",
            ProtocolId::Beacon => "Beacon",
            ProtocolId::Utp => "uTP",
        };
        write!(f, "{protocol}")
    }
}

impl From<ProtocolId> for u8 {
    fn from(protocol_id: ProtocolId) -> Self {
        match protocol_id {
            ProtocolId::State => 2,
            ProtocolId::VerkleState => 5,
            ProtocolId::History => 0,
            ProtocolId::TransactionGossip => 3,
            ProtocolId::CanonicalIndices => 4,
            ProtocolId::Beacon => 1,
            ProtocolId::Utp => 99,
        }
    }
}

/// A Portal protocol message.
#[derive(Debug, PartialEq, Clone, Encode, Decode)]
#[ssz(enum_behaviour = "union")]
pub enum Message {
    Ping(Ping),
    Pong(Pong),
    FindNodes(FindNodes),
    Nodes(Nodes),
    FindContent(FindContent),
    Content(Content),
    Offer(Offer),
    Accept(Accept),
}

// Silence clippy to avoid implementing newtype pattern on imported type.
#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for Message {
    fn into(self) -> Vec<u8> {
        self.as_ssz_bytes()
    }
}

impl TryFrom<Vec<u8>> for Message {
    type Error = MessageDecodeError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Message::from_ssz_bytes(&value).map_err(|e| MessageDecodeError::Ssz { decode_err: e })
    }
}

impl From<Request> for Message {
    fn from(request: Request) -> Self {
        match request {
            Request::Ping(ping) => Message::Ping(ping),
            Request::FindNodes(find_nodes) => Message::FindNodes(find_nodes),
            Request::FindContent(find_content) => Message::FindContent(find_content),
            Request::Offer(offer) => Message::Offer(offer),
            Request::PopulatedOffer(offer) => Request::Offer(offer.into()).into(),
            Request::PopulatedOfferWithResult(offer) => Request::Offer(offer.into()).into(),
        }
    }
}

impl From<Response> for Message {
    fn from(response: Response) -> Self {
        match response {
            Response::Pong(pong) => Message::Pong(pong),
            Response::Nodes(nodes) => Message::Nodes(nodes),
            Response::Content(content) => Message::Content(content),
            Response::Accept(accept) => Message::Accept(accept),
        }
    }
}

#[derive(Error, Debug)]
pub enum TryFromMessageError {
    #[error("non-request message")]
    NonRequestMessage,
    #[error("non-response message")]
    NonResponseMessage,
}

/// A Portal protocol request.
#[derive(Debug, Clone)]
pub enum Request {
    Ping(Ping),
    FindNodes(FindNodes),
    FindContent(FindContent),
    Offer(Offer),
    /// Equivalent to Offer, but with content values supplied, to skip the DB lookup
    PopulatedOffer(PopulatedOffer),
    /// Equivalent to PopulatedOffer, but with a return channel for the result
    PopulatedOfferWithResult(PopulatedOfferWithResult),
}

impl TryFrom<Message> for Request {
    type Error = TryFromMessageError;

    fn try_from(message: Message) -> Result<Self, Self::Error> {
        // Match all variants explicitly so that a new variant cannot be added without additional
        // match arm.
        match message {
            Message::Ping(ping) => Ok(Request::Ping(ping)),
            Message::Pong(_) => Err(TryFromMessageError::NonRequestMessage),
            Message::FindNodes(find_nodes) => Ok(Request::FindNodes(find_nodes)),
            Message::Nodes(_) => Err(TryFromMessageError::NonRequestMessage),
            Message::FindContent(find_content) => Ok(Request::FindContent(find_content)),
            Message::Content(_) => Err(TryFromMessageError::NonRequestMessage),
            Message::Offer(offer) => Ok(Request::Offer(offer)),
            Message::Accept(_) => Err(TryFromMessageError::NonRequestMessage),
        }
    }
}

/// A Portal protocol response.
#[derive(Debug, Clone)]
pub enum Response {
    Pong(Pong),
    Nodes(Nodes),
    Content(Content),
    Accept(Accept),
}

impl TryFrom<Message> for Response {
    type Error = TryFromMessageError;

    fn try_from(message: Message) -> Result<Self, Self::Error> {
        // Match all variants explicitly so that a new variant cannot be added without additional
        // match arm.
        match message {
            Message::Ping(_) => Err(TryFromMessageError::NonResponseMessage),
            Message::Pong(pong) => Ok(Response::Pong(pong)),
            Message::FindNodes(_) => Err(TryFromMessageError::NonResponseMessage),
            Message::Nodes(nodes) => Ok(Response::Nodes(nodes)),
            Message::FindContent(_) => Err(TryFromMessageError::NonResponseMessage),
            Message::Content(content) => Ok(Response::Content(content)),
            Message::Offer(_) => Err(TryFromMessageError::NonResponseMessage),
            Message::Accept(accept) => Ok(Response::Accept(accept)),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Ping {
    pub enr_seq: u64,
    pub custom_payload: CustomPayload,
}

impl fmt::Display for Ping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ping(enr_seq={}, radius={})",
            self.enr_seq,
            hex_encode(self.custom_payload.as_ssz_bytes())
        )
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Pong {
    pub enr_seq: u64,
    pub custom_payload: CustomPayload,
}

impl fmt::Display for Pong {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pong(enr_seq={}, radius={})",
            self.enr_seq,
            hex_encode(self.custom_payload.as_ssz_bytes())
        )
    }
}

/// Convert to JSON Value from Pong ssz bytes
impl From<Pong> for Value {
    fn from(val: Pong) -> Self {
        match U256::from_ssz_bytes(&val.custom_payload.payload.as_ssz_bytes()) {
            Ok(data_radius) => {
                let mut result = Map::new();
                result.insert("enrSeq".to_owned(), Value::String(val.enr_seq.to_string()));
                result.insert(
                    "dataRadius".to_owned(),
                    Value::String(data_radius.to_string()),
                );

                Value::Object(result)
            }
            Err(msg) => Value::String(format!("Unable to ssz decode data radius!: {msg:?}")),
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
                    .map_err(|e| DecodeError::BytesInvalid(format!("rlp decoding failed: {e}")))
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

impl From<Nodes> for Value {
    fn from(val: Nodes) -> Self {
        let enrs: Vec<Value> = val
            .enrs
            .iter()
            .map(|enr| serde_json::json!(enr.to_base64()))
            .collect();
        serde_json::json!({ "enrs":  enrs, "total": val.total})
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
    Content(Vec<u8>),
    Enrs(Vec<SszEnr>),
}

impl TryInto<Value> for Content {
    type Error = MessageDecodeError;

    fn try_into(self) -> Result<Value, Self::Error> {
        if let Content::ConnectionId(val) = self {
            Ok(serde_json::json!({ "connection_id": val }))
        } else if let Content::Content(val) = self {
            Ok(serde_json::json!({ "content": hex_encode(val) }))
        } else if let Content::Enrs(val) = self {
            Ok(serde_json::json!({ "enrs": val }))
        } else {
            Err(MessageDecodeError::Type)
        }
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Offer {
    pub content_keys: Vec<RawContentKey>,
}

/// The content necessary to make an offer message, with key/value pairs
#[derive(Debug, Clone)]
pub struct PopulatedOffer {
    /// All the offered content, pairing the keys and values
    pub content_items: Vec<(RawContentKey, Vec<u8>)>,
}

impl From<PopulatedOffer> for Offer {
    fn from(val: PopulatedOffer) -> Self {
        let content_keys = val
            .content_items
            .into_iter()
            .map(|(key, _val)| key)
            .collect();
        Self { content_keys }
    }
}

/// The content necessary to make an offer message and return the result of propagation
#[derive(Debug, Clone)]
pub struct PopulatedOfferWithResult {
    /// The offered content key & value
    pub content_item: (RawContentKey, Vec<u8>),
    /// The channel to send the result of the offer to
    pub result_tx: tokio::sync::mpsc::UnboundedSender<bool>,
}

impl From<PopulatedOfferWithResult> for Offer {
    fn from(val: PopulatedOfferWithResult) -> Self {
        Self {
            content_keys: vec![val.content_item.0],
        }
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode, Serialize, Deserialize)]
pub struct Accept {
    pub connection_id: u16,
    pub content_keys: BitList<typenum::U8>,
}

impl From<Accept> for Value {
    fn from(val: Accept) -> Self {
        serde_json::json!({ "connection_id": format!("{:?}", val.connection_id.to_be()) , "content_keys": val.content_keys})
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod test {
    use super::*;
    use std::str::FromStr;
    use test_log::test;

    #[test]
    fn protocol_id_invalid() {
        let hex = "0x504F";
        assert!(!MAINNET.portal_networks.contains_right(hex));
    }

    #[test]
    fn protocol_id_encoding() {
        let hex = "0x500A";
        let protocol_id = MAINNET.get_protocol_id_from_hex(hex).unwrap();
        let expected_hex = MAINNET.get_protocol_hex_from_id(&protocol_id).unwrap();
        assert_eq!(hex, expected_hex);
    }

    #[test]
    fn prtocol_id_to_u8() {
        let protocol_id = ProtocolId::History;
        let expected_u8 = 0;
        assert_eq!(expected_u8, u8::from(protocol_id));

        let protocol_id = ProtocolId::Beacon;
        let expected_u8 = 1;
        assert_eq!(expected_u8, u8::from(protocol_id));

        let protocol_id = ProtocolId::State;
        let expected_u8 = 2;
        assert_eq!(expected_u8, u8::from(protocol_id));

        let protocol_id = ProtocolId::TransactionGossip;
        let expected_u8 = 3;
        assert_eq!(expected_u8, u8::from(protocol_id));

        let protocol_id = ProtocolId::CanonicalIndices;
        let expected_u8 = 4;
        assert_eq!(expected_u8, u8::from(protocol_id));

        let protocol_id = ProtocolId::Utp;
        let expected_u8 = 99;
        assert_eq!(expected_u8, u8::from(protocol_id));
    }

    // Wire message test vectors available in Ethereum Portal Network specs repo:
    // github.com/ethereum/portal-network-specs

    #[test]
    fn message_encoding_ping() {
        let data_radius: U256 = U256::MAX - U256::from(1u8);
        let custom_payload = CustomPayload::from(data_radius.as_ssz_bytes());
        let ping = Ping {
            enr_seq: 1,
            custom_payload,
        };
        let ping = Message::Ping(ping);

        let encoded: Vec<u8> = ping.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x0001000000000000000c000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, ping);
    }

    #[test]
    fn message_encoding_pong() {
        let data_radius: U256 = U256::MAX / U256::from(2u8);
        let custom_payload = CustomPayload::from(data_radius.as_ssz_bytes());
        let pong = Pong {
            enr_seq: 1,
            custom_payload,
        };
        let pong = Message::Pong(pong);

        let encoded: Vec<u8> = pong.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x0101000000000000000c000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, pong);
    }

    #[test]
    fn message_encoding_find_nodes() {
        let distances = vec![256, 255];
        let find_nodes = FindNodes { distances };
        let find_nodes = Message::FindNodes(find_nodes);

        let encoded: Vec<u8> = find_nodes.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x02040000000001ff00";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, find_nodes);
    }

    #[test]
    fn message_encoding_nodes_zero_enrs() {
        let nodes = Nodes {
            total: 1,
            enrs: vec![],
        };
        let nodes = Message::Nodes(nodes);

        let encoded: Vec<u8> = nodes.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x030105000000";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, nodes);
    }

    #[test]
    fn message_encoding_nodes_multiple_enrs() {
        let enr_one = SszEnr(Enr::from_str("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg").unwrap());
        let enr_two = SszEnr(Enr::from_str("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU").unwrap());
        let nodes = Nodes {
            total: 1,
            enrs: vec![enr_one, enr_two],
        };
        let nodes = Message::Nodes(nodes);

        let encoded: Vec<u8> = nodes.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x030105000000080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, nodes);
    }

    #[test]
    fn message_encoding_find_content() {
        let content_key = hex_decode("0x706f7274616c").unwrap();
        let find_content = FindContent { content_key };
        let find_content = Message::FindContent(find_content);

        let encoded: Vec<u8> = find_content.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x0404000000706f7274616c";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, find_content);
    }

    #[test]
    fn message_encoding_content_connection_id() {
        let connection_id = u16::from_le_bytes([0x01, 0x02]);
        let content = Content::ConnectionId(connection_id);
        let content = Message::Content(content);

        let encoded: Vec<u8> = content.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x05000102";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn message_encoding_content_content() {
        let content_val = hex_decode("0x7468652063616b652069732061206c6965").unwrap();
        let content = Content::Content(content_val);
        let content = Message::Content(content);

        let encoded: Vec<u8> = content.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x05017468652063616b652069732061206c6965";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn message_encoding_content_enrs() {
        let enr_one = SszEnr(Enr::from_str("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg").unwrap());
        let enr_two = SszEnr(Enr::from_str("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU").unwrap());
        let content = Content::Enrs(vec![enr_one, enr_two]);
        let content = Message::Content(content);

        let encoded: Vec<u8> = content.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x0502080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn message_encoding_offer() {
        let content_keys = vec![hex_decode("0x010203").unwrap()];
        let offer = Offer { content_keys };
        let offer = Message::Offer(offer);

        let encoded: Vec<u8> = offer.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x060400000004000000010203";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, offer);
    }

    #[test]
    fn message_encoding_accept() {
        let connection_id = u16::from_le_bytes([0x01, 0x02]);
        let mut content_keys = BitList::with_capacity(8).unwrap();
        content_keys.set(0, true).unwrap();
        let accept = Accept {
            connection_id,
            content_keys,
        };
        let accept = Message::Accept(accept);

        let encoded: Vec<u8> = accept.clone().into();
        let encoded = hex_encode(encoded);
        let expected_encoded = "0x070102060000000101";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex_decode(&encoded).unwrap()).unwrap();
        assert_eq!(decoded, accept);
    }
}
