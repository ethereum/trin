use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use base64;
use hex::FromHexError;
use rlp::Encodable;
use serde_json::{Map, Value};
use ssz::{Decode, DecodeError, Encode};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, BitList, VariableList};
use thiserror::Error;
use validator::ValidationError;

use crate::portalnet::{types::uint::U256, Enr};

pub type ByteList = VariableList<u8, typenum::U2048>;

/// Custom payload element of Ping and Pong overlay messages
#[derive(Debug, PartialEq, Clone)]
pub struct CustomPayload {
    payload: ByteList,
}

impl TryFrom<&Value> for CustomPayload {
    type Error = ValidationError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let value = value
            .as_str()
            .ok_or_else(|| ValidationError::new("Custom payload value is not a string!"))?;
        let payload = match hex::decode(value) {
            Ok(payload) => payload,
            Err(_) => Err(ValidationError::new(
                "Unable to decode hex payload into bytes",
            ))?,
        };
        match ByteList::try_from(payload) {
            Ok(payload) => Ok(Self { payload }),
            Err(_) => Err(ValidationError::new("Invalid custom payload value")),
        }
    }
}

impl From<Vec<u8>> for CustomPayload {
    fn from(ssz_bytes: Vec<u8>) -> Self {
        Self {
            payload: ByteList::from(ssz_bytes),
        }
    }
}

impl ssz::Decode for CustomPayload {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(CustomPayload {
            payload: ByteList::from(bytes.to_vec()),
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
    pub enable_metrics: bool,
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
            enable_metrics: false,
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
        match Message::from_ssz_bytes(&value) {
            Ok(key) => Ok(key),
            Err(err) => Err(MessageDecodeError::from(err)),
        }
    }
}

impl From<Request> for Message {
    fn from(request: Request) -> Self {
        match request {
            Request::Ping(ping) => Message::Ping(ping),
            Request::FindNodes(find_nodes) => Message::FindNodes(find_nodes),
            Request::FindContent(find_content) => Message::FindContent(find_content),
            Request::Offer(offer) => Message::Offer(offer),
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
            hex::encode(self.custom_payload.as_ssz_bytes())
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
            hex::encode(self.custom_payload.as_ssz_bytes())
        )
    }
}

/// Convert to JSON Value from Pong ssz bytes
impl Into<Value> for Pong {
    fn into(self) -> Value {
        match U256::from_ssz_bytes(&self.custom_payload.payload.as_ssz_bytes()) {
            Ok(data_radius) => {
                let mut result = Map::new();
                result.insert("enrSeq".to_owned(), Value::String(self.enr_seq.to_string()));
                result.insert(
                    "dataRadius".to_owned(),
                    Value::String(data_radius.to_string()),
                );

                Value::Object(result)
            }
            Err(msg) => Value::String(format!("Unable to ssz decode data radius!: {:?}", msg)),
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

impl Into<Value> for Nodes {
    fn into(self) -> Value {
        serde_json::json!({ "enrs": format!("{:?}", self.enrs) , "total": self.total})
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

impl TryInto<Value> for Content {
    type Error = MessageDecodeError;

    fn try_into(self) -> Result<Value, Self::Error> {
        if let Content::ConnectionId(val) = self {
            Ok(serde_json::json!({ "connection_id": val }))
        } else if let Content::Content(val) = self {
            Ok(serde_json::json!({"content": hex::encode(val.to_vec())}))
        } else if let Content::Enrs(val) = self {
            Ok(serde_json::json!({ "enrs": format!("{:?}", val) }))
        } else {
            Err(MessageDecodeError::Type)
        }
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Offer {
    pub content_keys: Vec<Vec<u8>>,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Accept {
    pub connection_id: u16,
    pub content_keys: BitList<typenum::U8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SszEnr(Enr);

impl SszEnr {
    pub fn new(enr: Enr) -> SszEnr {
        SszEnr(enr)
    }
}

impl Into<Enr> for SszEnr {
    fn into(self) -> Enr {
        Enr::from(self.0)
    }
}

impl TryFrom<&Value> for SszEnr {
    type Error = ValidationError;

    fn try_from(value: &Value) -> Result<Self, Self::Error> {
        let enr = value
            .as_str()
            .ok_or_else(|| ValidationError::new("Enr value is not a string!"))?;
        match Enr::from_str(enr) {
            Ok(enr) => Ok(Self(enr)),
            Err(_) => Err(ValidationError::new("Invalid enr value")),
        }
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

    #[test]
    #[should_panic]
    fn protocol_id_invalid() {
        let hex = "500F";
        ProtocolId::from_str(hex).unwrap();
    }

    #[test]
    fn protocol_id_encoding() {
        let hex = "500A";
        let protocol_id = ProtocolId::from_str(hex).unwrap();
        let expected_hex = hex::encode_upper(Vec::try_from(protocol_id).unwrap());
        assert_eq!(hex, expected_hex);
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
        let encoded = hex::encode(encoded);
        let expected_encoded = "0001000000000000000c000000feffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
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
        let encoded = hex::encode(encoded);
        let expected_encoded = "0101000000000000000c000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, pong);
    }

    #[test]
    fn message_encoding_find_nodes() {
        let distances = vec![256, 255];
        let find_nodes = FindNodes { distances };
        let find_nodes = Message::FindNodes(find_nodes);

        let encoded: Vec<u8> = find_nodes.clone().into();
        let encoded = hex::encode(encoded);
        let expected_encoded = "02040000000001ff00";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
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
        let encoded = hex::encode(encoded);
        let expected_encoded = "030105000000";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
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
        let encoded = hex::encode(encoded);
        let expected_encoded = "030105000000080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, nodes);
    }

    #[test]
    fn message_encoding_find_content() {
        let content_key = hex::decode("706f7274616c").unwrap();
        let find_content = FindContent { content_key };
        let find_content = Message::FindContent(find_content);

        let encoded: Vec<u8> = find_content.clone().into();
        let encoded = hex::encode(encoded);
        let expected_encoded = "0404000000706f7274616c";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, find_content);
    }

    #[test]
    fn message_encoding_content_connection_id() {
        let connection_id = u16::from_le_bytes([0x01, 0x02]);
        let content = Content::ConnectionId(connection_id);
        let content = Message::Content(content);

        let encoded: Vec<u8> = content.clone().into();
        let encoded = hex::encode(encoded);
        let expected_encoded = "05000102";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn message_encoding_content_content() {
        let content_val = hex::decode("7468652063616b652069732061206c6965").unwrap();
        let content_val = ByteList::from(VariableList::from(content_val));
        let content = Content::Content(content_val);
        let content = Message::Content(content);

        let encoded: Vec<u8> = content.clone().into();
        let encoded = hex::encode(encoded);
        let expected_encoded = "05017468652063616b652069732061206c6965";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn message_encoding_content_enrs() {
        let enr_one = SszEnr(Enr::from_str("enr:-HW4QBzimRxkmT18hMKaAL3IcZF1UcfTMPyi3Q1pxwZZbcZVRI8DC5infUAB_UauARLOJtYTxaagKoGmIjzQxO2qUygBgmlkgnY0iXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTg").unwrap());
        let enr_two = SszEnr(Enr::from_str("enr:-HW4QNfxw543Ypf4HXKXdYxkyzfcxcO-6p9X986WldfVpnVTQX1xlTnWrktEWUbeTZnmgOuAY_KUhbVV1Ft98WoYUBMBgmlkgnY0iXNlY3AyNTZrMaEDDiy3QkHAxPyOgWbxp5oF1bDdlYE6dLCUUp8xfVw50jU").unwrap());
        let content = Content::Enrs(vec![enr_one, enr_two]);
        let content = Message::Content(content);

        let encoded: Vec<u8> = content.clone().into();
        let encoded = hex::encode(encoded);
        let expected_encoded = "0502080000007f000000f875b8401ce2991c64993d7c84c29a00bdc871917551c7d330fca2dd0d69c706596dc655448f030b98a77d4001fd46ae0112ce26d613c5a6a02a81a6223cd0c4edaa53280182696482763489736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138f875b840d7f1c39e376297f81d7297758c64cb37dcc5c3beea9f57f7ce9695d7d5a67553417d719539d6ae4b445946de4d99e680eb8063f29485b555d45b7df16a1850130182696482763489736563703235366b31a1030e2cb74241c0c4fc8e8166f1a79a05d5b0dd95813a74b094529f317d5c39d235";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, content);
    }

    #[test]
    fn message_encoding_offer() {
        let content_keys = vec![hex::decode("010203").unwrap()];
        let offer = Offer { content_keys };
        let offer = Message::Offer(offer);

        let encoded: Vec<u8> = offer.clone().into();
        let encoded = hex::encode(encoded);
        let expected_encoded = "060400000004000000010203";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
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
        let encoded = hex::encode(encoded);
        let expected_encoded = "070102060000000101";
        assert_eq!(encoded, expected_encoded);

        let decoded = Message::try_from(hex::decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, accept);
    }
}
