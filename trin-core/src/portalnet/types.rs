use std::convert::{TryFrom, TryInto};
use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use base64;
use rlp::Encodable;
use ssz;
use ssz::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder};
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum, VariableList};

use super::{Enr, U256};

type ByteList = VariableList<u8, typenum::U2048>;

#[derive(Clone)]
pub struct PortalnetConfig {
    pub external_addr: Option<SocketAddr>,
    pub private_key: Option<HexData>,
    pub listen_port: u16,
    pub bootnode_enrs: Vec<Enr>,
    pub data_radius: U256,
}

impl Default for PortalnetConfig {
    fn default() -> Self {
        Self {
            external_addr: None,
            private_key: None,
            listen_port: 4242,
            bootnode_enrs: Vec::<Enr>::new(),
            data_radius: U256::from(u64::MAX), //TODO better data_radius default?
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProtocolKind {
    History,
    State,
}

impl ToString for ProtocolKind {
    fn to_string(&self) -> String {
        match self {
            ProtocolKind::History => "history".to_string(),
            ProtocolKind::State => "state".to_string(),
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
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if let Some(message_id) = bytes.first() {
            match message_id {
                // Requests
                1 => Ok(Message::Request(Request::Ping(
                    Ping::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                3 => Ok(Message::Request(Request::FindNodes(
                    FindNodes::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                5 => Ok(Message::Request(Request::FindContent(
                    FindContent::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                2 => Ok(Message::Response(Response::Pong(
                    Pong::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                4 => Ok(Message::Response(Response::Nodes(
                    Nodes::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                6 => Ok(Message::Response(Response::FoundContent(
                    FoundContent::from_ssz_bytes(&bytes[1..])
                        .map_err(|e| format!("Failed to decode ssz: {:?}", e))?,
                ))),
                _ => Err("Unknown message id".to_string()),
            }
        } else {
            Err("Empty bytes".to_string())
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
pub struct CustomPayload {
    /// Overlay data radius
    pub data_radius: U256,
    /// Optional payload element of SSZ type List[uint8, max_length=2048].
    pub payload: Option<ByteList>,
}

impl CustomPayload {
    pub fn new(data_radius: U256, payload: Option<Vec<u8>>) -> Self {
        match payload {
            Some(payload) => {
                let ssz_list = VariableList::from(payload);
                let message: ByteList = ByteList::from(ssz_list);

                Self {
                    data_radius,
                    payload: Some(message),
                }
            }
            None => Self {
                data_radius,
                payload: None,
            },
        }
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Ping {
    pub enr_seq: u64,
    pub payload: Option<CustomPayload>,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Pong {
    pub enr_seq: u64,
    pub payload: Option<CustomPayload>,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct FindNodes {
    // TODO: Make this an ssz list
    pub distances: Vec<u16>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Nodes {
    pub total: u8,
    // TODO: Make this an ssz list
    pub enrs: Vec<Enr>,
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
    pub enrs: Vec<SszEnr>,
    pub payload: Vec<u8>,
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

impl ssz::Encode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let offset =
            <Vec<SszEnr> as Encode>::ssz_fixed_len() + <Vec<u8> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&self.enrs);
        encoder.append(&self.payload);
        encoder.finalize();
    }

    fn ssz_bytes_len(&self) -> usize {
        <Vec<SszEnr> as Encode>::ssz_fixed_len()
            + <Vec<u8> as Encode>::ssz_fixed_len()
            + self.enrs.ssz_bytes_len()
            + self.payload.ssz_bytes_len()
    }
}

impl ssz::Decode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(&bytes);

        builder.register_type::<Vec<SszEnr>>().unwrap();
        builder.register_type::<Vec<u8>>().unwrap();

        let mut decoder = builder.build()?;
        Ok(Self {
            enrs: decoder.decode_next()?,
            payload: decoder.decode_next()?,
        })
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
    fn test_found_content_encodes_empty() {
        let empty_enrs: Vec<SszEnr> = vec![];
        let empty_payload: Vec<u8> = vec![];
        let msg = FoundContent {
            enrs: empty_enrs.clone(),
            payload: empty_payload.clone(),
        };
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.enrs, empty_enrs);
        assert_eq!(decoded.payload, empty_payload);
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_found_content_encodes_payload() {
        let empty_enrs: Vec<SszEnr> = vec![];
        let msg = FoundContent {
            enrs: empty_enrs,
            payload: vec![1; 32],
        };
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.payload, vec![1; 32]);
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_found_content_encodes_single_enr() {
        let enr = build_enr(enr_one_key());
        let empty_payload: Vec<u8> = vec![];
        let msg = FoundContent {
            enrs: vec![SszEnr(enr.clone())],
            payload: empty_payload,
        };
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert!(SszEnr(enr).eq(decoded.enrs.first().unwrap()));
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_found_content_encodes_double_enrs() {
        let enr_one = build_enr(enr_one_key());
        let enr_two = build_enr(enr_two_key());

        let empty_payload: Vec<u8> = vec![];
        let msg = FoundContent {
            enrs: vec![SszEnr(enr_one.clone()), SszEnr(enr_two.clone())],
            payload: empty_payload,
        };
        let actual = msg.as_ssz_bytes();
        let decoded = FoundContent::from_ssz_bytes(&actual).unwrap();
        assert!(SszEnr(enr_one).eq(decoded.enrs.first().unwrap()));
        assert!(SszEnr(enr_two).eq(&decoded.enrs.into_iter().nth(1).unwrap()));
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }

    #[test]
    fn test_nodes_encodes_empty() {
        let empty_enrs: Vec<Enr> = vec![];
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
            enrs: vec![enr.clone()],
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
            enrs: vec![enr_one.clone(), enr_two.clone()],
            total,
        };
        let actual = msg.as_ssz_bytes();
        let decoded = Nodes::from_ssz_bytes(&actual).unwrap();

        assert_eq!(decoded, msg);
        assert!(enr_one.eq(decoded.enrs.first().unwrap()));
        assert!(enr_two.eq(&decoded.enrs.into_iter().nth(1).unwrap()));
        assert_eq!(actual.len(), msg.ssz_bytes_len());
    }
}
