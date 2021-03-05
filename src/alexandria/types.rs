use ssz::{DecodeError, Encode};

use super::{Enr, U256};
use rlp::Encodable;
use ssz::Decode;
use ssz_derive::{Decode, Encode};

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

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Ping {
    pub enr_seq: u32,
    pub data_radius: U256,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct Pong {
    pub enr_seq: u32,
    pub data_radius: U256,
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct FindNodes {
    // TODO: Make this an ssz list and use u16
    pub distances: Vec<u64>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Nodes {
    pub total: u8,
    // TODO: Make this an ssz list
    pub enrs: Vec<Enr>,
}

// TODO: check correctness and if there's a better way
// to impl Encode
impl ssz::Encode for Nodes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.push(self.total);
        for enr in self.enrs.iter() {
            buf.append(enr.rlp_bytes().to_vec().as_mut());
        }
    }
}

// TODO: check correctness and if there's a better way
// to impl Decode
impl ssz::Decode for Nodes {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() == 0 {
            return Err(DecodeError::BytesInvalid("Should not be empty".to_string()));
        }
        let total = bytes.first().expect("should have one element");
        let enr_bytes = <Vec<Vec<u8>>>::from_ssz_bytes(&bytes[1..])?;
        let enrs: Result<Vec<Enr>, _> = enr_bytes
            .into_iter()
            .map(|bytes| {
                rlp::decode(&bytes)
                    .map_err(|e| DecodeError::BytesInvalid(format!("rlp decoding failed: {}", e)))
            })
            .collect();
        Ok(Self {
            total: *total,
            enrs: enrs?,
        })
    }
}

#[derive(Debug, PartialEq, Clone, Encode, Decode)]
pub struct FindContent {
    // TODO: Use some version of H256
    pub content_key: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct FoundContent {
    pub enrs: Vec<Enr>,
    // TODO: uncomment this after figuring out how to do ssz tuples
    // payload: Vec<u8>,
}

// TODO: This is not according to spec.
// Fix after figuring out how to do ssz containers encoding.
impl ssz::Encode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.push(self.enrs.len() as u8);
        for enr in self.enrs.iter() {
            buf.append(enr.rlp_bytes().to_vec().as_mut());
        }
    }
}

// TODO: same as encode
impl ssz::Decode for FoundContent {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() == 0 {
            return Err(DecodeError::BytesInvalid("Should not be empty".to_string()));
        }
        let _length = bytes.first().expect("should have one element");
        let enr_bytes = <Vec<Vec<u8>>>::from_ssz_bytes(&bytes[1..])?;
        let enrs: Result<Vec<Enr>, _> = enr_bytes
            .into_iter()
            .map(|bytes| {
                rlp::decode(&bytes)
                    .map_err(|e| DecodeError::BytesInvalid(format!("rlp decoding failed: {}", e)))
            })
            .collect();
        Ok(Self { enrs: enrs? })
    }
}
