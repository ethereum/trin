#![allow(dead_code)]
// These are just some Trin helper functions

use ssz_derive::{Decode, Encode};

// These Utp impl are related to sending messages over uTP not the implementation itself or stream
pub struct UtpMessage {
    pub length: u32,
    pub payload: Vec<u8>,
}

impl UtpMessage {
    pub fn new(payload: Vec<u8>) -> Self {
        UtpMessage {
            length: payload.len() as u32,
            payload,
        }
    }

    pub fn encode(&mut self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.append(&mut self.payload);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<UtpMessage, String> {
        if bytes.len() >= 4 {
            let len = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
            if len + 4 <= bytes.len() as u32 {
                let mut payload_vec: Vec<u8> = vec![];
                payload_vec.extend_from_slice(&bytes[4..(len as usize + 4)]);

                return Ok(UtpMessage {
                    length: len,
                    payload: payload_vec,
                });
            }
        }
        Err("Invalid message".to_owned())
    }

    pub(crate) fn len(self) -> usize {
        4 + self.payload.len()
    }
}

#[derive(PartialEq, Debug, Encode, Decode)]
pub struct UtpAccept {
    pub message: Vec<(Vec<u8>, Vec<u8>)>,
}

// This is not in a spec, this is just for internally tracking for what portal message
// negotiated the uTP stream
pub enum UtpMessageId {
    OfferAcceptStream,
}

#[cfg(test)]
mod tests {
    use crate::utp::trin_helpers::UtpMessage;

    #[test]
    fn test_too_short_message() {
        let buf = [0x00, 0x00, 0x00, 0x03, 0x09, 0x0B];

        let message = UtpMessage::decode(&buf[..]);
        assert!(message.is_err());
    }

    #[test]
    fn test_message_decode() {
        // Added an extra byte since we will be parsing a vector
        let buf = [
            0x00, 0x00, 0x00, 0x0B, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C,
            0x64, 0x54,
        ];

        let message = UtpMessage::decode(&buf[..]);
        assert!(message.is_ok());
        let message = message.unwrap();
        assert_eq!(message.length, 11);
        assert_eq!(message.payload, b"Hello world".to_vec());
    }

    #[test]
    fn test_message_encode() {
        let payload = b"Hello world".to_vec();
        let buf = UtpMessage::encode(&mut UtpMessage::new(payload));

        let message = UtpMessage::decode(&buf[..]);
        assert!(message.is_ok());
        let message = message.unwrap();
        assert_eq!(message.length, 11);
        assert_eq!(message.payload, b"Hello world".to_vec());
    }
}
