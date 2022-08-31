use crate::utp::{
    bit_iterator::BitIterator,
    time::{Delay, Timestamp},
};
use anyhow::anyhow;
use std::{convert::TryFrom, fmt};

pub const HEADER_SIZE: usize = 20;
pub const VERSION: u8 = 1;

macro_rules! u8_to_unsigned_be {
    ($src:ident, $start:expr, $end:expr, $t:ty) => ({
        (0 .. $end - $start + 1).rev().fold(0, |acc, i| acc | $src[$start+i] as $t << (i * 8))
    })
}

macro_rules! make_getter {
    ($name:ident, $t:ty, $m:ident) => {
        pub fn $name(&self) -> $t {
            let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
            $m::from_be(header.$name)
        }
    };
}

macro_rules! make_setter {
    ($fn_name:ident, $field:ident, $t: ty) => {
        pub fn $fn_name(&mut self, new: $t) {
            let mut header = unsafe { &mut *(self.0.as_mut_ptr() as *mut PacketHeader) };
            header.$field = new.to_be();
        }
    };
}

#[derive(PartialEq, Eq, Debug)]
pub enum PacketType {
    Data,  // packet carries a data payload
    Fin,   // signals the end of a connection
    State, // signals acknowledgment of a packet
    Reset, // forcibly terminates a connection
    Syn,   // initiates a new connection with a peer
}

impl TryFrom<u8> for PacketType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketType::Data),
            1 => Ok(PacketType::Fin),
            2 => Ok(PacketType::State),
            3 => Ok(PacketType::Reset),
            4 => Ok(PacketType::Syn),
            _ => Err(anyhow!("Invalid packet type")),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(value: PacketType) -> u8 {
        match value {
            PacketType::Data => 0,
            PacketType::Fin => 1,
            PacketType::State => 2,
            PacketType::Reset => 3,
            PacketType::Syn => 4,
        }
    }
}

/// Validate correctness of packet extensions, if any, in byte slice
pub(crate) fn check_extensions(data: &[u8]) -> anyhow::Result<()> {
    if data.len() < HEADER_SIZE {
        return Err(anyhow!("The packet is too small"));
    }

    let mut extension_type = ExtensionType::from(data[1]);
    let mut index = HEADER_SIZE;

    if data.len() == HEADER_SIZE && extension_type != ExtensionType::None {
        return Err(anyhow!(
            "Invalid extension length (must be a non-zero multiple of 4)"
        ));
    }

    // Consume known extensions and skip over unknown ones
    while index < data.len() && extension_type != ExtensionType::None {
        if data.len() < index + 2 {
            return Err(anyhow!("Invalid packet length"));
        }
        let len = data[index + 1] as usize;
        let extension_start = index + 2;
        let extension_end = extension_start + len;

        // Check validity of extension length:
        // - non-zero,
        // - multiple of 4,
        // - does not exceed packet length
        if len == 0 || len % 4 != 0 || extension_end > data.len() {
            return Err(anyhow!("Invalid Extension Length"));
        }

        extension_type = ExtensionType::from(data[index]);
        index += len + 2;
    }

    // Check for pending extensions (early exit of previous loop)
    if extension_type != ExtensionType::None {
        return Err(anyhow!("Invalid packet length"));
    }

    Ok(())
}

// Default Rust representation doesn't guarantee the data layout and because we want to cast
// raw pointers to `PacketHeader` with `unsafe`, we need consistent data layout representation of the struct.
#[repr(C)]
pub struct PacketHeader {
    /// It would be wasteful over the wire to have 2 separate bytes for type and ver, so we split the u8 in half 0000_0000
    /// so the first half will store the type and the second half will store the version of the packet
    type_ver: u8, // type: u4, ver: u4
    extension: u8,
    connection_id: u16,
    timestamp_microseconds: u32,
    timestamp_difference_microseconds: u32,
    wnd_size: u32,
    seq_nr: u16,
    ack_nr: u16,
}

impl PacketHeader {
    /// Returns the packet's version.
    pub fn get_version(&self) -> u8 {
        self.type_ver & 0x0F
    }

    /// Sets the type of packet to the specified type.
    pub fn set_type(&mut self, t: PacketType) {
        let version = 0x0F & self.type_ver;
        self.type_ver = u8::from(t) << 4 | version;
    }

    /// Returns the packet's type.
    pub fn get_type(&self) -> PacketType {
        PacketType::try_from(self.type_ver >> 4).unwrap()
    }

    /// Returns the type of the first extension
    pub fn get_extension_type(&self) -> ExtensionType {
        self.extension.into()
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketHeader {
    type Error = anyhow::Error;
    /// Reads a byte buffer and returns the corresponding packet header.
    /// It assumes the fields are in network (big-endian) byte order,
    /// preserving it.
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.len() < HEADER_SIZE {
            return Err(anyhow!("The packet is too small"));
        }

        if buf[0] & 0x0F != VERSION {
            return Err(anyhow!("Unsupported packet version"));
        }

        // Check packet type
        PacketType::try_from(buf[0] >> 4)?;

        Ok(PacketHeader {
            type_ver: buf[0],
            extension: buf[1],
            connection_id: u8_to_unsigned_be!(buf, 2, 3, u16),
            timestamp_microseconds: u8_to_unsigned_be!(buf, 4, 7, u32),
            timestamp_difference_microseconds: u8_to_unsigned_be!(buf, 8, 11, u32),
            wnd_size: u8_to_unsigned_be!(buf, 12, 15, u32),
            seq_nr: u8_to_unsigned_be!(buf, 16, 17, u16),
            ack_nr: u8_to_unsigned_be!(buf, 18, 19, u16),
        })
    }
}

impl AsRef<[u8]> for PacketHeader {
    /// Returns the packet header as a slice of bytes.
    fn as_ref(&self) -> &[u8] {
        unsafe { &*(self as *const PacketHeader as *const [u8; HEADER_SIZE]) }
    }
}

impl Default for PacketHeader {
    fn default() -> PacketHeader {
        PacketHeader {
            type_ver: u8::from(PacketType::Data) << 4 | VERSION,
            extension: 0,
            connection_id: 0,
            timestamp_microseconds: 0,
            timestamp_difference_microseconds: 0,
            wnd_size: 0,
            seq_nr: 0,
            ack_nr: 0,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum ExtensionType {
    None,
    SelectiveAck,
    Unknown(u8),
}

impl From<u8> for ExtensionType {
    fn from(original: u8) -> Self {
        match original {
            0 => ExtensionType::None,
            1 => ExtensionType::SelectiveAck,
            n => ExtensionType::Unknown(n),
        }
    }
}

impl From<ExtensionType> for u8 {
    fn from(original: ExtensionType) -> u8 {
        match original {
            ExtensionType::None => 0,
            ExtensionType::SelectiveAck => 1,
            ExtensionType::Unknown(n) => n,
        }
    }
}

#[derive(Debug)]
pub struct Extension<'a> {
    pub ty: ExtensionType,
    pub data: &'a [u8],
}

impl<'a> Extension<'a> {
    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get_type(&self) -> ExtensionType {
        self.ty
    }

    pub fn iter(&self) -> BitIterator<'_> {
        BitIterator::from_bytes(self.data)
    }
}

pub struct ExtensionIterator<'a> {
    raw_bytes: &'a [u8],
    next_extension: ExtensionType,
    index: usize,
}

impl<'a> ExtensionIterator<'a> {
    fn new(packet: &'a Packet) -> Self {
        ExtensionIterator {
            raw_bytes: packet.as_ref(),
            next_extension: ExtensionType::from(packet.as_ref()[1]),
            index: HEADER_SIZE,
        }
    }
}

impl<'a> Iterator for ExtensionIterator<'a> {
    type Item = Extension<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_extension == ExtensionType::None {
            None
        } else if self.index < self.raw_bytes.len() {
            let len = self.raw_bytes[self.index + 1] as usize;
            let extension_start = self.index + 2;
            let extension_end = extension_start + len;

            // Assume extension is valid because the bytes come from a (valid) Packet
            let extension = Extension {
                ty: self.next_extension,
                data: &self.raw_bytes[extension_start..extension_end],
            };

            self.next_extension = self.raw_bytes[self.index].into();
            self.index += len + 2;

            Some(extension)
        } else {
            None
        }
    }
}

pub struct Packet(Vec<u8>);

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new()
    }
}

impl Packet {
    pub fn new() -> Packet {
        Packet(PacketHeader::default().as_ref().to_owned())
    }

    pub fn with_payload(payload: &[u8]) -> Packet {
        let mut inner = Vec::with_capacity(HEADER_SIZE + payload.len());
        let mut header = PacketHeader::default();
        header.set_type(PacketType::Data);

        inner.extend_from_slice(header.as_ref());
        inner.extend_from_slice(payload);

        Packet(inner)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn set_type(&mut self, t: PacketType) {
        let header = unsafe { &mut *(self.0.as_mut_ptr() as *mut PacketHeader) };
        header.set_type(t);
    }

    pub fn get_type(&self) -> PacketType {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        header.get_type()
    }

    pub fn get_version(&self) -> u8 {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        header.get_version()
    }

    pub fn get_extension_type(&self) -> ExtensionType {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        header.get_extension_type()
    }

    pub fn extensions(&self) -> ExtensionIterator<'_> {
        ExtensionIterator::new(self)
    }

    pub fn timestamp(&self) -> Timestamp {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        u32::from_be(header.timestamp_microseconds).into()
    }

    pub fn set_timestamp(&mut self, timestamp: Timestamp) {
        let header = unsafe { &mut *(self.0.as_mut_ptr() as *mut PacketHeader) };
        header.timestamp_microseconds = u32::from(timestamp).to_be();
    }

    pub fn timestamp_difference(&self) -> Delay {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        u32::from_be(header.timestamp_difference_microseconds).into()
    }

    pub fn set_timestamp_difference(&mut self, delay: Delay) {
        let header = unsafe { &mut *(self.0.as_mut_ptr() as *mut PacketHeader) };
        header.timestamp_difference_microseconds = u32::from(delay).to_be();
    }

    make_getter!(seq_nr, u16, u16);
    make_getter!(ack_nr, u16, u16);
    make_getter!(connection_id, u16, u16);
    make_getter!(wnd_size, u32, u32);

    make_setter!(set_seq_nr, seq_nr, u16);
    make_setter!(set_ack_nr, ack_nr, u16);
    make_setter!(set_connection_id, connection_id, u16);
    make_setter!(set_wnd_size, wnd_size, u32);

    pub fn payload(&self) -> &[u8] {
        let mut extension_type = ExtensionType::from(self.0[1]);
        let mut index = HEADER_SIZE;

        // Consume known extensions and skip over unknown ones
        while index < self.0.len() && extension_type != ExtensionType::None {
            let len = self.0[index + 1] as usize;

            // Assume extension is valid because the bytes come from a (valid) Packet

            extension_type = ExtensionType::from(self.0[index]);
            index += len + 2;
        }
        &self.0[index..]
    }

    /// Sets Selective ACK field in packet header and adds appropriate data.
    ///
    /// The length of the SACK extension is expressed in bytes, which
    /// must be a multiple of 4 and at least 4.
    pub fn set_selective_ack(&mut self, sack_bitfield: Vec<u8>) {
        // The length of the SACK extension is expressed in bytes, which
        // must be a multiple of 4 and at least 4.
        assert!(sack_bitfield.len() >= 4);
        assert_eq!(sack_bitfield.len() % 4, 0);

        let mut extension_type = ExtensionType::from(self.0[1]);
        let mut index = HEADER_SIZE;

        // Set extension type in header if none is used, otherwise find and update the
        // "next extension type" marker in the last extension before payload
        if extension_type == ExtensionType::None {
            self.0[1] = ExtensionType::SelectiveAck.into();
        } else {
            // Skip over all extensions until last, then modify its "next extension type" field and
            // add the new extension after it.

            // Consume known extensions and skip over unknown ones
            while index < self.0.len() && extension_type != ExtensionType::None {
                let len = self.0[index + 1] as usize;
                // No validity checks needed
                // ...

                extension_type = ExtensionType::from(self.0[index]);

                // Arrived at last extension
                if extension_type == ExtensionType::None {
                    // Mark existence of an additional extension
                    self.0[index] = ExtensionType::SelectiveAck.into();
                }
                index += len + 2;
            }
        }

        // Insert the new extension into the packet's data.
        // The way this is currently done is potentially slower than the alternative of resizing the
        // underlying Vec, moving the payload forward and then writing the extension in the "new"
        // place before the payload.

        // Set the type of the following (non-existent) extension
        self.0.insert(index, ExtensionType::None.into());
        // Set this extension's length
        self.0.insert(index + 1, sack_bitfield.len() as u8);
        // Write this extension's data
        for (i, &byte) in sack_bitfield.iter().enumerate() {
            self.0.insert(index + 2 + i, byte);
        }
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<'a> TryFrom<&'a [u8]> for Packet {
    type Error = anyhow::Error;

    /// Decodes a byte slice and construct the equivalent Packet.
    ///
    /// Note that this method makes no attempt to guess the payload size, saving
    /// all except the initial 20 bytes corresponding to the header as payload.
    /// It's the caller's responsibility to use an appropriately sized buffer
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        PacketHeader::try_from(buf)
            .and(check_extensions(buf))
            .and(Ok(Packet(buf.to_owned())))
    }
}

impl Clone for Packet {
    fn clone(&self) -> Packet {
        Packet(self.0.clone())
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Packet")
            .field("type", &self.get_type())
            .field("version", &self.get_version())
            .field("extension", &self.get_extension_type())
            .field("connection_id", &self.connection_id())
            .field("timestamp", &self.timestamp())
            .field("timestamp_difference", &self.timestamp_difference())
            .field("wnd_size", &self.wnd_size())
            .field("seq_nr", &self.seq_nr())
            .field("ack_nr", &self.ack_nr())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::utp::{
        packets::{
            PacketType::{Data, State},
            *,
        },
        time::{Delay, Timestamp},
    };
    use quickcheck::{QuickCheck, TestResult};
    use std::convert::TryFrom;
    use test_log::test;

    #[test]
    fn test_decode_packet() {
        let buf = [
            0x21, 0x0, 0xA4, 0x46, 0xA7, 0x3E, 0xF4, 0x40, 0x0, 0x0, 0x27, 0x10, 0x0, 0x0, 0xF0,
            0x0, 0x3C, 0x2C, 0x7E, 0xB5,
        ];

        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.get_type(), PacketType::State);
        assert_eq!(packet.get_version(), VERSION);
        assert_eq!(packet.get_extension_type(), ExtensionType::None);
        assert_eq!(packet.connection_id(), 42054);
        assert_eq!(packet.timestamp(), 2805920832.into());
        assert_eq!(packet.timestamp_difference(), 10000.into());
        assert_eq!(packet.wnd_size(), 61440);
        assert_eq!(packet.seq_nr(), 15404);
        assert_eq!(packet.ack_nr(), 32437);
        assert_eq!(packet.len(), buf.len());
        assert!(packet.payload().is_empty());
    }

    #[test]
    fn test_decode_packet_with_extension() {
        let buf = [
            0x21, 0x1, 0xA4, 0x46, 0xA7, 0x3E, 0xF4, 0x40, 0x0, 0x0, 0x27, 0x10, 0x0, 0x0, 0xF0,
            0x0, 0x3C, 0x2C, 0x7E, 0xB5, 0x0, 0x4, 0x00, 0x00, 0x00, 0x00,
        ];

        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_ok());

        let packet = packet.unwrap();
        assert_eq!(packet.get_type(), PacketType::State);
        assert_eq!(packet.get_version(), VERSION);
        assert_eq!(packet.get_extension_type(), ExtensionType::SelectiveAck);
        assert_eq!(packet.connection_id(), 42054);
        assert_eq!(packet.timestamp(), 2805920832.into());
        assert_eq!(packet.timestamp_difference(), 10000.into());
        assert_eq!(packet.wnd_size(), 61440);
        assert_eq!(packet.seq_nr(), 15404);
        assert_eq!(packet.ack_nr(), 32437);
        assert_eq!(packet.len(), buf.len());
        assert!(packet.payload().is_empty());
        let extensions: Vec<Extension<'_>> = packet.extensions().collect();
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].ty, ExtensionType::SelectiveAck);
        assert_eq!(extensions[0].data, &[0, 0, 0, 0]);
        assert_eq!(extensions[0].len(), extensions[0].data.len());
        assert_eq!(extensions[0].len(), 4);
        // Reversible
        assert_eq!(packet.as_ref(), &buf);
    }

    #[test]
    fn test_packet_decode_with_missing_extension() {
        let buf = [
            0x21, 0x01, 0x41, 0xa8, 0x99, 0x2f, 0xd0, 0x2a, 0x9f, 0x4a, 0x26, 0x21, 0x00, 0x10,
            0x00, 0x00, 0x3a, 0xf2, 0x6c, 0x79,
        ];
        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_err());
    }

    #[test]
    fn test_packet_decode_with_malformed_extension() {
        let buf = [
            0x21, 0x01, 0x41, 0xa8, 0x99, 0x2f, 0xd0, 0x2a, 0x9f, 0x4a, 0x26, 0x21, 0x00, 0x10,
            0x00, 0x00, 0x3a, 0xf2, 0x6c, 0x79, 0x00, 0x04, 0x00,
        ];
        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_err());
    }

    #[test]
    fn test_decode_packet_with_unknown_extensions() {
        let buf = [
            0x21, 0x01, 0x41, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x05, 0xdc, 0xab, 0x53, 0x3a, 0xf5, 0xff, 0x04, 0x00, 0x00, 0x00,
            0x00, // Imaginary extension
            0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];
        match Packet::try_from(&buf[..]) {
            Ok(packet) => {
                assert_eq!(packet.get_version(), 1);
                assert_eq!(packet.get_extension_type(), ExtensionType::SelectiveAck);
                assert_eq!(packet.get_type(), State);
                assert_eq!(packet.connection_id(), 16807);
                assert_eq!(packet.timestamp(), Timestamp(0));
                assert_eq!(packet.timestamp_difference(), Delay(0));
                assert_eq!(packet.wnd_size(), 1500);
                assert_eq!(packet.seq_nr(), 43859);
                assert_eq!(packet.ack_nr(), 15093);
                assert!(packet.payload().is_empty());
                // The invalid extension is discarded
                let extensions: Vec<Extension<'_>> = packet.extensions().collect();
                assert_eq!(extensions.len(), 2);
                assert_eq!(extensions[0].ty, ExtensionType::SelectiveAck);
                assert_eq!(extensions[0].data, &[0, 0, 0, 0]);
                assert_eq!(extensions[0].len(), extensions[0].data.len());
                assert_eq!(extensions[0].len(), 4);
            }
            Err(ref e) => panic!("{}", e),
        }
    }

    #[test]
    fn test_encode_packet() {
        let payload = b"Hello\n".to_vec();
        let timestamp = Timestamp(15270793);
        let timestamp_diff = Delay(1707040186);
        let (connection_id, seq_nr, ack_nr): (u16, u16, u16) = (16808, 15090, 17096);
        let window_size: u32 = 1048576;
        let mut packet = Packet::with_payload(&payload[..]);
        packet.set_type(Data);
        packet.set_timestamp(timestamp);
        packet.set_timestamp_difference(timestamp_diff);
        packet.set_connection_id(connection_id);
        packet.set_seq_nr(seq_nr);
        packet.set_ack_nr(ack_nr);
        packet.set_wnd_size(window_size);
        let buf = [
            0x01, 0x00, 0x41, 0xa8, 0x00, 0xe9, 0x03, 0x89, 0x65, 0xbf, 0x5d, 0xba, 0x00, 0x10,
            0x00, 0x00, 0x3a, 0xf2, 0x42, 0xc8, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x0a,
        ];

        assert_eq!(packet.len(), buf.len());
        assert_eq!(packet.len(), HEADER_SIZE + payload.len());
        assert_eq!(&packet.payload(), &payload.as_slice());
        assert_eq!(packet.get_version(), 1);
        assert_eq!(packet.get_extension_type(), ExtensionType::None);
        assert_eq!(packet.get_type(), Data);
        assert_eq!(packet.connection_id(), connection_id);
        assert_eq!(packet.seq_nr(), seq_nr);
        assert_eq!(packet.ack_nr(), ack_nr);
        assert_eq!(packet.wnd_size(), window_size);
        assert_eq!(packet.timestamp(), timestamp);
        assert_eq!(packet.timestamp_difference(), timestamp_diff);
        assert_eq!(packet.as_ref(), buf);
    }

    #[test]
    fn test_encode_packet_with_payload() {
        let payload = b"Hello\n".to_vec();
        let timestamp = Timestamp(15270793);
        let timestamp_diff = Delay(1707040186);
        let (connection_id, seq_nr, ack_nr): (u16, u16, u16) = (16808, 15090, 17096);
        let window_size: u32 = 1048576;
        let mut packet = Packet::with_payload(&payload[..]);
        packet.set_timestamp(timestamp);
        packet.set_timestamp_difference(timestamp_diff);
        packet.set_connection_id(connection_id);
        packet.set_seq_nr(seq_nr);
        packet.set_ack_nr(ack_nr);
        packet.set_wnd_size(window_size);
        let buf = [
            0x01, 0x00, 0x41, 0xa8, 0x00, 0xe9, 0x03, 0x89, 0x65, 0xbf, 0x5d, 0xba, 0x00, 0x10,
            0x00, 0x00, 0x3a, 0xf2, 0x42, 0xc8, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x0a,
        ];

        assert_eq!(packet.len(), buf.len());
        assert_eq!(packet.len(), HEADER_SIZE + payload.len());
        assert_eq!(&packet.payload(), &payload.as_slice());
        assert_eq!(packet.get_version(), 1);
        assert_eq!(packet.get_type(), Data);
        assert_eq!(packet.get_extension_type(), ExtensionType::None);
        assert_eq!(packet.connection_id(), connection_id);
        assert_eq!(packet.seq_nr(), seq_nr);
        assert_eq!(packet.ack_nr(), ack_nr);
        assert_eq!(packet.wnd_size(), window_size);
        assert_eq!(packet.timestamp(), timestamp);
        assert_eq!(packet.timestamp_difference(), timestamp_diff);
        assert_eq!(packet.as_ref(), buf);
    }

    #[test]
    fn test_reversible() {
        let buf = [
            0x01, 0x00, 0x41, 0xa8, 0x00, 0xe9, 0x03, 0x89, 0x65, 0xbf, 0x5d, 0xba, 0x00, 0x10,
            0x00, 0x00, 0x3a, 0xf2, 0x42, 0xc8, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x0a,
        ];
        assert_eq!(&Packet::try_from(&buf[..]).unwrap().as_ref(), &buf);
    }

    #[test]
    fn test_decode_evil_sequence() {
        let buf = [
            0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_err());
    }

    #[test]
    fn test_decode_empty_packet() {
        let packet = Packet::try_from(&[][..]);
        assert!(packet.is_err());
    }

    #[test]
    fn test_packet_set_type() {
        let mut packet = Packet::new();
        packet.set_type(PacketType::Syn);
        assert_eq!(packet.get_type(), PacketType::Syn);
        packet.set_type(PacketType::State);
        assert_eq!(packet.get_type(), PacketType::State);
        packet.set_type(PacketType::Fin);
        assert_eq!(packet.get_type(), PacketType::Fin);
        packet.set_type(PacketType::Reset);
        assert_eq!(packet.get_type(), PacketType::Reset);
        packet.set_type(PacketType::Data);
        assert_eq!(packet.get_type(), PacketType::Data);
    }

    #[test]
    fn test_packet_set_selective_acknowledgment() {
        let mut packet = Packet::new();
        packet.set_selective_ack(vec![1, 2, 3, 4]);

        {
            let extensions: Vec<Extension<'_>> = packet.extensions().collect();
            assert_eq!(extensions.len(), 1);
            assert_eq!(extensions[0].ty, ExtensionType::SelectiveAck);
            assert_eq!(extensions[0].data, &[1, 2, 3, 4]);
            assert_eq!(extensions[0].len(), extensions[0].data.len());
            assert_eq!(extensions[0].len(), 4);
        }

        // Add a second sack
        packet.set_selective_ack(vec![5, 6, 7, 8, 9, 10, 11, 12]);

        let extensions: Vec<Extension<'_>> = packet.extensions().collect();
        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions[0].ty, ExtensionType::SelectiveAck);
        assert_eq!(extensions[0].data, &[1, 2, 3, 4]);
        assert_eq!(extensions[0].len(), extensions[0].data.len());
        assert_eq!(extensions[0].len(), 4);
        assert_eq!(extensions[1].ty, ExtensionType::SelectiveAck);
        assert_eq!(extensions[1].data, &[5, 6, 7, 8, 9, 10, 11, 12]);
        assert_eq!(extensions[1].len(), extensions[1].data.len());
        assert_eq!(extensions[1].len(), 8);
    }

    // Use quickcheck to simulate a malicious attacker sending malformed packets
    #[test]
    fn quicktest() {
        fn run(x: Vec<u8>) -> TestResult {
            let packet = Packet::try_from(x.as_slice());

            if PacketHeader::try_from(x.as_slice())
                .and(check_extensions(x.as_slice()))
                .is_err()
            {
                TestResult::from_bool(packet.is_err())
            } else if let Ok(packet) = packet {
                TestResult::from_bool(packet.as_ref() == x.as_slice())
            } else {
                TestResult::from_bool(false)
            }
        }
        QuickCheck::new()
            .tests(10000)
            .quickcheck(run as fn(Vec<u8>) -> TestResult)
    }

    #[test]
    fn extension_iterator() {
        let buf = [
            0x21, 0x00, 0x41, 0xa8, 0x99, 0x2f, 0xd0, 0x2a, 0x9f, 0x4a, 0x26, 0x21, 0x00, 0x10,
            0x00, 0x00, 0x3a, 0xf2, 0x6c, 0x79,
        ];
        let packet = Packet::try_from(&buf[..]).unwrap();
        assert_eq!(packet.extensions().count(), 0);

        let buf = [
            0x21, 0x01, 0x41, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x05, 0xdc, 0xab, 0x53, 0x3a, 0xf5, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
        ];
        let packet = Packet::try_from(&buf[..]).unwrap();
        let extensions: Vec<Extension<'_>> = packet.extensions().collect();
        assert_eq!(extensions.len(), 1);
        assert_eq!(extensions[0].ty, ExtensionType::SelectiveAck);
        assert_eq!(extensions[0].data, &[0, 0, 0, 0]);
        assert_eq!(extensions[0].len(), extensions[0].data.len());
        assert_eq!(extensions[0].len(), 4);

        let buf = [
            0x21, 0x01, 0x41, 0xa7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x05, 0xdc, 0xab, 0x53, 0x3a, 0xf5, 0xff, 0x04, 0x01, 0x02, 0x03,
            0x04, // Imaginary extension
            0x00, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];

        let packet = Packet::try_from(&buf[..]).unwrap();
        let extensions: Vec<Extension<'_>> = packet.extensions().collect();
        assert_eq!(extensions.len(), 2);
        assert_eq!(extensions[0].ty, ExtensionType::SelectiveAck);
        assert_eq!(extensions[0].data, &[1, 2, 3, 4]);
        assert_eq!(extensions[0].len(), extensions[0].data.len());
        assert_eq!(extensions[0].len(), 4);
        assert_eq!(extensions[1].ty, ExtensionType::Unknown(0xff));
        assert_eq!(extensions[1].data, &[5, 6, 7, 8]);
        assert_eq!(extensions[1].len(), extensions[1].data.len());
        assert_eq!(extensions[1].len(), 4);
    }

    // https://github.com/ethereum/portal-network-specs/pull/127
    // konrad uTP test vectors

    #[test]
    fn test_syn_packet() {
        let mut packet = Packet::new();
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(10049);
        packet.set_timestamp(3384187322.into());
        packet.set_timestamp_difference(0.into());
        packet.set_wnd_size(1048576);
        packet.set_seq_nr(11884);
        packet.set_ack_nr(0);

        println!("packet: {:?}", packet);
        println!("packet raw: {:?}", packet.as_ref());

        assert_eq!(
            hex::encode(packet.as_ref()),
            "41002741c9b699ba00000000001000002e6c0000"
        );
    }

    #[test]
    fn test_act_packet_no_extension() {
        let mut packet = Packet::new();
        packet.set_type(PacketType::State);
        packet.set_connection_id(10049);
        packet.set_timestamp(6195294.into());
        packet.set_timestamp_difference(916973699.into());
        packet.set_wnd_size(1048576);
        packet.set_seq_nr(16807);
        packet.set_ack_nr(11885);

        assert_eq!(
            hex::encode(packet.as_ref()),
            "21002741005e885e36a7e8830010000041a72e6d"
        );
    }

    #[test]
    fn test_act_packet_with_selective_ack_extension() {
        let mut packet = Packet::new();
        packet.set_type(PacketType::State);
        packet.set_connection_id(10049);
        packet.set_timestamp(6195294.into());
        packet.set_timestamp_difference(916973699.into());
        packet.set_wnd_size(1048576);
        packet.set_seq_nr(16807);
        packet.set_ack_nr(11885);

        packet.set_selective_ack(vec![1, 0, 0, 128]);

        assert_eq!(
            hex::encode(packet.as_ref()),
            "21012741005e885e36a7e8830010000041a72e6d000401000080"
        );
    }

    #[test]
    fn test_data_packet() {
        let mut packet = Packet::with_payload(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        packet.set_type(PacketType::Data);
        packet.set_connection_id(26237);
        packet.set_timestamp(252492495.into());
        packet.set_timestamp_difference(242289855.into());
        packet.set_wnd_size(1048576);
        packet.set_seq_nr(8334);
        packet.set_ack_nr(16806);

        assert_eq!(
            hex::encode(packet.as_ref()),
            "0100667d0f0cbacf0e710cbf00100000208e41a600010203040506070809"
        );
    }

    #[test]
    fn test_fin_packet() {
        let mut packet = Packet::new();
        packet.set_type(PacketType::Fin);
        packet.set_connection_id(19003);
        packet.set_timestamp(515227279.into());
        packet.set_timestamp_difference(511481041.into());
        packet.set_wnd_size(1048576);
        packet.set_seq_nr(41050);
        packet.set_ack_nr(16806);

        assert_eq!(
            hex::encode(packet.as_ref()),
            "11004a3b1eb5be8f1e7c94d100100000a05a41a6"
        );
    }

    #[test]
    fn test_reset_packet() {
        let mut packet = Packet::new();
        packet.set_type(PacketType::Reset);
        packet.set_connection_id(62285);
        packet.set_timestamp(751226811.into());
        packet.set_timestamp_difference(0.into());
        packet.set_wnd_size(0);
        packet.set_seq_nr(55413);
        packet.set_ack_nr(16807);

        assert_eq!(
            hex::encode(packet.as_ref()),
            "3100f34d2cc6cfbb0000000000000000d87541a7"
        );
    }
}
