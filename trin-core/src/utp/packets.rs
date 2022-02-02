use std::fmt;

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

#[derive(PartialEq, Debug)]
pub enum PacketType {
    Data,  // packet carries a data payload
    Fin,   // signals the end of a connection
    State, // signals acknowledgment of a packet
    Reset, // forcibly terminates a connection
    Syn,   // initiates a new connection with a peer
}

impl TryFrom<u8> for PacketType {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketType::Data),
            1 => Ok(PacketType::Fin),
            2 => Ok(PacketType::State),
            3 => Ok(PacketType::Reset),
            4 => Ok(PacketType::Syn),
            _ => Err("invalid packet type"),
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
fn check_extensions(data: &[u8]) -> Result<(), &'static str> {
    if data.len() < HEADER_SIZE {
        return Err("invalid header size");
    }

    let mut extension = data[1];
    let mut index = HEADER_SIZE;

    // must be at least 4 bytes, and in multiples of 4
    while extension != 0 {
        if data.len() < index + 2 {
            return Err("Invalid packet length");
        }
        extension = data[index];
        let len = data[index + 1] as usize;

        if len == 0 || len % 4 != 0 || len + index + 2 > data.len() {
            return Err("Invalid Extension Length");
        }

        index += len + 2;
    }
    Ok(())
}

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
}

impl<'a> TryFrom<&'a [u8]> for PacketHeader {
    // TODO: Refactor this to use anyhow crate
    type Error = &'static str;
    /// Reads a byte buffer and returns the corresponding packet header.
    /// It assumes the fields are in network (big-endian) byte order,
    /// preserving it.
    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        // Check length
        if buf.len() < HEADER_SIZE {
            return Err("The packet is too small");
        }

        // Check version
        if buf[0] & 0x0F != VERSION {
            return Err("Unsupported packet version");
        }

        // Check packet type
        if let Err(e) = PacketType::try_from(buf[0] >> 4) {
            return Err(e);
        }

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

#[derive(Debug)]
pub struct Extension {
    pub extension_type: u8,
    pub len: u8,
    pub bitmask: Vec<u8>,
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

    // TODO: Add ExtensionType struct instead of raw u8
    pub fn get_extension_type(&self) -> u8 {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        header.extension
    }

    // TODO: Return use Timestamp and Delay data structures instead of u32 in the following methods
    pub fn timestamp(&self) -> u32 {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        header.timestamp_microseconds.to_be()
    }

    pub fn set_timestamp(&mut self, timestamp: u32) {
        let header = unsafe { &mut *(self.0.as_mut_ptr() as *mut PacketHeader) };
        header.timestamp_microseconds = timestamp.to_be()
    }

    pub fn timestamp_difference(&self) -> u32 {
        let header = unsafe { &*(self.0.as_ptr() as *const PacketHeader) };
        header.timestamp_difference_microseconds.to_be()
    }

    pub fn set_timestamp_difference(&mut self, delay: u32) {
        let header = unsafe { &mut *(self.0.as_mut_ptr() as *mut PacketHeader) };
        header.timestamp_difference_microseconds = delay.to_be()
    }

    make_getter!(seq_nr, u16, u16);
    make_getter!(ack_nr, u16, u16);
    make_getter!(connection_id, u16, u16);
    make_getter!(wnd_size, u32, u32);

    make_setter!(set_seq_nr, seq_nr, u16);
    make_setter!(set_ack_nr, ack_nr, u16);
    make_setter!(set_connection_id, connection_id, u16);
    make_setter!(set_wnd_size, wnd_size, u32);

    pub fn get_extensions(&self) -> Vec<Extension> {
        let mut extensions: Vec<Extension> = Vec::default();
        let mut extension = self.get_extension_type();
        let mut extension_begins = HEADER_SIZE;
        while extension != 0 {
            let len = self.0[extension_begins + 1];
            let ext = Extension {
                extension_type: extension,
                len,
                bitmask: Vec::from(
                    &self.0[(extension_begins + 2)..(extension_begins + len as usize + 2)],
                ),
            };
            extensions.push(ext);

            extension = self.0[extension_begins];
            extension_begins += (len + 2) as usize;
        }
        extensions
    }

    pub fn get_payload(&self) -> &[u8] {
        let mut extension = self.get_extension_type();
        let mut payload_begins = HEADER_SIZE;
        while extension != 0 {
            extension = self.0[payload_begins];
            let len = self.0[payload_begins + 1];
            payload_begins += (len + 2) as usize;
        }
        &self.0[payload_begins..]
    }

    pub fn set_selective_ack(&mut self, sack_bitfield: Vec<u8>) {
        let mut extension = self.get_extension_type();
        let mut extension_begins = HEADER_SIZE;

        if !sack_bitfield.is_empty() {
            if self.0[1] == 0 {
                self.0[1] = 1;
            } else {
                while extension != 0 {
                    extension = self.0[extension_begins];
                    let len = self.0[extension_begins + 1];
                    extension_begins += (len + 2) as usize;

                    if extension == 0 {
                        self.0[extension_begins] = 1;
                    }
                }
            }

            self.0.insert(extension_begins, 0);
            self.0
                .insert(extension_begins + 1, sack_bitfield.len() as u8);
            for (i, byte) in sack_bitfield.iter().enumerate() {
                self.0.insert(extension_begins + 2 + i, *byte);
            }
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for Packet {
    // TODO: Refactor error to use anyhow crate
    type Error = &'static str;

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
