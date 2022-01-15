pub const HEADER_SIZE: usize = 20;
pub const VERSION: u8 = 1;

#[derive(PartialEq, Debug)]
pub enum PacketType {
    Data,
    Fin,
    State,
    Reset,
    Syn,
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

impl<'a> TryFrom<&'a [u8]> for PacketHeader {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < HEADER_SIZE {
            return Err("invalid header size");
        }

        if value[0] & 0xf != VERSION {
            return Err("invalid packet version");
        }

        if let Err(e) = PacketType::try_from(value[0] >> 4) {
            return Err(e);
        }

        Ok(PacketHeader::decode(value))
    }
}

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

impl<'a> TryFrom<&'a [u8]> for Packet {
    type Error = &'static str;

    // todo: Added support to check validity of extensions,
    // we don't need to worry about checking payloads
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match PacketHeader::try_from(value).and(check_extensions(value)) {
            Ok(_) => Ok(Packet(value.to_owned())),
            Err(e) => Err(e),
        }
    }
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct PacketHeader {
    type_ver: u8,
    extension: u8,
    connection_id: u16,
    // This time is in microseconds
    timestamp: u32,
    timestamp_difference: u32,
    wnd_size: u32,
    pub seq_nr: u16,
    ack_nr: u16,
}

impl PacketHeader {
    pub fn new() -> Self {
        PacketHeader {
            type_ver: u8::from(PacketType::Data) << 4 | VERSION,
            extension: 0,
            connection_id: 0,
            timestamp: 0,
            timestamp_difference: 0,
            wnd_size: 0xf000,
            seq_nr: 0,
            ack_nr: 0,
        }
    }

    pub fn encode(&mut self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend_from_slice(&[self.type_ver]);
        buf.extend_from_slice(&[self.extension]);
        buf.extend_from_slice(&self.connection_id.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.timestamp_difference.to_be_bytes());
        buf.extend_from_slice(&self.wnd_size.to_be_bytes());
        buf.extend_from_slice(&self.seq_nr.to_be_bytes());
        buf.extend_from_slice(&self.ack_nr.to_be_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> PacketHeader {
        PacketHeader {
            type_ver: bytes[0],
            extension: bytes[1],
            connection_id: u16::from_be_bytes([bytes[2], bytes[3]]),
            timestamp: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            timestamp_difference: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            wnd_size: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
            seq_nr: u16::from_be_bytes([bytes[16], bytes[17]]),
            ack_nr: u16::from_be_bytes([bytes[18], bytes[19]]),
        }
    }

    pub fn version(&self) -> u8 {
        self.type_ver & 0xf
    }
    pub fn set_version(&mut self, int: u8) {
        self.type_ver = (self.type_ver & 0xf0) | (int & 0xf)
    }
    pub fn type_(&self) -> PacketType {
        PacketType::try_from(self.type_ver >> 4).unwrap()
    }
    pub fn set_type(&mut self, t: PacketType) {
        self.type_ver = (self.type_ver & 0xf) | (u8::from(t) << 4)
    }

    pub fn set_connection_id(&mut self, connection_id: u16) {
        self.connection_id = connection_id;
    }

    pub fn set_timestamp(&mut self, timestamp: u32) {
        self.timestamp = timestamp;
    }

    pub fn set_timestamp_difference(&mut self, timestamp_difference: u32) {
        self.timestamp_difference = timestamp_difference;
    }

    pub fn set_wnd_size(&mut self, wnd_size: u32) {
        self.wnd_size = wnd_size;
    }

    pub fn set_seq_nr(&mut self, seq_nr: u16) {
        self.seq_nr = seq_nr;
    }

    pub fn set_ack_nr(&mut self, ack_nr: u16) {
        self.ack_nr = ack_nr;
    }
}

#[derive(Debug)]
pub struct Extension {
    pub extension_type: u8,
    pub len: u8,
    pub bitmask: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Packet(pub Vec<u8>);

impl Packet {
    pub fn new(mut packet_header: PacketHeader) -> Packet {
        let mut vec = Vec::with_capacity(HEADER_SIZE);
        vec.append(&mut packet_header.encode());
        Packet(vec)
    }

    pub fn with_payload(mut packet_header: PacketHeader, payload: &[u8]) -> Packet {
        let mut vec = Vec::with_capacity(HEADER_SIZE + payload.len());
        vec.append(&mut packet_header.encode());
        vec.extend_from_slice(payload);
        Packet(vec)
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    pub fn get_header(&self) -> PacketHeader {
        PacketHeader::decode(&self.0[0..20])
    }

    pub fn type_(&self) -> PacketType {
        self.get_header().type_()
    }

    pub fn version(&self) -> u8 {
        self.get_header().version()
    }

    pub fn extension(&self) -> u8 {
        self.get_header().extension
    }

    pub fn connection_id(&self) -> u16 {
        self.get_header().connection_id
    }

    pub fn timestamp(&self) -> u32 {
        self.get_header().timestamp
    }

    pub fn timestamp_difference(&self) -> u32 {
        self.get_header().timestamp_difference
    }

    pub fn wnd_size(&self) -> u32 {
        self.get_header().wnd_size
    }

    pub fn seq_nr(&self) -> u16 {
        self.get_header().seq_nr
    }

    pub fn ack_nr(&self) -> u16 {
        self.get_header().ack_nr
    }

    pub fn get_extensions(&self) -> Vec<Extension> {
        let mut extensions: Vec<Extension> = Vec::default();
        let mut extension = self.extension();
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
        let mut extension = self.extension();
        let mut payload_begins = HEADER_SIZE;
        while extension != 0 {
            extension = self.0[payload_begins];
            let len = self.0[payload_begins + 1];
            payload_begins += (len + 2) as usize;
        }
        &self.0[payload_begins..]
    }

    pub fn set_selective_ack(&mut self, sack_bitfield: Vec<u8>) {
        let mut extension = self.extension();
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
