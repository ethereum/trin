#![allow(dead_code)]

use super::discovery::Discovery;
use core::convert::TryFrom;
use discv5::enr::NodeId;
use discv5::Enr;
use log::debug;
use rand::Rng;
use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::portalnet::types::messages::ProtocolId;

pub const HEADER_SIZE: usize = 20;
pub const MAX_DISCV5_PACKET_SIZE: usize = 1280;
pub const MIN_PACKET_SIZE: usize = 150;
const MIN_DISCV5_PACKET_SIZE: usize = 63;
// 100 miliseconds
const CCONTROL_TARGET: usize = 100 * 1000;
const MAX_CWND_INCREASE_BYTES_PER_RTT: usize = 3000;
const MIN_WINDOW_SIZE: usize = 10;
const VERSION: u8 = 1;

#[derive(PartialEq, Debug)]
enum Type {
    StData,
    StFin,
    StState,
    StReset,
    StSyn,
}

impl TryFrom<u8> for Type {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Type::StData),
            1 => Ok(Type::StFin),
            2 => Ok(Type::StState),
            3 => Ok(Type::StReset),
            4 => Ok(Type::StSyn),
            _ => Err("invalid packet type"),
        }
    }
}

impl From<Type> for u8 {
    fn from(value: Type) -> u8 {
        match value {
            Type::StData => 0,
            Type::StFin => 1,
            Type::StState => 2,
            Type::StReset => 3,
            Type::StSyn => 4,
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

        if let Err(e) = Type::try_from(value[0] >> 4) {
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

#[derive(Debug)]
struct PacketHeader {
    type_ver: u8,
    extension: u8,
    connection_id: u16,
    // This time is in microseconds
    timestamp: u32,
    timestamp_difference: u32,
    wnd_size: u32,
    seq_nr: u16,
    ack_nr: u16,
}

impl PacketHeader {
    fn new() -> Self {
        PacketHeader {
            type_ver: u8::from(Type::StData) << 4 | VERSION,
            extension: 0,
            connection_id: 0,
            timestamp: 0,
            timestamp_difference: 0,
            wnd_size: 0xf000,
            seq_nr: 0,
            ack_nr: 0,
        }
    }

    fn encode(&mut self) -> Vec<u8> {
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

    fn decode(bytes: &[u8]) -> PacketHeader {
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

    fn version(&self) -> u8 {
        self.type_ver & 0xf
    }
    fn set_version(&mut self, int: u8) {
        self.type_ver = (self.type_ver & 0xf0) | (int & 0xf)
    }
    fn type_(&self) -> Type {
        Type::try_from(self.type_ver >> 4).unwrap()
    }
    fn set_type(&mut self, t: Type) {
        self.type_ver = (self.type_ver & 0xf) | (u8::from(t) << 4)
    }

    fn set_connection_id(&mut self, connection_id: u16) {
        self.connection_id = connection_id;
    }

    fn set_timestamp(&mut self, timestamp: u32) {
        self.timestamp = timestamp;
    }

    fn set_timestamp_difference(&mut self, timestamp_difference: u32) {
        self.timestamp_difference = timestamp_difference;
    }

    fn set_wnd_size(&mut self, wnd_size: u32) {
        self.wnd_size = wnd_size;
    }

    fn set_seq_nr(&mut self, seq_nr: u16) {
        self.seq_nr = seq_nr;
    }

    fn set_ack_nr(&mut self, ack_nr: u16) {
        self.ack_nr = ack_nr;
    }
}

#[derive(Debug)]
struct Extension {
    extension_type: u8,
    len: u8,
    bitmask: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Packet(Vec<u8>);

impl Packet {
    fn new(mut packet_header: PacketHeader) -> Packet {
        let mut vec = Vec::with_capacity(HEADER_SIZE);
        vec.append(&mut packet_header.encode());
        Packet(vec)
    }

    fn with_payload(mut packet_header: PacketHeader, payload: &[u8]) -> Packet {
        let mut vec = Vec::with_capacity(HEADER_SIZE + payload.len());
        vec.append(&mut packet_header.encode());
        vec.extend_from_slice(payload);
        Packet(vec)
    }

    fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    fn get_header(&self) -> PacketHeader {
        PacketHeader::decode(&self.0[0..20])
    }

    fn type_(&self) -> Type {
        self.get_header().type_()
    }

    fn version(&self) -> u8 {
        self.get_header().version()
    }

    fn extension(&self) -> u8 {
        self.get_header().extension
    }

    fn connection_id(&self) -> u16 {
        self.get_header().connection_id
    }

    fn timestamp(&self) -> u32 {
        self.get_header().timestamp
    }

    fn timestamp_difference(&self) -> u32 {
        self.get_header().timestamp_difference
    }

    fn wnd_size(&self) -> u32 {
        self.get_header().wnd_size
    }

    fn seq_nr(&self) -> u16 {
        self.get_header().seq_nr
    }

    fn ack_nr(&self) -> u16 {
        self.get_header().ack_nr
    }

    fn get_extensions(&self) -> Vec<Extension> {
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

    fn get_payload(&self) -> &[u8] {
        let mut extension = self.extension();
        let mut payload_begins = HEADER_SIZE;
        while extension != 0 {
            extension = self.0[payload_begins];
            let len = self.0[payload_begins + 1];
            payload_begins += (len + 2) as usize;
        }
        &self.0[payload_begins..]
    }

    fn set_selective_ack(&mut self, incoming_buffer: &BTreeMap<u16, Packet>, ack_nr: u16) {
        // must be at least 4 bytes, and in multiples of 4
        let incoming = incoming_buffer.range((ack_nr + 2)..);
        let len = incoming.clone().count();
        let k = if len % 32 != 0 {
            (len / 32) + 1
        } else {
            len / 32
        };

        let mut sack_bitfield: Vec<u8> = vec![0u8; k * 4];

        for (seq, _) in incoming {
            let v = (seq - ack_nr - 2) as usize;
            let (index, offset) = (v / 8, v % 8);
            sack_bitfield[index] |= 1 << offset;
        }

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

fn get_time() -> u32 {
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros()
        & 0xffffffff) as u32
}

fn get_time_diff(response_time: u32) -> u32 {
    let current_time = get_time();

    if current_time > response_time {
        current_time - response_time
    } else {
        response_time - current_time
    }
}

fn rand() -> u16 {
    rand::thread_rng().gen()
}

#[derive(PartialEq, Clone)]
enum ConnectionState {
    Uninitialized,
    SynSent,
    SynRecv,
    Connected,
    Disconnected,
}

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug)]
pub struct ConnectionKey {
    node_id: NodeId,
    conn_id_recv: u16,
}

impl ConnectionKey {
    fn new(node_id: NodeId, conn_id_recv: u16) -> Self {
        Self {
            node_id,
            conn_id_recv,
        }
    }
}

// Basically the same idea as in the official Bit Torrent library we will store all of the active connections data here
pub struct UtpListener {
    pub discovery: Arc<Discovery>,
    pub utp_connections: HashMap<ConnectionKey, UtpStream>,
}

impl UtpListener {
    pub async fn process_utp_request(&mut self, payload: &[u8], node_id: &NodeId) {
        match Packet::try_from(payload) {
            Ok(packet) => {
                let connection_id = packet.connection_id();

                match packet.type_() {
                    Type::StReset => {
                        let key_fn = |offset| {
                            ConnectionKey::new(node_id.clone(), connection_id - 1 + offset)
                        };
                        let f =
                            |conn: &&mut UtpStream| -> bool { conn.conn_id_send == connection_id };

                        if let Some(conn) = self.utp_connections.get_mut(&key_fn(1)) {
                            conn.state = ConnectionState::Disconnected;
                        } else if let Some(conn) =
                            self.utp_connections.get_mut(&key_fn(2)).filter(f)
                        {
                            conn.state = ConnectionState::Disconnected;
                        } else if let Some(conn) =
                            self.utp_connections.get_mut(&key_fn(0)).filter(f)
                        {
                            conn.state = ConnectionState::Disconnected;
                        }
                    }
                    Type::StSyn => {
                        if let Some(enr) = self.discovery.discv5.find_enr(&node_id) {
                            // If neither of those cases happened handle this is a new request
                            let mut conn = UtpStream::init(Arc::clone(&self.discovery), enr);
                            conn.handle_packet(packet).await;
                            self.utp_connections.insert(
                                ConnectionKey {
                                    node_id: node_id.clone(),
                                    conn_id_recv: conn.conn_id_recv,
                                },
                                conn,
                            );
                        } else {
                            debug!("Query requested an unknown ENR");
                        }
                    }
                    _ => {
                        if let Some(conn) = self.utp_connections.get_mut(&ConnectionKey {
                            node_id: node_id.clone(),
                            conn_id_recv: connection_id,
                        }) {
                            conn.handle_packet(packet).await;
                        }
                    }
                }
            }
            Err(e) => {
                debug!("Failed to decode packet: {}", e);
            }
        }
    }

    // I am honestly not sure if I should init this with Enr or NodeId since we could use both
    async fn connect(&mut self, connection_id: u16, node_id: NodeId) {
        if let Some(enr) = self.discovery.discv5.find_enr(&node_id) {
            let mut conn = UtpStream::init(Arc::clone(&self.discovery), enr);
            conn.make_connection(connection_id).await;
            self.utp_connections.insert(
                ConnectionKey {
                    node_id,
                    conn_id_recv: connection_id,
                },
                conn,
            );
        }
    }
}

// Used to be MicroTransportProtocol impl but it is basically just called UtpStream compared to the
// Rust Tcp Lib so I changed it
pub struct UtpStream {
    state: ConnectionState,
    seq_nr: u16,
    ack_nr: u16,
    conn_id_recv: u16,
    conn_id_send: u16,
    // maximum window size, in bytes
    max_window: u32,
    // A buffer of packets will be sorted and concatenated on socket close.
    // <seq_nr, packet>
    incoming_buffer: BTreeMap<u16, Packet>,
    unsent_queue: VecDeque<Packet>,
    enr: Enr,
    discovery: Arc<Discovery>,
    cur_window: u32,
    remote_wnd_size: u32,
    send_window: HashMap<u16, Packet>,
    // counts the amount of acks
    duplicate_acks: u8,
    // stores the last ack we seen
    last_ack: u16,
    // round trip time
    rtt: i32,
    // rtt variance
    rtt_var: i32,
    base_delay: Vec<u32>,
    timeout: u64,
    last_rollover: u32,
    current_delay: Vec<u32>,
    pub recv_data_stream: Vec<u8>,
}

impl UtpStream {
    fn init(arc: Arc<Discovery>, enr: Enr) -> Self {
        Self {
            state: ConnectionState::Uninitialized,
            seq_nr: 0,
            ack_nr: 0,
            conn_id_recv: 0,
            conn_id_send: 0,
            max_window: 0,
            incoming_buffer: Default::default(),
            unsent_queue: Default::default(),
            enr,
            discovery: arc,
            cur_window: 0,
            remote_wnd_size: 0,
            send_window: Default::default(),
            duplicate_acks: 0,
            last_ack: 0,
            rtt: 0,
            rtt_var: 0,
            base_delay: vec![],
            timeout: 1000,
            last_rollover: 0,
            current_delay: Vec::with_capacity(8),
            recv_data_stream: vec![],
        }
    }

    // If you want to send a payload call this it is basically just write
    async fn write(&mut self, message: &[u8]) {
        for chunk in message.chunks(MAX_DISCV5_PACKET_SIZE - MIN_DISCV5_PACKET_SIZE - HEADER_SIZE) {
            let mut response = PacketHeader::new();
            response.set_type(Type::StData);
            response.set_connection_id(self.conn_id_send);
            response.set_timestamp(get_time());
            response.set_timestamp_difference(0);
            response.set_seq_nr(self.seq_nr);
            response.set_ack_nr(self.ack_nr);

            self.seq_nr = self.seq_nr + 1;
            let packet = Packet::with_payload(response, chunk);
            self.unsent_queue.push_back(packet)
        }

        self.send_packets_in_queue().await;
    }

    async fn send_packets_in_queue(&mut self) {
        while let Some(packet) = self.unsent_queue.pop_front() {
            self.send(&packet).await;
            self.cur_window += packet.0.len() as u32;
            self.send_window.insert(packet.get_header().seq_nr, packet);
        }
    }

    async fn resend_packet(&self, seq_nr: u16) {
        if let Some(packet) = self.send_window.get(&seq_nr) {
            self.send(&packet).await;
        }
    }

    async fn send(&self, packet: &Packet) {
        let max_send = max(
            MAX_DISCV5_PACKET_SIZE,
            min(self.max_window as usize, self.remote_wnd_size as usize),
        );
        while self.cur_window + packet.0.len() as u32 > max_send as u32 {
            // I might change the amount of milliseconds later, but this sleep is just so
            // It doesn't waste cpu cycles well waiting.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let talk_request_result = self
            .discovery
            .send_talk_req(self.enr.clone(), ProtocolId::Utp, packet.0.clone())
            .await;
        debug!("uTP TalkRequest result: {:?}", talk_request_result);
    }

    fn update_base_delay(&mut self, delay: u32, now: u32) {
        if now - self.last_rollover > 60 * 1000 {
            self.last_rollover = now;
            if self.base_delay.len() == 10 {
                self.base_delay.remove(0);
            }
            self.base_delay.push(delay);
        } else {
            let index = self.base_delay.len() - 1;
            self.base_delay[index] = min(self.base_delay[index], delay);
        }
    }

    fn update_current_delay(&mut self, delay: u32) {
        if self.current_delay.len() < 8 {
            self.current_delay.push(delay);
        } else {
            self.current_delay = self.current_delay[1..].to_owned();
            self.current_delay.push(delay);
        }
    }

    fn filter(current_delay: &Vec<u32>) -> u32 {
        let filt = (current_delay.len() as f64 / 3_f64).ceil() as usize;
        *current_delay[current_delay.len() - filt..]
            .iter()
            .min()
            .unwrap()
    }

    async fn make_connection(&mut self, connection_id: u16) {
        if self.state == ConnectionState::Uninitialized {
            self.state = ConnectionState::SynSent;
            self.seq_nr = 1;
            self.conn_id_recv = connection_id;
            self.conn_id_send = self.conn_id_recv + 1;

            let mut response = PacketHeader::new();
            response.set_type(Type::StSyn);
            response.set_connection_id(self.conn_id_recv);
            response.set_timestamp(get_time());
            response.set_timestamp_difference(0);
            response.set_seq_nr(self.seq_nr + 1);
            response.set_ack_nr(0);

            self.send(&Packet::new(response)).await;
        }
    }

    async fn make_connection_rand_id(&mut self) {
        self.state = ConnectionState::SynSent;
        self.seq_nr = 1;
        self.conn_id_recv = rand();
        self.conn_id_send = self.conn_id_recv + 1;

        let mut response = PacketHeader::new();
        response.set_type(Type::StSyn);
        response.set_connection_id(self.conn_id_recv);
        response.set_timestamp(get_time());
        response.set_timestamp_difference(0);
        response.set_seq_nr(self.seq_nr + 1);
        response.set_ack_nr(0);

        self.send(&Packet::new(response)).await;
    }

    async fn send_finalize(&self) {
        let mut response = PacketHeader::new();
        response.set_type(Type::StReset);
        response.set_connection_id(self.conn_id_send);
        response.set_timestamp(get_time());
        response.set_timestamp_difference(0);
        response.set_seq_nr(self.seq_nr + 1);
        response.set_ack_nr(0);

        self.send(&Packet::new(response)).await;
    }

    async fn handle_packet(&mut self, packet: Packet) {
        self.remote_wnd_size = packet.wnd_size();

        // Only acknowledge this if this follows the last one, else do it when we advance the send
        // window
        if packet.seq_nr().wrapping_sub(self.ack_nr) == 1 {
            self.ack_nr = packet.seq_nr();
        }

        match packet.type_() {
            Type::StData => self.handle_data_packet(packet).await,
            Type::StFin => self.handle_finalize_packet(packet).await,
            Type::StState => self.handle_state_packet(packet).await,
            Type::StReset => assert!(false, "StReset should never make it here"),
            Type::StSyn => self.handle_syn_packet(packet).await,
        }
    }

    async fn handle_data_packet(&mut self, packet: Packet) {
        if self.state == ConnectionState::SynRecv {
            self.state = ConnectionState::Connected
        }

        let mut response = PacketHeader::new();
        response.set_type(Type::StState);
        response.set_connection_id(self.conn_id_send);
        response.set_timestamp(get_time());
        response.set_timestamp_difference(get_time_diff(packet.timestamp()));
        response.set_seq_nr(self.seq_nr);
        response.set_ack_nr(self.ack_nr);

        let mut reply = Packet::new(response);
        if packet.seq_nr().wrapping_sub(self.ack_nr) > 1 {
            reply.set_selective_ack(&self.incoming_buffer, self.ack_nr);
        }

        self.send(&reply).await;

        // Add packet to BTreeMap
        self.incoming_buffer.insert(packet.seq_nr(), packet);

        // TODO: use pop_front when it is in a stable release
        if let Some(packet_from_buffer) = self.incoming_buffer.clone().values().next() {
            let packet_seq = packet_from_buffer.seq_nr();
            if !self.incoming_buffer.is_empty()
                && (self.ack_nr == packet_seq || self.ack_nr + 1 == packet_seq)
            {
                self.incoming_buffer.remove(&packet_seq);
                self.ack_nr = packet_seq;

                self.recv_data_stream
                    .append(&mut Vec::from(packet_from_buffer.get_payload()));
            }
        }
    }

    async fn handle_state_packet(&mut self, packet: Packet) {
        if self.state == ConnectionState::SynSent {
            self.state = ConnectionState::Connected;
            self.ack_nr = packet.seq_nr() - 1;
        } else {
            if self.last_ack == packet.ack_nr() {
                self.duplicate_acks += 1;
            } else {
                self.last_ack = packet.ack_nr();
                self.duplicate_acks = 1;
            }

            // handle timeouts and congestion window
            if let Some(stored_packet) = self.send_window.get(&packet.ack_nr()) {
                let now = get_time();
                let our_delay = now - stored_packet.timestamp();
                self.update_base_delay(our_delay, now);
                self.update_current_delay(our_delay);
                let queuing_delay =
                    UtpStream::filter(&self.current_delay) - self.base_delay.iter().min().unwrap();

                self.update_congestion_window(&packet, queuing_delay);
                self.update_timeout(our_delay, queuing_delay);
            }

            let mut packet_loss_detected = false;
            let mut already_resent_ack_1 = false;
            for extension in &packet.get_extensions() {
                // The only extension we support is 1 selective acks, some clients support
                // others tho.
                if extension.extension_type == 1 {
                    self.resend_packet(packet.ack_nr() + 1).await;
                    already_resent_ack_1 = true;
                    packet_loss_detected = true;
                }

                if let Some((last_seq_nr, _)) = self.send_window.iter().last() {
                    // I need to iterate over this starting with least sig byte per byte
                    // then move right after
                    let mut k = 0;
                    for byte in &extension.bitmask {
                        for i in 0..8 {
                            let (bit, seq_nr) = ((byte >> i) & 1, packet.ack_nr() + 2 + k);
                            if bit == 0 && seq_nr < *last_seq_nr {
                                self.resend_packet(seq_nr).await;
                                packet_loss_detected = true;
                            }
                            k += 1;
                        }
                    }
                }
            }

            if self.duplicate_acks == 3 && !already_resent_ack_1 {
                self.resend_packet(packet.ack_nr() + 1).await;
                packet_loss_detected = true;
            }

            if packet_loss_detected {
                self.max_window = self.max_window / 2;
            }

            // acknowledge received packet
            if let Some(stored_packet) = self.send_window.get(&packet.ack_nr()) {
                let seq_nr = stored_packet.seq_nr();
                let len = stored_packet.0.len() as u32;
                self.send_window.remove(&seq_nr);
                self.cur_window -= len;
            }
        }
    }

    fn update_congestion_window(&mut self, packet: &Packet, queuing_delay: u32) {
        // LEDBAT congestion control
        // todo: I will need to add support for bytes_acked to also consider selective
        // acks when they are implemented
        let mut bytes_acked = 0;
        for (i, stored_packet) in self.send_window.iter() {
            if &packet.ack_nr() <= i {
                bytes_acked += stored_packet.0.len();
            }
        }

        let off_target = (CCONTROL_TARGET as f64 - queuing_delay as f64) / CCONTROL_TARGET as f64;
        let window_factor = (min(bytes_acked, self.max_window as usize)
            / max(self.max_window as usize, bytes_acked)) as f64;
        let scaled_gain =
            (MAX_CWND_INCREASE_BYTES_PER_RTT as f64 * off_target * window_factor) as u32;

        self.max_window += scaled_gain;
    }

    fn update_timeout(&mut self, our_delay: u32, queuing_delay: u32) {
        let packet_rtt = (our_delay - queuing_delay) as i32;
        let delta = self.rtt - packet_rtt;
        self.rtt_var += (delta - self.rtt_var) / 4;
        self.rtt += (packet_rtt - self.rtt) / 8;
        self.timeout = max((self.rtt + self.rtt_var * 4) as u64, 500);
    }

    async fn handle_finalize_packet(&mut self, packet: Packet) {
        if self.state == ConnectionState::Connected {
            self.state = ConnectionState::Disconnected;

            let mut response = PacketHeader::new();
            response.set_type(Type::StFin);
            response.set_connection_id(self.conn_id_send);
            response.set_timestamp(get_time());
            response.set_timestamp_difference(get_time_diff(packet.timestamp()));
            response.set_seq_nr(self.seq_nr);
            response.set_ack_nr(self.ack_nr);

            self.send(&Packet::new(response)).await;
        }
    }

    async fn handle_syn_packet(&mut self, packet: Packet) {
        self.conn_id_recv = packet.connection_id() + 1;
        self.conn_id_send = packet.connection_id();
        self.seq_nr = rand();
        self.ack_nr = packet.seq_nr();
        self.state = ConnectionState::SynRecv;

        let mut response = PacketHeader::new();
        response.set_type(Type::StState);
        response.set_connection_id(self.conn_id_send);
        response.set_timestamp(get_time());
        response.set_timestamp_difference(get_time_diff(packet.timestamp()));
        response.set_seq_nr(self.seq_nr);
        response.set_ack_nr(self.ack_nr);

        self.send(&Packet::new(response)).await;
    }
}

#[cfg(test)]
mod tests {
    use crate::portalnet::utp::{Packet, PacketHeader, Type, VERSION};
    use std::collections::BTreeMap;
    use std::convert::TryFrom;

    #[test]
    fn test_decode_packet() {
        let buf = [
            0x21, 0x0, 0xA4, 0x46, 0xA7, 0x3E, 0xF4, 0x40, 0x0, 0x0, 0x27, 0x10, 0x0, 0x0, 0xF0,
            0x0, 0x3C, 0x2C, 0x7E, 0xB5,
        ];

        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.type_(), Type::StState);
        assert_eq!(packet.version(), VERSION);
        assert_eq!(packet.extension(), 0);
        assert_eq!(packet.connection_id(), 42054);
        assert_eq!(packet.timestamp(), 2805920832);
        assert_eq!(packet.timestamp_difference(), 10000);
        assert_eq!(packet.wnd_size(), 61440);
        assert_eq!(packet.seq_nr(), 15404);
        assert_eq!(packet.ack_nr(), 32437);
        assert!(packet.get_payload().is_empty());
    }

    #[test]
    fn test_decode_packet_with_extension() {
        let buf = [
            0x21, 0x1, 0xA4, 0x46, 0xA7, 0x3E, 0xF4, 0x40, 0x0, 0x0, 0x27, 0x10, 0x0, 0x0, 0xF0,
            0x0, 0x3C, 0x2C, 0x7E, 0xB5, 0x0, 0x4, 0xAA, 0x3C, 0x5F, 0x0,
        ];

        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_ok());
        let packet = packet.unwrap();
        assert_eq!(packet.type_(), Type::StState);
        assert_eq!(packet.version(), VERSION);
        assert_eq!(packet.extension(), 1);
        assert_eq!(packet.connection_id(), 42054);
        assert_eq!(packet.timestamp(), 2805920832);
        assert_eq!(packet.timestamp_difference(), 10000);
        assert_eq!(packet.wnd_size(), 61440);
        assert_eq!(packet.seq_nr(), 15404);
        assert_eq!(packet.ack_nr(), 32437);
        assert!(packet.get_payload().is_empty());
    }

    #[test]
    fn test_decode_packet_with_invalid_extension() {
        let buf = [
            0x21, 0x1, 0xA4, 0x46, 0xA7, 0x3E, 0xF4, 0x40, 0x0, 0x0, 0x27, 0x10, 0x0, 0x0, 0xF0,
            0x0, 0x3C, 0x2C, 0x7E, 0xB5, 0x0, 0x4, 0xAA, 0x3C, 0x0,
        ];

        let packet = Packet::try_from(&buf[..]);
        assert!(packet.is_err());
    }

    #[test]
    fn test_encode_packet() {
        let mut response = PacketHeader::new();
        response.set_type(Type::StData);
        response.set_connection_id(49300);
        response.set_timestamp(2805920832);
        response.set_timestamp_difference(1805367832);
        response.set_wnd_size(61440);
        response.set_seq_nr(12044);
        response.set_ack_nr(12024);

        let packet = Packet::new(response);
        assert_eq!(packet.type_(), Type::StData);
        assert_eq!(packet.version(), VERSION);
        assert_eq!(packet.extension(), 0);
        assert_eq!(packet.connection_id(), 49300);
        assert_eq!(packet.timestamp(), 2805920832);
        assert_eq!(packet.timestamp_difference(), 1805367832);
        assert_eq!(packet.wnd_size(), 61440);
        assert_eq!(packet.seq_nr(), 12044);
        assert_eq!(packet.ack_nr(), 12024);
        assert!(packet.get_payload().is_empty());
    }

    #[test]
    fn test_encode_packet_with_payload() {
        let mut response = PacketHeader::new();
        response.set_type(Type::StData);
        response.set_connection_id(49300);
        response.set_timestamp(2805920832);
        response.set_timestamp_difference(1805367832);
        response.set_wnd_size(61440);
        response.set_seq_nr(12044);
        response.set_ack_nr(12024);
        let payload = b"Hello world".to_vec();

        let packet = Packet::with_payload(response, &payload[..]);
        assert_eq!(packet.type_(), Type::StData);
        assert_eq!(packet.version(), VERSION);
        assert_eq!(packet.extension(), 0);
        assert_eq!(packet.connection_id(), 49300);
        assert_eq!(packet.timestamp(), 2805920832);
        assert_eq!(packet.timestamp_difference(), 1805367832);
        assert_eq!(packet.wnd_size(), 61440);
        assert_eq!(packet.seq_nr(), 12044);
        assert_eq!(packet.ack_nr(), 12024);
        assert_eq!(packet.get_payload(), &payload[..]);
    }

    #[test]
    fn test_empty_packet() {
        let packet = Packet::try_from(&[][..]);
        assert!(packet.is_err());
    }

    #[test]
    fn test_selective_ack() {
        let mut response = PacketHeader::new();
        response.set_type(Type::StState);
        response.set_connection_id(49300);
        response.set_timestamp(2805920832);
        response.set_timestamp_difference(1805367832);
        response.set_wnd_size(61440);
        response.set_seq_nr(12044);
        response.set_ack_nr(12024);

        let mut incoming_buffer: BTreeMap<u16, Packet> = Default::default();
        incoming_buffer.insert(12045, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12049, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12050, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12052, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12049, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12053, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12054, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12057, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12067, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12069, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12070, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12072, Packet::new(PacketHeader::new()));
        incoming_buffer.insert(12074, Packet::new(PacketHeader::new()));

        let mut reply = Packet::new(response);
        if reply.seq_nr().wrapping_sub(12048) > 1 {
            reply.set_selective_ack(&incoming_buffer, 12048);
        }

        assert_eq!(reply.get_extensions()[0].bitmask[0], 0b1001_1101);
        assert_eq!(reply.get_extensions()[0].bitmask[1], 0b0000_0000);
        assert_eq!(reply.get_extensions()[0].bitmask[2], 0b0101_1010);
        assert_eq!(reply.get_extensions()[0].bitmask[3], 0b0000_0001);
    }
}
