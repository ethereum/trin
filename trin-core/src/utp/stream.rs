#![allow(dead_code)]
#![allow(unreachable_code)]

use crate::portalnet::discovery::Discovery;
use core::convert::TryFrom;
use discv5::enr::NodeId;
use discv5::Enr;
use log::debug;
use rand::Rng;
use std::cmp::{max, min};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::portalnet::types::messages::ProtocolId;
use crate::utp::packets::{ExtensionType, Packet, PacketType, HEADER_SIZE};
use crate::utp::time::{now_microseconds, Delay, Timestamp};
use crate::utp::trin_helpers::{UtpMessageId, UtpStreamState};
use crate::utp::utils::{abs_diff, ewma};
use anyhow::anyhow;
use std::time::{Duration, Instant};

// Maximum time (in microseconds) to wait for incoming packets when the send window is full
const PRE_SEND_TIMEOUT: u32 = 500_000;

// Maximum age of base delay sample (60 seconds)
const MAX_BASE_DELAY_AGE: Delay = Delay(60_000_000);
const BASE_HISTORY: usize = 10; // base delays history size
const MIN_CONGESTION_TIMEOUT: u64 = 500; // 500 ms
const MAX_CONGESTION_TIMEOUT: u64 = 60_000; // one minute
const INITIAL_CONGESTION_TIMEOUT: u64 = 1000; // one second

const MIN_CWND: u32 = 2;
const INIT_CWND: u32 = 2;

// For simplicity's sake, let us assume no packet will ever exceed the
// Ethernet maximum transfer unit of 1500 bytes.
const BUF_SIZE: usize = 1500;
const GAIN: f64 = 1.0;
const ALLOWED_INCREASE: u32 = 1;
const TARGET: f64 = 100_000.0; // 100 milliseconds
const MSS: u32 = 1400;

pub const MAX_DISCV5_PACKET_SIZE: usize = 1280;
pub const MIN_PACKET_SIZE: usize = 150;
const MIN_DISCV5_PACKET_SIZE: usize = 63;
// 100 miliseconds
const CCONTROL_TARGET: usize = 100 * 1000;
const MAX_CWND_INCREASE_BYTES_PER_RTT: usize = 3000;
const MIN_WINDOW_SIZE: usize = 10;
const WINDOW_SIZE: u32 = 1024 * 1024; // local receive window size
const MAX_RETRANSMISSION_RETRIES: u32 = 5; // maximum retransmission retries

pub fn rand() -> u16 {
    rand::thread_rng().gen()
}

#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum SocketState {
    New,
    Connected,
    SynSent,
    FinSent,
    ResetReceived,
    Closed,
}

struct DelayDifferenceSample {
    received_at: Timestamp,
    difference: Delay,
}

#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug)]
pub struct ConnectionKey {
    pub node_id: NodeId,
    pub conn_id_recv: u16,
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
    pub utp_connections: HashMap<ConnectionKey, UtpSocket>,
    // We only want to listen/handle packets of connections that were negotiated with
    pub listening: HashMap<u16, UtpMessageId>,
}

impl UtpListener {
    pub fn process_utp_request(&mut self, payload: &[u8], node_id: &NodeId) {
        match Packet::try_from(payload) {
            Ok(packet) => {
                let connection_id = packet.connection_id();

                match packet.get_type() {
                    PacketType::Reset => {
                        let key_fn =
                            |offset| ConnectionKey::new(*node_id, connection_id - 1 + offset);
                        let f = |conn: &&mut UtpSocket| -> bool {
                            conn.sender_connection_id == connection_id
                        };

                        if let Some(conn) = self.utp_connections.get_mut(&key_fn(1)) {
                            conn.state = SocketState::Closed;
                        } else if let Some(conn) =
                            self.utp_connections.get_mut(&key_fn(2)).filter(f)
                        {
                            conn.state = SocketState::Closed;
                        } else if let Some(conn) =
                            self.utp_connections.get_mut(&key_fn(0)).filter(f)
                        {
                            conn.state = SocketState::Closed;
                        }
                    }
                    PacketType::Syn => {
                        if let Some(enr) = self.discovery.discv5.find_enr(node_id) {
                            // If neither of those cases happened handle this is a new request
                            let (tx, _) = mpsc::unbounded_channel::<UtpStreamState>();
                            let mut conn =
                                UtpSocket::new(Arc::clone(&self.discovery), enr.clone(), tx);
                            conn.handle_packet(&packet, enr);
                            self.utp_connections.insert(
                                ConnectionKey {
                                    node_id: *node_id,
                                    conn_id_recv: conn.receiver_connection_id,
                                },
                                conn,
                            );
                        } else {
                            debug!("Query requested an unknown ENR");
                        }
                    }
                    _ => {
                        if let Some(conn) = self.utp_connections.get_mut(&ConnectionKey {
                            node_id: *node_id,
                            conn_id_recv: connection_id,
                        }) {
                            if let Some(enr) = self.discovery.discv5.find_enr(node_id) {
                                conn.handle_packet(&packet, enr);
                            } else {
                                debug!("Query requested an unknown ENR");
                            }
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
    pub fn connect(
        &mut self,
        connection_id: u16,
        node_id: NodeId,
        tx: mpsc::UnboundedSender<UtpStreamState>,
    ) {
        if let Some(enr) = self.discovery.discv5.find_enr(&node_id) {
            let mut conn = UtpSocket::new(Arc::clone(&self.discovery), enr, tx);
            conn.make_connection(connection_id);
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
pub struct UtpSocket {
    /// The wrapped discv5 protocol
    socket: Arc<Discovery>,

    /// Socket state
    pub state: SocketState,

    // Remote peer
    connected_to: Enr,

    /// Sequence number for the next packet
    seq_nr: u16,

    /// Sequence number of the latest acknowledged packet sent by the remote peer
    ack_nr: u16,

    /// Sender connection identifier
    sender_connection_id: u16,

    /// Receiver connection identifier
    pub receiver_connection_id: u16,

    // maximum window size, in bytes
    max_window: u32,

    /// Received but not acknowledged packets
    incoming_buffer: Vec<Packet>,

    /// Packets not yet sent
    unsent_queue: VecDeque<Packet>,

    /// Bytes in flight
    cur_window: u32,

    /// Window size of the remote peer
    remote_wnd_size: u32,

    /// Sent but not yet acknowledged packets
    send_window: Vec<Packet>,

    /// How many ACKs did the socket receive for packet with sequence number equal to `ack_nr`
    duplicate_ack_count: u8,

    /// Sequence number of the latest packet the remote peer acknowledged
    last_acked: u16,

    /// Timestamp of the latest packet the remote peer acknowledged
    last_acked_timestamp: Timestamp,

    /// Sequence number of the last packet removed from the incoming buffer
    last_dropped: u16,

    /// Round-trip time to remote peer
    rtt: i32,

    /// Variance of the round-trip time to the remote peer
    rtt_variance: i32,

    /// Data from the latest packet not yet returned in `recv_from`
    pending_data: Vec<u8>,

    /// Rolling window of packet delay to remote peer
    base_delays: VecDeque<Delay>,

    /// Rolling window of the difference between sending a packet and receiving its acknowledgement
    current_delays: Vec<DelayDifferenceSample>,

    /// Difference between timestamp of the latest packet received and time of reception
    their_delay: Delay,

    /// Current congestion timeout in milliseconds
    congestion_timeout: u64,

    /// Congestion window in bytes
    cwnd: u32,

    /// Start of the current minute for sampling purposes
    last_rollover: Timestamp,

    /// Maximum retransmission retries
    pub max_retransmission_retries: u32,

    pub recv_data_stream: Vec<u8>,
    tx: mpsc::UnboundedSender<UtpStreamState>,
}

impl UtpSocket {
    fn new(
        socket: Arc<Discovery>,
        connected_to: Enr,
        tx: mpsc::UnboundedSender<UtpStreamState>,
    ) -> Self {
        Self {
            state: SocketState::New,
            seq_nr: 0,
            ack_nr: 0,
            receiver_connection_id: 0,
            sender_connection_id: 0,
            max_window: 0,
            incoming_buffer: Default::default(),
            unsent_queue: Default::default(),
            connected_to,
            socket,
            cur_window: 0,
            remote_wnd_size: 0,
            send_window: Default::default(),
            duplicate_ack_count: 0,
            last_acked: 0,
            last_acked_timestamp: Timestamp::default(),
            last_dropped: 0,
            rtt: 0,
            rtt_variance: 0,
            pending_data: Vec::new(),
            base_delays: VecDeque::with_capacity(BASE_HISTORY),
            their_delay: Delay::default(),
            congestion_timeout: INITIAL_CONGESTION_TIMEOUT,
            cwnd: INIT_CWND * MSS,
            last_rollover: Timestamp::default(),
            current_delays: Vec::with_capacity(8),
            recv_data_stream: Vec::new(),
            max_retransmission_retries: MAX_RETRANSMISSION_RETRIES,

            // signal when node is connected to write payload
            tx,
        }
    }

    /// Sends data on the socket to the remote peer. On success, returns the number of bytes
    /// written.
    //
    // # Implementation details
    //
    // This method inserts packets into the send buffer and keeps trying to
    // advance the send window until an ACK corresponding to the last packet is
    // received.
    //
    // Note that the buffer passed to `send_to` might exceed the maximum packet
    // size, which will result in the data being split over several packets.
    pub fn send_to(&mut self, buf: &[u8]) -> anyhow::Result<usize> {
        if self.state == SocketState::Closed {
            return Err(anyhow!("The socket is closed"));
        }

        let total_length = buf.len();

        for chunk in buf.chunks(MAX_DISCV5_PACKET_SIZE - MIN_DISCV5_PACKET_SIZE - HEADER_SIZE) {
            let mut packet = Packet::with_payload(chunk);
            packet.set_seq_nr(self.seq_nr);
            packet.set_ack_nr(self.ack_nr);
            packet.set_connection_id(self.sender_connection_id);

            self.unsent_queue.push_back(packet);

            // Intentionally wrap around sequence number
            self.seq_nr = self.seq_nr.wrapping_add(1);
        }

        // Send every packet in the queue
        self.send_packets_in_queue();

        Ok(total_length)
    }

    /// Gracefully closes connection to peer.
    ///
    /// This method allows both peers to receive all packets still in
    /// flight.
    pub fn close(&mut self) -> anyhow::Result<()> {
        // Nothing to do if the socket's already closed or not connected
        if self.state == SocketState::Closed
            || self.state == SocketState::New
            || self.state == SocketState::SynSent
        {
            return Ok(());
        }

        // Flush unsent and unacknowledged packets
        self.flush()?;

        let mut packet = Packet::new();
        packet.set_connection_id(self.sender_connection_id);
        packet.set_seq_nr(self.seq_nr);
        packet.set_ack_nr(self.ack_nr);
        packet.set_timestamp(now_microseconds());
        packet.set_type(PacketType::Fin);

        // Send FIN
        self.socket
            .send_to(packet.as_ref(), self.connected_to.clone())?;
        debug!("sent {:?}", packet);
        self.state = SocketState::FinSent;

        // Receive JAKE
        let mut buf = [0; BUF_SIZE];
        while self.state != SocketState::Closed {
            self.recv(&mut buf)?;
        }

        Ok(())
    }

    /// Receives data from socket.
    ///
    /// On success, returns the number of bytes read and the sender's address.
    /// Returns 0 bytes read after receiving a FIN packet when the remaining
    /// in-flight packets are consumed.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> anyhow::Result<(usize, Enr)> {
        let read = self.flush_incoming_buffer(buf);

        if read > 0 {
            return Ok((read, self.connected_to.clone()));
        }

        // If the socket received a reset packet and all data has been flushed, then it can't
        // receive anything else
        if self.state == SocketState::ResetReceived {
            return Err(anyhow!("Connection reset by remote peer"));
        }

        loop {
            // A closed socket with no pending data can only "read" 0 new bytes.
            if self.state == SocketState::Closed {
                return Ok((0, self.connected_to.clone()));
            }

            match self.recv(buf) {
                Ok((0, _src)) => continue,
                Ok(x) => return Ok(x),
                Err(e) => return Err(e),
            }
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> anyhow::Result<(usize, Enr)> {
        let mut b = [0; BUF_SIZE + HEADER_SIZE];
        let start = Instant::now();
        let (read, src);
        let mut retries = 0;

        // Try to receive a packet and handle timeouts
        loop {
            // Abort loop if the current try exceeds the maximum number of retransmission retries.
            if retries >= self.max_retransmission_retries {
                self.state = SocketState::Closed;
                return Err(anyhow!("Connection timed out"));
            }

            let timeout = if self.state != SocketState::New {
                debug!("setting read timeout of {} ms", self.congestion_timeout);
                Some(Duration::from_millis(self.congestion_timeout))
            } else {
                None
            };

            // self.socket
            //     .set_read_timeout(timeout)
            //     .expect("Error setting read timeout");
            //
            // TODO: Refactor this to use discv5 layer
            // match self.socket.recv_from(&mut b) {
            //     Ok((r, s)) => {
            //         read = r;
            //         src = s;
            //         break;
            //     }
            //     Err(ref e)
            //         if (e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut) =>
            //     {
            //         debug!("recv_from timed out");
            //         self.handle_receive_timeout()?;
            //     }
            //     Err(e) => return Err(e),
            // };

            let elapsed = start.elapsed();
            let elapsed_ms = elapsed.as_secs() * 1000 + elapsed.subsec_millis() as u64;
            debug!("{} ms elapsed", elapsed_ms);
            retries += 1;
        }

        // Decode received data into a packet
        let packet = match Packet::try_from(&b[..read]) {
            Ok(packet) => packet,
            Err(e) => {
                debug!("{}", e);
                debug!("Ignoring invalid packet");
                return Ok((0, self.connected_to));
            }
        };
        debug!("received {:?}", packet);

        // Process packet, including sending a reply if necessary
        if let Some(mut pkt) = self.handle_packet(&packet, src)? {
            pkt.set_wnd_size(WINDOW_SIZE);
            self.socket.send_to(pkt.as_ref(), src)?;
            debug!("sent {:?}", pkt);
        }

        // Insert data packet into the incoming buffer if it isn't a duplicate of a previously
        // discarded packet
        if packet.get_type() == PacketType::Data
            && packet.seq_nr().wrapping_sub(self.last_dropped) > 0
        {
            self.insert_into_buffer(packet);
        }

        // Flush incoming buffer if possible
        let read = self.flush_incoming_buffer(buf);

        Ok((read, src))
    }

    fn handle_receive_timeout(&mut self) -> anyhow::Result<()> {
        self.congestion_timeout *= 2;
        self.cwnd = MSS;

        // There are three possible cases here:
        //
        // - If the socket is sending and waiting for acknowledgements (the send window is
        //   not empty), resend the first unacknowledged packet;
        //
        // - If the socket is not sending and it hasn't sent a FIN yet, then it's waiting
        //   for incoming packets: send a fast resend request;
        //
        // - If the socket sent a FIN previously, resend it.
        debug!(
            "self.send_window: {:?}",
            self.send_window
                .iter()
                .map(Packet::seq_nr)
                .collect::<Vec<u16>>()
        );

        if self.send_window.is_empty() {
            // The socket is trying to close, all sent packets were acknowledged, and it has
            // already sent a FIN: resend it.
            if self.state == SocketState::FinSent {
                let mut packet = Packet::new();
                packet.set_connection_id(self.sender_connection_id);
                packet.set_seq_nr(self.seq_nr);
                packet.set_ack_nr(self.ack_nr);
                packet.set_timestamp(now_microseconds());
                packet.set_type(PacketType::Fin);

                // Send FIN
                self.socket
                    .send_to(packet.as_ref(), self.connected_to.clone())?;
                debug!("resent FIN: {:?}", packet);
            } else if self.state != SocketState::New {
                // The socket is waiting for incoming packets but the remote peer is silent:
                // send a fast resend request.
                debug!("sending fast resend request");
                self.send_fast_resend_request();
            }
        } else {
            // The socket is sending data packets but there is no reply from the remote
            // peer: resend the first unacknowledged packet with the current timestamp.
            let packet = &mut self.send_window[0];
            packet.set_timestamp(now_microseconds());
            self.socket
                .send_to(packet.as_ref(), self.connected_to.clone())?;
            debug!("resent {:?}", packet);
        }

        Ok(())
    }

    /// Removes a packet in the incoming buffer and updates the current acknowledgement number.
    fn advance_incoming_buffer(&mut self) -> Option<Packet> {
        if !self.incoming_buffer.is_empty() {
            let packet = self.incoming_buffer.remove(0);
            debug!("Removed packet from incoming buffer: {:?}", packet);
            self.ack_nr = packet.seq_nr();
            self.last_dropped = self.ack_nr;
            Some(packet)
        } else {
            None
        }
    }

    /// Discards sequential, ordered packets in incoming buffer, starting from
    /// the most recently acknowledged to the most recent, as long as there are
    /// no missing packets. The discarded packets' payload is written to the
    /// slice `buf`, starting in position `start`.
    /// Returns the last written index.
    fn flush_incoming_buffer(&mut self, buf: &mut [u8]) -> usize {
        fn unsafe_copy(src: &[u8], dst: &mut [u8]) -> usize {
            let max_len = min(src.len(), dst.len());
            unsafe {
                use std::ptr::copy;
                copy(src.as_ptr(), dst.as_mut_ptr(), max_len);
            }
            max_len
        }

        // Return pending data from a partially read packet
        if !self.pending_data.is_empty() {
            let flushed = unsafe_copy(&self.pending_data[..], buf);

            if flushed == self.pending_data.len() {
                self.pending_data.clear();
                self.advance_incoming_buffer();
            } else {
                self.pending_data = self.pending_data[flushed..].to_vec();
            }

            return flushed;
        }

        if !self.incoming_buffer.is_empty()
            && (self.ack_nr == self.incoming_buffer[0].seq_nr()
                || self.ack_nr + 1 == self.incoming_buffer[0].seq_nr())
        {
            let flushed = unsafe_copy(&self.incoming_buffer[0].payload(), buf);

            if flushed == self.incoming_buffer[0].payload().len() {
                self.advance_incoming_buffer();
            } else {
                self.pending_data = self.incoming_buffer[0].payload()[flushed..].to_vec();
            }

            return flushed;
        }

        0
    }

    /// Sends a fast resend request to the remote peer.
    ///
    /// A fast resend request consists of sending three State packets (acknowledging the last
    /// received packet) in quick succession.
    fn send_fast_resend_request(&self) {
        for _ in 0..3 {
            let mut packet = Packet::new();
            packet.set_type(PacketType::State);
            let self_t_micro = now_microseconds();
            packet.set_timestamp(self_t_micro);
            packet.set_timestamp_difference(self.their_delay);
            packet.set_connection_id(self.sender_connection_id);
            packet.set_seq_nr(self.seq_nr);
            packet.set_ack_nr(self.ack_nr);
            let _ = self
                .socket
                .send_to(packet.as_ref(), self.connected_to.clone());
        }
    }

    /// Inserts a packet into the socket's buffer.
    ///
    /// The packet is inserted in such a way that the packets in the buffer are sorted according to
    /// their sequence number in ascending order. This allows storing packets that were received out
    /// of order.
    ///
    /// Trying to insert a duplicate of a packet will silently fail.
    /// it's more recent (larger timestamp).
    fn insert_into_buffer(&mut self, packet: Packet) {
        // Immediately push to the end if the packet's sequence number comes after the last
        // packet's.
        if self
            .incoming_buffer
            .last()
            .map_or(false, |p| packet.seq_nr() > p.seq_nr())
        {
            self.incoming_buffer.push(packet);
        } else {
            // Find index following the most recent packet before the one we wish to insert
            let i = self
                .incoming_buffer
                .iter()
                .filter(|p| p.seq_nr() < packet.seq_nr())
                .count();

            if self
                .incoming_buffer
                .get(i)
                .map_or(true, |p| p.seq_nr() != packet.seq_nr())
            {
                self.incoming_buffer.insert(i, packet);
            }
        }
    }

    /// Consumes acknowledgements for every pending packet.
    pub fn flush(&mut self) -> anyhow::Result<()> {
        let mut buf = [0u8; BUF_SIZE];
        while !self.send_window.is_empty() {
            debug!("packets in send window: {}", self.send_window.len());
            self.recv(&mut buf)?;
        }

        Ok(())
    }

    fn send_packets_in_queue(&mut self) {
        while let Some(mut packet) = self.unsent_queue.pop_front() {
            self.send_packet(&mut packet);
            self.cur_window += packet.len() as u32;
            self.send_window.push(packet);
        }
    }

    /// Send one packet.
    fn send_packet(&mut self, packet: &mut Packet) {
        debug!("current window: {}", self.send_window.len());
        let max_inflight = max(
            MAX_DISCV5_PACKET_SIZE,
            min(self.max_window as usize, self.remote_wnd_size as usize),
        );
        let now = now_microseconds();

        // Wait until enough in-flight packets are acknowledged for rate control purposes, but don't
        // wait more than 500 ms (PRE_SEND_TIMEOUT) before sending the packet
        while self.cur_window + packet.as_ref().len() as u32 > max_inflight as u32
            && now_microseconds() - now < PRE_SEND_TIMEOUT.into()
        {
            debug!("self.curr_window: {}", self.cur_window);
            debug!("max_inflight: {}", max_inflight);
            debug!("self.duplicate_ack_count: {}", self.duplicate_ack_count);
            debug!("now_microseconds() - now = {}", now_microseconds() - now)
            // TODO: Why here we dont do for example:
            // let mut buf = [0; BUF_SIZE];
            // self.recv(&mut buf)?;
        }

        debug!(
            "out: now_microseconds() - now = {}",
            now_microseconds() - now
        );

        // Check if it still makes sense to send packet, as we might be trying to resend a lost
        // packet acknowledged in the receive loop above.
        // If there were no wrapping around of sequence numbers, we'd simply check if the packet's
        // sequence number is greater than `last_acked`.
        let distance_a = packet.seq_nr().wrapping_sub(self.last_acked);
        let distance_b = self.last_acked.wrapping_sub(packet.seq_nr());
        if distance_a > distance_b {
            debug!("Packet already acknowledged, skipping...");
            return;
        }

        let enr = self.connected_to.clone();
        let discovery = self.socket.clone();

        packet.set_timestamp(now_microseconds());
        // TODO: Add their_delay field instead of calculating here get_time_diff
        packet.set_timestamp_difference(self.their_delay);

        let packet_to_send = packet.clone();

        // Handle talkreq/talkresp in the background
        tokio::spawn(async move {
            if let Err(response) = {
                discovery
                    .send_talk_req(enr, ProtocolId::Utp, Vec::from(packet_to_send.as_ref()))
                    .await
            } {
                debug!("Unable to send utp talk req: {response}")
            }
        });
        debug!("sent {:?}", packet);
    }

    fn update_base_delay(&mut self, base_delay: Delay, now: Timestamp) {
        if self.base_delays.is_empty() || now - self.last_rollover > MAX_BASE_DELAY_AGE {
            // Update last rollover
            self.last_rollover = now;

            // Drop the oldest sample, if need be
            if self.base_delays.len() == BASE_HISTORY {
                self.base_delays.pop_front();
            }

            // Insert new sample
            self.base_delays.push_back(base_delay);
        } else {
            // Replace sample for the current minute if the delay is lower
            let last_idx = self.base_delays.len() - 1;
            if base_delay < self.base_delays[last_idx] {
                self.base_delays[last_idx] = base_delay;
            }
        }
    }

    /// Inserts a new sample in the current delay list after removing samples older than one RTT, as
    /// specified in RFC6817.
    fn update_current_delay(&mut self, v: Delay, now: Timestamp) {
        // Remove samples more than one RTT old
        let rtt = (self.rtt as i64 * 100).into();
        while !self.current_delays.is_empty() && now - self.current_delays[0].received_at > rtt {
            self.current_delays.remove(0);
        }

        // Insert new measurement
        self.current_delays.push(DelayDifferenceSample {
            received_at: now,
            difference: v,
        });
    }

    fn queuing_delay(&self) -> Delay {
        let filtered_current_delay = self.filtered_current_delay();
        let min_base_delay = self.min_base_delay();
        let queuing_delay = filtered_current_delay - min_base_delay;

        debug!("filtered_current_delay: {}", filtered_current_delay);
        debug!("min_base_delay: {}", min_base_delay);
        debug!("queuing_delay: {}", queuing_delay);

        queuing_delay
    }

    /// Calculates the filtered current delay in the current window.
    ///
    /// The current delay is calculated through application of the exponential
    /// weighted moving average filter with smoothing factor 0.333 over the
    /// current delays in the current window.
    fn filtered_current_delay(&self) -> Delay {
        let input = self.current_delays.iter().map(|delay| &delay.difference);
        (ewma(input, 0.333) as i64).into()
    }

    /// Calculates the lowest base delay in the current window.
    fn min_base_delay(&self) -> Delay {
        self.base_delays.iter().min().cloned().unwrap_or_default()
    }

    fn filter(current_delay: &[u32]) -> u32 {
        let filt = (current_delay.len() as f64 / 3_f64).ceil() as usize;
        *current_delay[current_delay.len() - filt..]
            .iter()
            .min()
            .unwrap()
    }

    fn make_connection(&mut self, connection_id: u16) {
        if self.state == SocketState::New {
            self.state = SocketState::SynSent;
            self.seq_nr = 1;
            self.receiver_connection_id = connection_id;
            self.sender_connection_id = self.receiver_connection_id + 1;

            let mut packet = Packet::new();
            packet.set_type(PacketType::Syn);
            packet.set_connection_id(self.receiver_connection_id);
            packet.set_seq_nr(self.seq_nr + 1);
            packet.set_ack_nr(0);

            self.send_packet(&mut packet);
        }
    }

    /// Builds the selective acknowledgement extension data for usage in packets.
    fn build_selective_ack(&self) -> Vec<u8> {
        let stashed = self
            .incoming_buffer
            .iter()
            .filter(|pkt| pkt.seq_nr() > self.ack_nr + 1)
            .map(|pkt| (pkt.seq_nr() - self.ack_nr - 2) as usize)
            .map(|diff| (diff / 8, diff % 8));

        let mut sack = Vec::new();
        for (byte, bit) in stashed {
            // Make sure the amount of elements in the SACK vector is a
            // multiple of 4 and enough to represent the lost packets
            while byte >= sack.len() || sack.len() % 4 != 0 {
                sack.push(0u8);
            }

            sack[byte] |= 1 << bit;
        }

        sack
    }

    pub fn send_finalize(&mut self) {
        let mut packet = Packet::new();
        packet.set_type(PacketType::Fin);
        packet.set_connection_id(self.sender_connection_id);
        packet.set_seq_nr(self.seq_nr + 1);
        packet.set_ack_nr(0);

        self.send_packet(&mut packet);
    }

    fn handle_packet(&mut self, packet: &Packet, src: Enr) -> anyhow::Result<Option<Packet>> {
        debug!("({:?}, {:?})", self.state, packet.get_type());

        // Acknowledge only if the packet strictly follows the previous one
        if packet.seq_nr().wrapping_sub(self.ack_nr) == 1 {
            self.ack_nr = packet.seq_nr();
        }

        // Reset connection if connection id doesn't match and this isn't a SYN
        if packet.get_type() != PacketType::Syn
            && self.state != SocketState::SynSent
            && !(packet.connection_id() == self.sender_connection_id
                || packet.connection_id() == self.receiver_connection_id)
        {
            return Ok(Some(self.prepare_reply(packet, PacketType::Reset)));
        }

        // Update remote window size
        self.remote_wnd_size = packet.wnd_size();
        debug!("self.remote_wnd_size: {}", self.remote_wnd_size);

        // Update remote peer's delay between them sending the packet and us receiving it
        let now = now_microseconds();
        self.their_delay = abs_diff(now, packet.timestamp());
        debug!("self.their_delay: {}", self.their_delay);

        match (self.state, packet.get_type()) {
            (SocketState::New, PacketType::Syn) => {
                self.connected_to = src;
                self.ack_nr = packet.seq_nr();
                self.seq_nr = rand::random();
                self.receiver_connection_id = packet.connection_id() + 1;
                self.sender_connection_id = packet.connection_id();
                self.state = SocketState::Connected;
                self.last_dropped = self.ack_nr;

                Ok(Some(self.prepare_reply(packet, PacketType::State)))
            }
            (_, PacketType::Syn) => Ok(Some(self.prepare_reply(packet, PacketType::Reset))),
            (SocketState::SynSent, PacketType::State) => {
                self.connected_to = src;
                self.ack_nr = packet.seq_nr();
                self.seq_nr += 1;
                self.state = SocketState::Connected;
                self.last_acked = packet.ack_nr();
                self.last_acked_timestamp = now_microseconds();
                Ok(None)
            }
            (SocketState::SynSent, _) => Err(anyhow!("The remote peer sent an invalid reply")),
            (SocketState::Connected, PacketType::Data)
            | (SocketState::FinSent, PacketType::Data) => Ok(self.handle_data_packet(packet)),
            (SocketState::Connected, PacketType::State) => {
                self.handle_state_packet(packet);
                Ok(None)
            }
            (SocketState::Connected, PacketType::Fin) | (SocketState::FinSent, PacketType::Fin) => {
                if packet.ack_nr() < self.seq_nr {
                    debug!("FIN received but there are missing acknowledgements for sent packets");
                }
                let mut reply = self.prepare_reply(packet, PacketType::State);
                if packet.seq_nr().wrapping_sub(self.ack_nr) > 1 {
                    debug!(
                        "current ack_nr ({}) is behind received packet seq_nr ({})",
                        self.ack_nr,
                        packet.seq_nr()
                    );

                    // Set SACK extension payload if the packet is not in order
                    let sack = self.build_selective_ack();

                    if !sack.is_empty() {
                        reply.set_sack(sack);
                    }
                }

                // Give up, the remote peer might not care about our missing packets
                self.state = SocketState::Closed;
                Ok(Some(reply))
            }
            (SocketState::Closed, PacketType::Fin) => {
                Ok(Some(self.prepare_reply(packet, PacketType::State)))
            }
            (SocketState::FinSent, PacketType::State) => {
                if packet.ack_nr() == self.seq_nr {
                    self.state = SocketState::Closed;
                } else {
                    self.handle_state_packet(packet);
                }
                Ok(None)
            }
            (_, PacketType::Reset) => {
                self.state = SocketState::ResetReceived;
                Err(anyhow!("Connection reset by remote peer"))
            }
            (state, ty) => {
                let message = format!("Unimplemented handling for ({:?},{:?})", state, ty);
                debug!("{}", message);
                Err(anyhow!(message))
            }
        }
    }

    fn prepare_reply(&self, original: &Packet, t: PacketType) -> Packet {
        let mut resp = Packet::new();
        resp.set_type(t);
        let self_t_micro = now_microseconds();
        let other_t_micro = original.timestamp();
        let time_difference: Delay = abs_diff(self_t_micro, other_t_micro);
        resp.set_timestamp(self_t_micro);
        resp.set_timestamp_difference(time_difference);
        resp.set_connection_id(self.sender_connection_id);
        resp.set_seq_nr(self.seq_nr);
        resp.set_ack_nr(self.ack_nr);

        resp
    }

    fn handle_data_packet(&mut self, packet: &Packet) -> Option<Packet> {
        // if self.state == SocketState::SynRecv {
        //     self.state = SocketState::Connected;
        // }

        // If a FIN was previously sent, reply with a FIN packet acknowledging the received packet.
        let packet_type = if self.state == SocketState::FinSent {
            PacketType::Fin
        } else {
            PacketType::State
        };
        let mut reply = self.prepare_reply(packet, packet_type);

        if packet.seq_nr().wrapping_sub(self.ack_nr) > 1 {
            debug!(
                "current ack_nr ({}) is behind received packet seq_nr ({})",
                self.ack_nr,
                packet.seq_nr()
            );

            // Set SACK extension payload if the packet is not in order
            let sack = self.build_selective_ack();

            if !sack.is_empty() {
                reply.set_sack(sack);
            }
        }

        Some(reply)
    }

    fn handle_state_packet(&mut self, packet: &Packet) {
        if packet.ack_nr() == self.last_acked {
            self.duplicate_ack_count += 1;
        } else {
            self.last_acked = packet.ack_nr();
            self.last_acked_timestamp = now_microseconds();
            self.duplicate_ack_count = 1;
        }

        // Update congestion window size
        if let Some(index) = self
            .send_window
            .iter()
            .position(|p| packet.ack_nr() == p.seq_nr())
        {
            // Calculate the sum of the size of every packet implicitly and explicitly acknowledged
            // by the inbound packet (i.e., every packet whose sequence number precedes the inbound
            // packet's acknowledgement number, plus the packet whose sequence number matches)
            let bytes_newly_acked = self
                .send_window
                .iter()
                .take(index + 1)
                .fold(0, |acc, p| acc + p.len());

            // Update base and current delay
            let now = now_microseconds();
            let our_delay = now - self.send_window[index].timestamp();
            debug!("our_delay: {}", our_delay);
            self.update_base_delay(our_delay, now);
            self.update_current_delay(our_delay, now);

            let off_target: f64 = (TARGET - u32::from(self.queuing_delay()) as f64) / TARGET;
            debug!("off_target: {}", off_target);

            self.update_congestion_window(off_target, bytes_newly_acked as u32);

            // Update congestion timeout
            let rtt = u32::from(our_delay - self.queuing_delay()) / 1000; // in milliseconds
            self.update_congestion_timeout(rtt as i32);
        }

        let mut packet_loss_detected: bool =
            !self.send_window.is_empty() && self.duplicate_ack_count == 3;

        // Process extensions, if any
        for extension in packet.extensions() {
            if extension.get_type() == ExtensionType::SelectiveAck {
                // If three or more packets are acknowledged past the implicit missing one,
                // assume it was lost.
                if extension.iter().count_ones() >= 3 {
                    self.resend_lost_packet(packet.ack_nr() + 1);
                    packet_loss_detected = true;
                }

                if let Some(last_seq_nr) = self.send_window.last().map(Packet::seq_nr) {
                    let lost_packets = extension
                        .iter()
                        .enumerate()
                        .filter(|&(_, received)| !received)
                        .map(|(idx, _)| packet.ack_nr() + 2 + idx as u16)
                        .take_while(|&seq_nr| seq_nr < last_seq_nr);

                    for seq_nr in lost_packets {
                        debug!("SACK: packet {} lost", seq_nr);
                        self.resend_lost_packet(seq_nr);
                        packet_loss_detected = true;
                    }
                }
            } else {
                debug!("Unknown extension {:?}, ignoring", extension.get_type());
            }
        }

        // Three duplicate ACKs mean a fast resend request. Resend the first unacknowledged packet
        // if the incoming packet doesn't have a SACK extension. If it does, the lost packets were
        // already resent.
        if !self.send_window.is_empty()
            && self.duplicate_ack_count == 3
            && !packet
                .extensions()
                .any(|ext| ext.get_type() == ExtensionType::SelectiveAck)
        {
            self.resend_lost_packet(packet.ack_nr() + 1);
        }

        // Packet lost, halve the congestion window
        if packet_loss_detected {
            debug!("packet loss detected, halving congestion window");
            self.cwnd = max(self.cwnd / 2, MIN_CWND * MSS);
            debug!("cwnd: {}", self.cwnd);
        }

        // Success, advance send window
        self.advance_send_window();
    }

    /// Forgets sent packets that were acknowledged by the remote peer.
    fn advance_send_window(&mut self) {
        // The reason I'm not removing the first element in a loop while its sequence number is
        // smaller than `last_acked` is because of wrapping sequence numbers, which would create the
        // sequence [..., 65534, 65535, 0, 1, ...]. If `last_acked` is smaller than the first
        // packet's sequence number because of wraparound (for instance, 1), no packets would be
        // removed, as the condition `seq_nr < last_acked` would fail immediately.
        //
        // On the other hand, I can't keep removing the first packet in a loop until its sequence
        // number matches `last_acked` because it might never match, and in that case no packets
        // should be removed.
        if let Some(position) = self
            .send_window
            .iter()
            .position(|packet| packet.seq_nr() == self.last_acked)
        {
            for _ in 0..position + 1 {
                let packet = self.send_window.remove(0);
                self.cur_window -= packet.len() as u32;
            }
        }
        debug!("self.curr_window: {}", self.cur_window);
    }

    fn resend_lost_packet(&mut self, lost_packet_nr: u16) {
        debug!("---> resend_lost_packet({}) <---", lost_packet_nr);
        match self
            .send_window
            .iter()
            .position(|pkt| pkt.seq_nr() == lost_packet_nr)
        {
            None => debug!("Packet {} not found", lost_packet_nr),
            Some(position) => {
                debug!("self.send_window.len(): {}", self.send_window.len());
                debug!("position: {}", position);
                let mut packet = self.send_window[position].clone();
                // FIXME: Unchecked result
                let _ = self.send_packet(&mut packet);

                // We intentionally don't increase `cur_window` because otherwise a packet's length
                // would be counted more than once
            }
        }
        debug!("---> END resend_lost_packet <---");
    }

    /// Calculates the new congestion window size, increasing it or decreasing it.
    ///
    /// This is the core of uTP, the [LEDBAT][ledbat_rfc] congestion algorithm. It depends on
    /// estimating the queuing delay between the two peers, and adjusting the congestion window
    /// accordingly.
    ///
    /// `off_target` is a normalized value representing the difference between the current queuing
    /// delay and a fixed target delay (`TARGET`). `off_target` ranges between -1.0 and 1.0. A
    /// positive value makes the congestion window increase, while a negative value makes the
    /// congestion window decrease.
    ///
    /// `bytes_newly_acked` is the number of bytes acknowledged by an inbound `State` packet. It may
    /// be the size of the packet explicitly acknowledged by the inbound packet (i.e., with sequence
    /// number equal to the inbound packet's acknowledgement number), or every packet implicitly
    /// acknowledged (every packet with sequence number between the previous inbound `State`
    /// packet's acknowledgement number and the current inbound `State` packet's acknowledgement
    /// number).
    ///
    ///[ledbat_rfc]: https://tools.ietf.org/html/rfc6817
    fn update_congestion_window(&mut self, off_target: f64, bytes_newly_acked: u32) {
        let flightsize = self.cur_window;

        let cwnd_increase = GAIN * off_target * bytes_newly_acked as f64 * MSS as f64;
        let cwnd_increase = cwnd_increase / self.cwnd as f64;
        debug!("cwnd_increase: {}", cwnd_increase);

        self.cwnd = (self.cwnd as f64 + cwnd_increase) as u32;
        let max_allowed_cwnd = flightsize + ALLOWED_INCREASE * MSS;
        self.cwnd = min(self.cwnd, max_allowed_cwnd);
        self.cwnd = max(self.cwnd, MIN_CWND * MSS);

        debug!("cwnd: {}", self.cwnd);
        debug!("max_allowed_cwnd: {}", max_allowed_cwnd);
    }

    fn update_congestion_timeout(&mut self, current_delay: i32) {
        let delta = self.rtt - current_delay;
        self.rtt_variance += (delta.abs() - self.rtt_variance) / 4;
        self.rtt += (current_delay - self.rtt) / 8;
        self.congestion_timeout = max(
            (self.rtt + self.rtt_variance * 4) as u64,
            MIN_CONGESTION_TIMEOUT,
        );
        self.congestion_timeout = min(self.congestion_timeout, MAX_CONGESTION_TIMEOUT);

        debug!("current_delay: {}", current_delay);
        debug!("delta: {}", delta);
        debug!("self.rtt_variance: {}", self.rtt_variance);
        debug!("self.rtt: {}", self.rtt);
        debug!("self.congestion_timeout: {}", self.congestion_timeout);
    }
}
