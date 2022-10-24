use crate::portalnet::discovery::Discovery;
use anyhow::anyhow;
use async_recursion::async_recursion;
use discv5::{enr::NodeId, Enr, TalkRequest};
use rand::Rng;
use ssz::Encode;
use std::{
    cmp::{max, min},
    collections::{HashMap, VecDeque},
    convert::TryFrom,
    sync::Arc,
};
use tokio::{
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot, RwLock,
    },
    time::timeout,
};
use tracing::{debug, error, warn};

use crate::{
    locks::RwLoggingExt,
    portalnet::types::messages::ProtocolId,
    utp::{
        packets::{ExtensionType, Packet, PacketType, HEADER_SIZE},
        time::{now_microseconds, Delay, Timestamp},
        trin_helpers::{UtpMessage, UtpStreamId},
        util::{abs_diff, ewma, generate_sequential_identifiers},
    },
};
use std::time::Duration;

// For simplicity's sake, let us assume no packet will ever exceed the
// Discv5 maximum transfer unit of 1280 bytes.
pub const BUF_SIZE: usize = 1280;
const GAIN: f64 = 1.0;
const ALLOWED_INCREASE: u32 = 1;
const MIN_CWND: u32 = 2; // minimum congestion window size
const INIT_CWND: u32 = 2; // init congestion window size
const MIN_CONGESTION_TIMEOUT: u64 = 500; // 500 ms
const MAX_CONGESTION_TIMEOUT: u64 = 60_000; // one minute
const MAX_RETRANSMISSION_RETRIES: u32 = 5; // discv5 socket maximum retransmission retries
const WINDOW_SIZE: u32 = 1024 * 1024; // local receive window size

// Maximum time (in microseconds) to wait for incoming packets when the send window is full
const PRE_SEND_TIMEOUT: u32 = 500_000;

const MAX_DISCV5_PACKET_SIZE: u32 = 1280;
const MAX_DISCV5_HEADER_SIZE: usize = 80;
// Size of the payload length in uTP message
const PAYLOAD_LENGTH_SIZE: usize = 32;
// Buffering delay that the uTP accepts on the up-link. Currently the delay target is set to 100 ms.
const CCONTROL_TARGET: f64 = 100_000.0;

const BASE_HISTORY: usize = 10; // base delays history size
                                // Maximum age of base delay sample (60 seconds)
const MAX_BASE_DELAY_AGE: Delay = Delay(60_000_000);
// Discv5 socket timeout in milliseconds
const DISCV5_SOCKET_TIMEOUT: u64 = 25;
/// uTP receive timeout in milliseconds
const UTP_RECEIVE_TIMEOUT: u64 = 1000;
/// Maximum retries trying to receive acknowledgments for the send packets
const MAX_RECV_ACKS_RETRIES: u8 = 5;

/// uTP connection id
type ConnId = u16;

/// uTP payload data
pub type UtpPayload = Vec<u8>;

pub fn rand() -> u16 {
    rand::thread_rng().gen()
}

/// Connection key for storing active uTP connections
#[derive(Hash, Eq, PartialEq, Copy, Clone, Debug)]
pub struct ConnectionKey {
    node_id: NodeId,
    conn_id_recv: ConnId,
}

impl ConnectionKey {
    fn new(node_id: NodeId, conn_id_recv: ConnId) -> Self {
        Self {
            node_id,
            conn_id_recv,
        }
    }
}

/// uTP stream connection state
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum StreamState {
    Uninitialized,
    SynSent,
    SynRecv,
    FinSent,
    Connected,
    Closed,
    ResetReceived,
}

#[derive(Clone, Debug)]
struct DelayDifferenceSample {
    received_at: Timestamp,
    difference: Delay,
}

/// Represent overlay to uTP listener request. It is used as a way to communicate between the overlay protocol
/// and uTP listener
#[derive(Debug)]
pub enum UtpListenerRequest {
    /// Request to create and connect to a uTP stream initiated by a remote node
    Connect(
        ConnId,
        Enr,
        ProtocolId,
        UtpStreamId,
        oneshot::Sender<UtpStream>,
    ),
    /// Request to initiate and add uTP stream to the connections hash map
    InitiateConnection(Enr, ProtocolId, UtpStreamId, ConnId),
}

/// Emit global event to overlay handler
#[derive(Clone, Debug, PartialEq)]
pub enum UtpListenerEvent {
    /// uTP stream is closed
    ClosedStream(UtpPayload, ProtocolId, UtpStreamId),
    /// uTP stream is reset
    ResetStream(ProtocolId, UtpStreamId),
}

/// uTP stream state events emitted from `UtpStream`
#[derive(Clone, Debug)]
pub enum UtpStreamEvent {
    /// Event signaling that a UtpStream has completed, containing received uTP payload, protocol id,
    /// receive connection id and node id of the remote peer
    Closed(UtpPayload, ProtocolId, UtpStreamId, ConnectionKey),
    /// Event signaling that a UtpStream has been reset, containing protocol id, receive connection id
    /// and node id of the remote peer
    Reset(ProtocolId, UtpStreamId, ConnectionKey),
}

/// Main uTP service used to listen and handle all uTP connections and streams
pub struct UtpListener {
    /// Base discv5 layer
    discovery: Arc<Discovery>,
    /// Store all active connections
    utp_connections: HashMap<ConnectionKey, UtpStream>,
    /// Receiver for uTP events sent from the main portal event handler
    utp_event_rx: UnboundedReceiver<TalkRequest>,
    /// Sender to overlay layer with processed uTP stream
    overlay_tx: UnboundedSender<UtpListenerEvent>,
    /// Receiver for uTP requests sent from the overlay layer
    overlay_rx: UnboundedReceiver<UtpListenerRequest>,
    /// Sender used in UtpStream to emit stream state events
    stream_tx: UnboundedSender<UtpStreamEvent>,
    /// Receiver for uTP stream state events
    stream_rx: UnboundedReceiver<UtpStreamEvent>,
}

impl UtpListener {
    pub fn new(
        discovery: Arc<Discovery>,
    ) -> (
        UnboundedSender<TalkRequest>,
        UnboundedSender<UtpListenerRequest>,
        UnboundedReceiver<UtpListenerEvent>,
        Self,
    ) {
        // Channel to process uTP TalkReq packets from main portal event handler
        let (utp_event_tx, utp_event_rx) = unbounded_channel::<TalkRequest>();
        // Channel to process portal overlay requests
        let (utp_listener_tx, utp_listener_rx) = unbounded_channel::<UtpListenerRequest>();
        // Channel to emit processed uTP payload to overlay service
        let (overlay_tx, overlay_rx) = unbounded_channel::<UtpListenerEvent>();
        // Channel to emit stream events from UtpStream
        let (stream_tx, stream_rx) = unbounded_channel::<UtpStreamEvent>();

        (
            utp_event_tx,
            utp_listener_tx,
            overlay_rx,
            UtpListener {
                discovery,
                utp_connections: HashMap::new(),
                utp_event_rx,
                overlay_tx,
                overlay_rx: utp_listener_rx,
                stream_tx,
                stream_rx,
            },
        )
    }

    /// The main execution loop of the UtpListener service.
    pub async fn start(&mut self) {
        loop {
            tokio::select! {
                Some(utp_request) = self.utp_event_rx.recv() => {
                    self.process_utp_request(utp_request).await
                },
                Some(overlay_request) = self.overlay_rx.recv() => {
                    self.process_overlay_request(overlay_request).await
                },
                Some(stream_event) = self.stream_rx.recv() => {
                    self.process_stream_event(stream_event)
                }
            }
        }
    }

    /// Process uTP TalkReq packets
    async fn process_utp_request(&mut self, request: TalkRequest) {
        let payload = request.body();
        let node_id = request.node_id();

        match Packet::try_from(payload) {
            Ok(packet) => {
                let connection_id = packet.connection_id();

                match packet.get_type() {
                    PacketType::Reset => {
                        if let Some(conn) = self
                            .utp_connections
                            .get_mut(&ConnectionKey::new(*node_id, connection_id))
                        {
                            if conn.discv5_tx.send(packet).is_ok() {
                                let mut buf = [0; BUF_SIZE];
                                if let Err(msg) = conn.recv(&mut buf).await {
                                    error!("Unable to receive uTP RESET packet: {msg}")
                                }
                            } else {
                                error!("Unable to send RESET packet to uTP stream handler")
                            }
                        }
                    }
                    PacketType::Syn => {
                        let conn_key = ConnectionKey::new(*node_id, connection_id);
                        if let Some(conn) = self.utp_connections.get_mut(&conn_key) {
                            if conn.discv5_tx.send(packet).is_err() {
                                error!("Unable to send SYN packet to uTP stream handler");
                                return;
                            }

                            let mut buf = [0; BUF_SIZE];

                            if let Err(msg) = conn.recv(&mut buf).await {
                                error!("Unable to receive SYN packet {msg}");
                                return;
                            }

                            // Send content data if the stream is listening for FindContent SYN packet
                            if let UtpStreamId::ContentStream(content_data) = conn.stream_id.clone()
                            // TODO: Change this `clone` to borrow after rust 1.62
                            {
                                // We want to send uTP data only if the content is Content(ByteList)
                                debug!(
                                    "Sending content data via uTP with len: {}",
                                    content_data.len()
                                );
                                // send the content to the requester over a uTP stream
                                let result = conn
                                    .send_to(
                                        &UtpMessage::new(content_data.as_ssz_bytes()).encode()[..],
                                    )
                                    .await;

                                if let Err(err) = result {
                                    error!("Error sending content {err}");
                                    return;
                                }

                                // Close uTP connection
                                let mut conn_clone = conn.clone();
                                tokio::spawn(async move {
                                    if let Err(msg) = conn_clone.close().await {
                                        error!("Unable to close uTP connection!: {msg}")
                                    }
                                });
                            }
                        } else {
                            warn!(
                                "Received SYN packet for an unknown active uTP stream: {packet:?}"
                            );
                        }
                    }
                    // Receive DATA and FIN packets
                    PacketType::Data => {
                        let conn_key = ConnectionKey::new(*node_id, connection_id);
                        let mut conn = self.utp_connections.get_mut(&conn_key);

                        // To resolve bidirectional uTP packets, we also check for a key with connection_id - 1
                        if conn.is_none() {
                            let conn_key =
                                ConnectionKey::new(*node_id, connection_id.wrapping_sub(1));
                            conn = self.utp_connections.get_mut(&conn_key);
                        }

                        if let Some(conn) = conn {
                            if conn.discv5_tx.send(packet.clone()).is_err() {
                                error!("Unable to send DATA packet to uTP stream handler");
                                return;
                            }

                            let mut buf = [0; BUF_SIZE];
                            match conn.recv_from(&mut buf).await {
                                Ok((bytes_read, _)) => {
                                    if bytes_read > 0 {
                                        conn.recv_data_stream.extend_from_slice(&buf[..bytes_read]);
                                    }
                                }
                                Err(err) => {
                                    error!("Unable to receive uTP packet {packet:?}: {err}")
                                }
                            }
                        } else {
                            warn!(
                                "Received DATA packet for an unknown active uTP stream: {packet:?}, stream id: {}", connection_id
                            )
                        }
                    }
                    PacketType::Fin => {
                        // As we can receive bidirectional FIN packets, we handle explicitly here
                        // only the packet received when we are receiver of the data.
                        // When we send the data and receive a FIN packet, those packet is handled
                        // implicitly in overlay when we close the connection with `conn.close()`
                        if let Some(conn) = self
                            .utp_connections
                            .get_mut(&ConnectionKey::new(*node_id, connection_id.wrapping_sub(1)))
                        {
                            if conn.discv5_tx.send(packet).is_err() {
                                error!("Unable to send FIN packet to uTP stream handler");
                                return;
                            }

                            // When FIN is received, loop and collect all remaining payload before closing the connection
                            loop {
                                let mut buf = [0; BUF_SIZE];

                                match conn.recv_from(&mut buf).await {
                                    Ok((bytes_read, _)) => {
                                        if bytes_read > 0 {
                                            conn.recv_data_stream
                                                .extend_from_slice(&buf[..bytes_read]);
                                        } else {
                                            conn.emit_close_event();
                                            break;
                                        }
                                    }
                                    Err(err) => error!("Unable to receive uTP FIN packet: {err}"),
                                }
                            }
                        } else if let Some(conn) = self
                            .utp_connections
                            .get_mut(&ConnectionKey::new(*node_id, connection_id))
                        {
                            if conn.state == StreamState::Connected {
                                // Do not handle the packet here, send it to uTP socket layer
                                if conn.discv5_tx.send(packet).is_err() {
                                    error!("Unable to send FIN packet to uTP stream handler");
                                }

                                let mut buf = [0; BUF_SIZE];

                                match conn.recv(&mut buf).await {
                                    Ok(_) => {
                                        conn.emit_close_event();
                                    }
                                    Err(err) => error!("Unable to receive uTP FIN packet: {err}"),
                                }
                            }
                        } else {
                            warn!(
                                "Received FIN packet for an unknown active uTP stream: {packet:?}"
                            )
                        }
                    }
                    PacketType::State => {
                        let conn_key = ConnectionKey::new(*node_id, connection_id);
                        let mut conn = self.utp_connections.get_mut(&conn_key);

                        // To resolve bidirectional uTP packets, we also check for a key with connection_id - 1
                        if conn.is_none() {
                            let conn_key =
                                ConnectionKey::new(*node_id, connection_id.wrapping_sub(1));
                            conn = self.utp_connections.get_mut(&conn_key);
                        }
                        if let Some(conn) = conn {
                            if conn.discv5_tx.send(packet).is_err() {
                                error!("Unable to send STATE packet to uTP stream handler");
                            }
                            // We don't handle STATE packets here, because the uTP client is handling them
                            // implicitly in the background when sending FIN packet with conn.close()
                        } else {
                            warn!("Received STATE packet for an unknown active uTP stream: {packet:?}");
                        }
                    }
                }
            }
            Err(err) => {
                error!("Failed to decode packet: {err}");
            }
        }
    }

    /// Process overlay uTP requests
    async fn process_overlay_request(&mut self, request: UtpListenerRequest) {
        match request {
            UtpListenerRequest::InitiateConnection(
                connected_to,
                protocol_id,
                stream_id,
                conn_id_recv,
            ) => {
                let conn = UtpStream::new(
                    Arc::clone(&self.discovery),
                    connected_to.clone(),
                    protocol_id,
                    stream_id,
                    Some(self.stream_tx.clone()),
                );
                let conn_key = ConnectionKey::new(connected_to.node_id(), conn_id_recv);
                self.utp_connections.insert(conn_key, conn);
            }
            UtpListenerRequest::Connect(conn_id, enr, protocol_id, stream_id, tx) => {
                let conn = self.connect(conn_id, enr, protocol_id, stream_id).await;
                if tx.send(conn).is_err() {
                    error!("Unable to send the uTP stream to requester")
                };
            }
        }
    }

    /// Emit global uTP listener event upon processing uTP stream event
    fn process_stream_event(&mut self, event: UtpStreamEvent) {
        match event {
            UtpStreamEvent::Closed(utp_payload, protocol_id, stream_id, conn_key) => {
                // Remove closed stream from active connections
                if self.utp_connections.remove(&conn_key).is_none() {
                    error!("Unable to remove closed uTP stream from active connections, STREAM_CONN_ID_RECV: {}, CONNECTED_TO: {}", conn_key.conn_id_recv, conn_key.node_id);
                }

                // Emit global event to overlay handler
                if let Err(err) = self.overlay_tx.send(UtpListenerEvent::ClosedStream(
                    utp_payload,
                    protocol_id,
                    stream_id,
                )) {
                    error!("Unable to send ClosedStream event to overlay handler: {err}");
                }
            }
            UtpStreamEvent::Reset(protocol_id, stream_id, conn_key) => {
                // Remove reset stream from active connections
                if self.utp_connections.remove(&conn_key).is_none() {
                    error!("Unable to remove reset uTP stream from active connections, STREAM_CONN_ID_RECV: {}, CONNECTED_TO: {}", conn_key.conn_id_recv, conn_key.node_id);
                }

                if let Err(err) = self
                    .overlay_tx
                    .send(UtpListenerEvent::ResetStream(protocol_id, stream_id))
                {
                    error!("Unable to send ResetStream event to overlay handler: {err}");
                }
            }
        }
    }

    /// Initialize uTP stream with remote node
    async fn connect(
        &mut self,
        connection_id: ConnId,
        enr: Enr,
        protocol_id: ProtocolId,
        stream_id: UtpStreamId,
    ) -> UtpStream {
        let mut conn = UtpStream::new(
            Arc::clone(&self.discovery),
            enr.clone(),
            protocol_id,
            stream_id,
            Some(self.stream_tx.clone()),
        );
        conn.make_connection(connection_id).await;
        self.utp_connections.insert(
            ConnectionKey::new(enr.node_id(), conn.receiver_connection_id),
            conn.clone(),
        );

        conn
    }
}

// Used to be MicroTransportProtocol impl but it is basically just called UtpStream compared to the
// Rust Tcp Lib so I changed it
#[derive(Debug, Clone)]
pub struct UtpStream {
    /// The wrapped discv5 protocol
    socket: Arc<Discovery>,

    /// uTP stream state
    pub state: StreamState,

    /// ENR of the connected remote peer
    pub connected_to: Enr,

    /// Overlay protocol identifier
    protocol_id: ProtocolId,

    /// Overlay uTP stream id
    stream_id: UtpStreamId,

    /// Sequence number for the next packet
    seq_nr: u16,

    /// Sequence number of the latest acknowledged packet sent by the remote peer
    ack_nr: u16,

    /// Sender connection identifier
    sender_connection_id: ConnId,

    /// Receiver connection identifier
    receiver_connection_id: ConnId,

    /// Congestion window in bytes
    cwnd: u32,

    /// Received but not acknowledged packets
    incoming_buffer: Vec<Packet>,

    /// Packets not yet sent
    unsent_queue: VecDeque<Packet>,

    /// Bytes in flight
    pub cur_window: u32,

    /// Window size of the remote peer
    remote_wnd_size: u32,

    /// Sent but not yet acknowledged packets
    send_window: Vec<Packet>,

    /// How many ACKs did the stream receive for packet with sequence number equal to `ack_nr`
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

    /// Start of the current minute for sampling purposes
    last_rollover: Timestamp,

    /// Maximum retransmission retries
    max_retransmission_retries: u32,

    /// Send channel for discv5 socket
    discv5_tx: UnboundedSender<Packet>,

    /// Receive channel for discv5 socket
    discv5_rx: Arc<RwLock<UnboundedReceiver<Packet>>>,

    /// Sender to emit stream events to UtpListener
    event_tx: Option<UnboundedSender<UtpStreamEvent>>,

    /// Store received uTP payload data over the stream
    pub recv_data_stream: Vec<u8>,
}

impl UtpStream {
    pub fn new(
        socket: Arc<Discovery>,
        connected_to: Enr,
        protocol_id: ProtocolId,
        stream_id: UtpStreamId,
        utp_listener_tx: Option<UnboundedSender<UtpStreamEvent>>,
    ) -> Self {
        let (receiver_id, sender_id) = generate_sequential_identifiers();

        let (discv5_tx, discv5_rx) = unbounded_channel::<Packet>();

        Self {
            state: StreamState::Uninitialized,
            protocol_id,
            stream_id,
            seq_nr: 1,
            ack_nr: 0,
            receiver_connection_id: receiver_id,
            sender_connection_id: sender_id,
            cwnd: INIT_CWND * MAX_DISCV5_PACKET_SIZE,
            incoming_buffer: Default::default(),
            unsent_queue: VecDeque::new(),
            connected_to,
            socket,
            cur_window: 0,
            remote_wnd_size: 0,
            send_window: Vec::new(),
            duplicate_ack_count: 0,
            last_acked: 0,
            last_acked_timestamp: Timestamp::default(),
            last_dropped: 0,
            rtt: 0,
            rtt_variance: 0,
            pending_data: Vec::new(),
            base_delays: VecDeque::with_capacity(BASE_HISTORY),
            their_delay: Delay::default(),
            congestion_timeout: 1000,
            last_rollover: Timestamp::default(),
            current_delays: Vec::with_capacity(8),
            recv_data_stream: Vec::new(),
            max_retransmission_retries: MAX_RETRANSMISSION_RETRIES,
            discv5_tx,
            discv5_rx: Arc::new(RwLock::new(discv5_rx)),
            event_tx: utp_listener_tx,
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
    pub async fn send_to(&mut self, buf: &[u8]) -> anyhow::Result<usize> {
        if self.state == StreamState::Closed {
            return Err(anyhow!("The stream is closed"));
        }

        let total_length = buf.len();

        for chunk in buf.chunks(
            MAX_DISCV5_PACKET_SIZE as usize
                - MAX_DISCV5_HEADER_SIZE
                - PAYLOAD_LENGTH_SIZE
                - HEADER_SIZE,
        ) {
            let mut packet = Packet::with_payload(chunk);
            packet.set_seq_nr(self.seq_nr);
            packet.set_ack_nr(self.ack_nr);
            packet.set_wnd_size(WINDOW_SIZE.saturating_sub(self.cur_window));
            packet.set_connection_id(self.sender_connection_id);

            self.unsent_queue.push_back(packet);

            // Intentionally wrap around sequence number
            self.seq_nr = self.seq_nr.wrapping_add(1);
        }

        // Send every packet in the queue
        self.send_packets_in_queue().await;

        Ok(total_length)
    }

    pub async fn raw_receive(&mut self) -> Option<Packet> {
        // Listen on a channel for discovery utp packet
        match timeout(
            Duration::from_millis(DISCV5_SOCKET_TIMEOUT),
            self.discv5_rx.write_with_warn().await.recv(),
        )
        .await
        {
            Ok(val) => val,
            Err(_) => None,
        }
    }

    async fn send_packets_in_queue(&mut self) {
        while let Some(mut packet) = self.unsent_queue.pop_front() {
            self.send_packet(&mut packet).await;
            self.cur_window += packet.len() as u32;
            self.send_window.push(packet);
        }
    }

    #[async_recursion]
    async fn resend_lost_packet(&mut self, lost_packet_nr: u16) {
        debug!("---> resend_lost_packet({}) <---", lost_packet_nr);
        match self
            .send_window
            .iter()
            .position(|pkt| pkt.seq_nr() == lost_packet_nr)
        {
            None => debug!("Packet {} not found", lost_packet_nr),
            Some(position) => {
                debug!("Send window len: {}", self.send_window.len());
                debug!("position: {}", position);
                let mut packet = self.send_window[position].clone();
                self.send_packet(&mut packet).await;

                // We intentionally don't increase `curr_window` because otherwise a packet's length
                // would be counted more than once
            }
        }
        debug!("---> END resend_lost_packet <---");
    }

    /// Send one packet.
    #[async_recursion]
    async fn send_packet(&mut self, packet: &mut Packet) {
        let max_inflight = min(self.cwnd, self.remote_wnd_size);
        let max_inflight = max(MIN_CWND * MAX_DISCV5_PACKET_SIZE, max_inflight);
        let now = now_microseconds();

        // Wait until enough in-flight packets are acknowledged for rate control purposes, but don't
        // wait more than 500 ms (PRE_SEND_TIMEOUT) before sending the packet
        while self.cur_window + packet.as_ref().len() as u32 > max_inflight as u32
            && now_microseconds() - now < PRE_SEND_TIMEOUT.into()
        {
            let mut buf = [0; BUF_SIZE];
            if let Err(msg) = self.recv(&mut buf).await {
                debug!("Unable to receive from uTP socket: {msg}");
            }
        }

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
        packet.set_timestamp_difference(self.their_delay);

        let packet_to_send = packet.clone();

        debug!("Sending uTP packet ... {packet:?}");
        // Handle talkreq/talkresp in the background
        tokio::spawn(async move {
            if let Err(response) = discovery
                .send_talk_req(enr, ProtocolId::Utp, Vec::from(packet_to_send.as_ref()))
                .await
            {
                debug!("Unable to send uTP packet {:?}: {response}", packet_to_send)
            }
        });
    }

    // Insert a new sample in the base delay list.
    //
    // The base delay list contains at most `BASE_HISTORY` samples, each sample is the minimum
    // measured over a period of a minute (MAX_BASE_DELAY_AGE).
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
    fn update_current_delay(&mut self, our_delay: Delay, now: Timestamp) {
        // Remove samples more than one RTT old
        let rtt = (self.rtt as i64 * 100).into();
        while !self.current_delays.is_empty() && now - self.current_delays[0].received_at > rtt {
            self.current_delays.remove(0);
        }

        // Insert new measurement
        self.current_delays.push(DelayDifferenceSample {
            received_at: now,
            difference: our_delay,
        });
    }

    async fn make_connection(&mut self, connection_id: ConnId) {
        if self.state == StreamState::Uninitialized {
            self.receiver_connection_id = connection_id;
            self.sender_connection_id = self.receiver_connection_id + 1;

            let mut packet = Packet::new();
            packet.set_type(PacketType::Syn);
            packet.set_connection_id(self.receiver_connection_id);
            packet.set_wnd_size(WINDOW_SIZE);
            packet.set_seq_nr(self.seq_nr);

            self.send_packet(&mut packet).await;
            self.state = StreamState::SynSent;
        }
    }

    /// Builds the selective acknowledgement extension data for usage in packets.
    fn build_selective_ack(&self) -> Vec<u8> {
        // Build selective ack for empty incoming buffer
        if self.incoming_buffer.is_empty() {
            let mut sack: Vec<u8> = vec![0u8; 4];
            sack[0] = 1;

            return sack;
        }

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

    pub async fn send_finalize(&mut self) {
        let mut packet = Packet::new();
        packet.set_type(PacketType::Fin);
        packet.set_connection_id(self.sender_connection_id);
        packet.set_seq_nr(self.seq_nr);
        packet.set_ack_nr(self.ack_nr);

        self.send_packet(&mut packet).await;
        self.state = StreamState::FinSent;
    }

    /// Handle uTP socket timeout
    async fn handle_receive_timeout(&mut self) -> anyhow::Result<()> {
        self.congestion_timeout = self.congestion_timeout.saturating_mul(2);
        self.cwnd = INIT_CWND * MAX_DISCV5_PACKET_SIZE;

        // There are four possible cases here:
        //
        // - If the socket is sending and waiting for acknowledgements (the send window is
        //   not empty), resend the first unacknowledged packet;
        //
        // - If the socket is not sending and it hasn't sent a FIN yet, then it's waiting
        //   for incoming packets: send a fast resend request;
        //
        // - If the socket sent a FIN previously, resend it.
        //
        // - If the socket sent a SYN previously, resend it.
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
            if self.state == StreamState::FinSent {
                let mut packet = Packet::new();
                packet.set_connection_id(self.sender_connection_id);
                packet.set_seq_nr(self.seq_nr);
                packet.set_ack_nr(self.ack_nr);
                packet.set_timestamp(now_microseconds());
                packet.set_type(PacketType::Fin);

                // Send FIN
                debug!("resending FIN: {:?}", packet);
                let _ = self
                    .socket
                    .send_talk_req(
                        self.connected_to.clone(),
                        ProtocolId::Utp,
                        Vec::from(packet.as_ref()),
                    )
                    .await;
            } else if self.state == StreamState::SynSent {
                // SYN packet is sent but no response from remote peer, try to resend SYN packet
                let mut packet = Packet::new();
                packet.set_type(PacketType::Syn);
                packet.set_timestamp(now_microseconds());
                packet.set_connection_id(self.receiver_connection_id);
                packet.set_wnd_size(WINDOW_SIZE);
                packet.set_seq_nr(1);

                // Send SYN
                debug!("resending SYN: {:?}", packet);
                let _ = self
                    .socket
                    .send_talk_req(
                        self.connected_to.clone(),
                        ProtocolId::Utp,
                        Vec::from(packet.as_ref()),
                    )
                    .await;

                // When resending SYN packet, we want to make sure that we increase the socket seq_nr
                if self.seq_nr == 1 {
                    self.seq_nr = self.seq_nr.wrapping_add(1)
                }
            } else if self.state != StreamState::Uninitialized {
                // The socket is waiting for incoming packets but the remote peer is silent:
                // send a fast resend request.
                debug!("sending fast resend request");
                // TODO: send fast resend request
            }
        } else {
            // The socket is sending data packets but there is no reply from the remote
            // peer: resend the first unacknowledged packet with the current timestamp.
            let packet = &mut self.send_window[0];
            packet.set_timestamp(now_microseconds());
            let _ = self
                .socket
                .send_talk_req(
                    self.connected_to.clone(),
                    ProtocolId::Utp,
                    Vec::from(packet.as_ref()),
                )
                .await;
            debug!("resent {:?}", packet);
        }

        Ok(())
    }

    #[async_recursion]
    async fn handle_packet(&mut self, packet: &Packet, src: Enr) -> anyhow::Result<Option<Packet>> {
        debug!(
            "Handle packet: {:?}. Conn state: {:?}",
            packet.get_type(),
            self.state
        );

        // To make uTP connection bidirectional, we want to always acknowledge the received packet
        if self.state == StreamState::SynSent {
            self.ack_nr = packet.seq_nr();
        } else {
            // Only acknowledge this if this follows the last one, else do it when we advance the send
            // window
            if packet.seq_nr().wrapping_sub(self.ack_nr) == 1
                && packet.get_type() != PacketType::State
            {
                self.ack_nr = packet.seq_nr();
            }
        }

        // Reset connection if connection id doesn't match and this isn't a SYN

        if packet.get_type() != PacketType::Syn
            && self.state != StreamState::SynSent
            && !(packet.connection_id() == self.sender_connection_id
                || packet.connection_id() == self.receiver_connection_id)
        {
            return Ok(Some(self.prepare_reply(packet, PacketType::Reset)));
        }

        // Update remote window size
        self.remote_wnd_size = packet.wnd_size();

        // Update remote peer's delay between them sending the packet and us receiving it
        let now = now_microseconds();
        self.their_delay = abs_diff(now, packet.timestamp());

        match (self.state, packet.get_type()) {
            // New connection, when we receive SYN packet, respond with STATE packet
            (StreamState::Uninitialized, PacketType::Syn) => {
                self.connected_to = src;
                self.ack_nr = packet.seq_nr();
                self.seq_nr = rand::random();
                self.receiver_connection_id = packet.connection_id() + 1;
                self.sender_connection_id = packet.connection_id();
                self.state = StreamState::Connected;
                self.last_dropped = self.ack_nr;

                let reply = self.prepare_reply(packet, PacketType::State);
                // We always assume that SYN-ACK packet is acknowledged, this allows us to send DATA packet right after
                // SYN-ACK (bi-directional utp flow)
                self.last_acked = reply.seq_nr();

                Ok(Some(reply))
            }
            // When connection is already initialised and we receive SYN packet,
            // we want to forcibly terminate the connection
            (_, PacketType::Syn) => Ok(Some(self.prepare_reply(packet, PacketType::Reset))),
            // When SYN is send and we receive STATE, do not reply
            (StreamState::SynSent, PacketType::State) => {
                self.connected_to = src;
                self.ack_nr = packet.seq_nr() - 1;
                self.seq_nr += 1;
                self.state = StreamState::Connected;
                self.last_acked = packet.ack_nr();
                self.last_acked_timestamp = now_microseconds();
                Ok(None)
            }
            // To make uTP connection bidirectional, we also can expect DATA packet if state is SynSent
            (StreamState::SynSent, PacketType::Data) => Ok(self.handle_data_packet(packet)),
            // Handle data packet if stream state is `Connected` or `FinSent` and packet type is DATA
            (StreamState::Connected, PacketType::Data)
            | (StreamState::FinSent, PacketType::Data) => Ok(self.handle_data_packet(packet)),
            // Handle state packet if stream state is `Connected` and packet type is STATE
            (StreamState::Connected, PacketType::State) => {
                self.handle_state_packet(packet).await;
                Ok(None)
            }
            // Handle FIN packet. Check if all send packets are acknowledged.
            (StreamState::Connected, PacketType::Fin)
            | (StreamState::FinSent, PacketType::Fin)
            | (StreamState::SynSent, PacketType::Fin) => {
                if packet.ack_nr() < self.seq_nr {
                    debug!("FIN received but there are missing acknowledgements for sent packets");
                }
                let mut reply = self.prepare_reply(packet, PacketType::State);

                if packet.seq_nr().wrapping_sub(self.ack_nr) > 1 {
                    warn!(
                        "current ack_nr ({}) is behind received packet seq_nr ({})",
                        self.ack_nr,
                        packet.seq_nr()
                    );

                    // Set SACK extension payload if the packet is not in order
                    let sack = self.build_selective_ack();

                    if !sack.is_empty() {
                        reply.set_selective_ack(sack);
                    }
                }

                // Give up, the remote peer might not care about our missing packets
                self.state = StreamState::Closed;

                Ok(Some(reply))
            }
            // Confirm with STATE packet when stream state is `Closed` and we receive FIN packet
            (StreamState::Closed, PacketType::Fin) => {
                Ok(Some(self.prepare_reply(packet, PacketType::State)))
            }
            (StreamState::FinSent, PacketType::State) => {
                if packet.ack_nr() == self.seq_nr {
                    self.state = StreamState::Closed;
                    self.emit_close_event();
                } else {
                    self.handle_state_packet(packet).await;
                }
                Ok(None)
            }
            // Reset connection when receiving RESET packet
            (_, PacketType::Reset) => {
                self.state = StreamState::ResetReceived;
                // Emit stream state event to UtpListener
                if let Some(listener_tx) = self.event_tx.clone() {
                    let conn_key = self.get_conn_key();

                    if let Err(err) = listener_tx.send(UtpStreamEvent::Reset(
                        self.protocol_id.clone(),
                        self.stream_id.clone(),
                        conn_key,
                    )) {
                        error!("Unable to send uTP RESET event to uTP listener: {err}");
                    }
                }
                debug!(
                    "Connection reset by remote peer. Connection id: {}",
                    packet.connection_id()
                );
                Ok(None)
            }
            (state, ty) => {
                let message = format!("Unimplemented handling for ({state:?},{ty:?})");
                debug!("{}", message);
                Err(anyhow!(message))
            }
        }
    }

    /// Emit stream state event to UtpListener
    fn emit_close_event(&mut self) {
        if let Some(listener_tx) = self.event_tx.clone() {
            let conn_key = self.get_conn_key();

            if let Err(err) = listener_tx.send(UtpStreamEvent::Closed(
                self.recv_data_stream.clone(),
                self.protocol_id.clone(),
                self.stream_id.clone(),
                conn_key,
            )) {
                error!("Unable to send uTP CLOSED event to uTP listener: {err}");
            }
        }
    }

    /// Get connection key used in uTP listener to store active uTP connections
    fn get_conn_key(&self) -> ConnectionKey {
        let conn_id = match self.stream_id {
            UtpStreamId::FindContentStream => self.receiver_connection_id,
            UtpStreamId::ContentStream(_) => self.sender_connection_id,
            UtpStreamId::OfferStream => self.receiver_connection_id,
            UtpStreamId::AcceptStream(_) => self.sender_connection_id,
        };
        ConnectionKey::new(self.connected_to.node_id(), conn_id)
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
        // We increase packet seq_nr if we are going to send DATA packet right after SYN-ACK.
        if self.state == StreamState::SynSent {
            self.seq_nr += 1;
            self.state = StreamState::Connected
        }

        // If a FIN was previously sent, reply with a FIN packet acknowledging the received packet.
        let packet_type = match self.state {
            StreamState::FinSent => PacketType::Fin,
            _ => PacketType::State,
        };

        let mut reply = self.prepare_reply(packet, packet_type);

        if packet.seq_nr().wrapping_sub(self.ack_nr) > 1 {
            debug!(
                "current ack_nr ({}) is behind received packet seq_nr ({})",
                self.ack_nr,
                packet.seq_nr()
            );

            // Set SACK extension payload if the packet is not in order
            let sack_bitfield = self.build_selective_ack();

            if !sack_bitfield.is_empty() {
                reply.set_selective_ack(sack_bitfield);
            }
        }
        Some(reply)
    }

    #[async_recursion]
    async fn handle_state_packet(&mut self, packet: &Packet) {
        if self.last_acked == packet.ack_nr() {
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
            self.update_base_delay(our_delay, now);
            self.update_current_delay(our_delay, now);

            let off_target: f64 =
                (CCONTROL_TARGET - u32::from(self.queuing_delay()) as f64) / CCONTROL_TARGET;

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
                    self.resend_lost_packet(packet.ack_nr() + 1).await;
                    packet_loss_detected = true;
                }

                if let Some(last_seq_nr) = self.send_window.last().map(Packet::seq_nr) {
                    // Remove all acknowledged packets from the send window
                    let ack_packets = extension
                        .iter()
                        .enumerate()
                        .filter(|&(_, received)| received)
                        .map(|(idx, _)| packet.ack_nr() + 2 + idx as u16)
                        .take_while(|&seq_nr| seq_nr <= last_seq_nr);

                    for seq_nr in ack_packets {
                        if let Some(position) = self
                            .send_window
                            .iter()
                            .position(|packet| packet.seq_nr() == seq_nr)
                        {
                            let packet = self.send_window.remove(position);
                            self.cur_window -= packet.len() as u32;
                        }
                    }
                    // Resend lost packets
                    let lost_packets = extension
                        .iter()
                        .enumerate()
                        .filter(|&(_, received)| !received)
                        .map(|(idx, _)| packet.ack_nr() + 2 + idx as u16)
                        .take_while(|&seq_nr| seq_nr < last_seq_nr);

                    for seq_nr in lost_packets {
                        debug!("SACK: packet {} lost", seq_nr);
                        self.resend_lost_packet(seq_nr).await;
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
            self.resend_lost_packet(packet.ack_nr() + 1).await;
        }

        // Packet lost, halve the congestion window
        if packet_loss_detected {
            debug!("packet loss detected, halving congestion window");
            self.cwnd = max(self.cwnd / 2, MIN_CWND * MAX_DISCV5_PACKET_SIZE);
            debug!("congestion window: {}", self.cwnd);
        }

        // Success, advance send window
        self.advance_send_window();
    }

    /// Forgets sent packets that were acknowledged by the remote peer.
    fn advance_send_window(&mut self) {
        // The reason we are not removing the first element in a loop while its sequence number is
        // smaller than `last_acked` is because of wrapping sequence numbers, which would create the
        // sequence [..., 65534, 65535, 0, 1, ...]. If `last_acked` is smaller than the first
        // packet's sequence number because of wraparound (for instance, 1), no packets would be
        // removed, as the condition `seq_nr < last_acked` would fail immediately.
        //
        // On the other hand, we can't keep removing the first packet in a loop until its sequence
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
    }

    fn queuing_delay(&self) -> Delay {
        let filtered_current_delay = self.filtered_current_delay();
        let min_base_delay = self.min_base_delay();
        filtered_current_delay - min_base_delay
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

    /// Calculates the new congestion window size, increasing it or decreasing it.
    ///
    /// This is the core of uTP, the [LEDBAT][ledbat_rfc] congestion algorithm. It depends on
    /// estimating the queuing delay between the two peers, and adjusting the congestion window
    /// accordingly.
    ///
    /// `off_target` is a normalized value representing the difference between the current queuing
    /// delay and a fixed target delay (`CCONTROL_TARGET`). `off_target` ranges between -1.0 and 1.0. A
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

        let cwnd_increase =
            GAIN * off_target * bytes_newly_acked as f64 * MAX_DISCV5_PACKET_SIZE as f64;
        let cwnd_increase = cwnd_increase / self.cwnd as f64;

        self.cwnd = (self.cwnd as f64 + cwnd_increase) as u32;
        let max_allowed_cwnd = flightsize + ALLOWED_INCREASE * MAX_DISCV5_PACKET_SIZE;
        self.cwnd = min(self.cwnd, max_allowed_cwnd);
        self.cwnd = max(self.cwnd, MIN_CWND * MAX_DISCV5_PACKET_SIZE);
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
    }

    /// Receives data from socket.
    ///
    /// On success, returns the number of bytes read and the sender's ENR.
    /// Returns 0 bytes read after receiving a FIN packet when the remaining
    /// in-flight packets are consumed.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> anyhow::Result<(usize, Enr)> {
        let read = self.flush_incoming_buffer(buf);

        if read > 0 {
            return Ok((read, self.connected_to.clone()));
        }

        // If the stream received a reset packet and all data has been flushed, then it can't
        // receive anything else
        if self.state == StreamState::ResetReceived {
            return Err(anyhow!("Connection reset by remote peer"));
        }

        loop {
            // A closed stream with no pending data can only "read" 0 new bytes.
            if self.state == StreamState::Closed {
                return Ok((0, self.connected_to.clone()));
            }

            match self.recv(buf).await {
                Ok(Some(0)) => {
                    continue;
                }
                Ok(Some(bytes)) => {
                    return Ok((bytes, self.connected_to.clone()));
                }
                Ok(None) => {
                    return Ok((0, self.connected_to.clone()));
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[async_recursion]
    pub async fn recv(&mut self, buf: &mut [u8]) -> anyhow::Result<Option<usize>> {
        let packet;

        let mut recv_retries = 0;
        // Try to receive a packet. Abort loop if the current try exceeds the maximum number of retransmission retries.
        loop {
            let result = self.raw_receive().await;

            match result {
                Some(pkt) => {
                    packet = pkt;
                    break;
                }
                None => {
                    recv_retries += 1;

                    if recv_retries > self.max_retransmission_retries {
                        tokio::time::sleep(Duration::from_millis(UTP_RECEIVE_TIMEOUT)).await;
                        self.handle_receive_timeout().await?;
                        return Ok(None);
                    }
                }
            }
        }

        debug!("received {:?}", packet);

        // Insert data packet into the incoming buffer if it isn't a duplicate of a previously
        // discarded packet
        if packet.get_type() == PacketType::Data
            && packet.seq_nr().wrapping_sub(self.last_dropped) > 0
        {
            self.insert_into_buffer(packet.clone());
        }

        // Process packet, including sending a reply if necessary
        if let Some(mut pkt) = self
            .handle_packet(&packet, self.connected_to.clone())
            .await?
        {
            pkt.set_wnd_size(WINDOW_SIZE.saturating_sub(self.cur_window));
            if let Err(msg) = self
                .socket
                .send_talk_req(
                    self.connected_to.clone(),
                    ProtocolId::Utp,
                    Vec::from(pkt.as_ref()),
                )
                .await
            {
                let msg = format!("reply packet error {packet:?}: {msg}");
                warn!("{msg}");
                return Err(anyhow!(msg));
            }

            debug!("sent {:?}", pkt);
        }

        // Flush incoming buffer if possible
        let read = self.flush_incoming_buffer(buf);

        Ok(Some(read))
    }

    /// Discards sequential, ordered packets in incoming buffer, starting from
    /// the most recently acknowledged to the most recent, as long as there are
    /// no missing packets. The discarded packets' payload is written to the
    /// slice `buf`, starting in position `start`.
    /// Returns the last written index.
    fn flush_incoming_buffer(&mut self, buf: &mut [u8]) -> usize {
        fn unsafe_copy(src: &[u8], dst: &mut [u8]) -> usize {
            let max_len = min(src.len(), dst.len());
            // Unsafe is needed because `copy` is unsafe function
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
            let flushed = unsafe_copy(self.incoming_buffer[0].payload(), buf);

            if flushed == self.incoming_buffer[0].payload().len() {
                self.advance_incoming_buffer();
            } else {
                self.pending_data = self.incoming_buffer[0].payload()[flushed..].to_vec();
            }

            return flushed;
        }

        0
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

    /// Inserts a packet into the stream's buffer.
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

    /// Gracefully closes connection to peer.
    ///
    /// This method allows both peers to receive all packets still in
    /// flight.
    pub async fn close(&mut self) -> anyhow::Result<()> {
        // Nothing to do if the stream's already closed or not connected
        if self.state == StreamState::Closed || self.state == StreamState::Uninitialized {
            return Ok(());
        }

        // Flush unsent and unacknowledged packets
        self.flush().await?;

        let mut packet = Packet::new();
        packet.set_connection_id(self.sender_connection_id);
        packet.set_seq_nr(self.seq_nr);
        packet.set_ack_nr(self.ack_nr);
        packet.set_wnd_size(WINDOW_SIZE.saturating_sub(self.cur_window));
        packet.set_timestamp(now_microseconds());
        packet.set_type(PacketType::Fin);

        // Send FIN
        debug!("Closing connection, sending {:?}", packet);
        if let Err(msg) = self
            .socket
            .send_talk_req(
                self.connected_to.clone(),
                ProtocolId::Utp,
                Vec::from(packet.as_ref()),
            )
            .await
        {
            let msg = format!("Unable to send FIN packet: {msg}");
            debug!("{msg}");
            return Err(anyhow!(msg));
        }

        self.state = StreamState::FinSent;

        // Attempts to receive ST_FIN
        let mut buf = [0; BUF_SIZE];
        if self.state != StreamState::Closed {
            self.recv(&mut buf).await?;
        }

        self.state = StreamState::Closed;

        Ok(())
    }

    /// Consumes acknowledgements for every pending packet.
    /// Try to receive acknowledgements for up to MAX_RECV_ACKS_RETRIES.
    pub async fn flush(&mut self) -> anyhow::Result<()> {
        let mut buf = [0u8; BUF_SIZE];

        let mut flush_retries: u8 = 0;

        while !self.send_window.is_empty() && flush_retries < MAX_RECV_ACKS_RETRIES {
            self.recv(&mut buf).await?;
            flush_retries += 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::utp::packets::PacketType::State;
    use crate::{
        portalnet::{
            discovery::Discovery,
            types::messages::{PortalnetConfig, ProtocolId},
            Enr,
        },
        socket,
        utils::node_id::generate_random_remote_enr,
        utp::{
            packets::{Packet, PacketType},
            stream::{StreamState, UtpStream, BUF_SIZE},
            time::now_microseconds,
            trin_helpers::UtpStreamId,
        },
    };

    use discv5::TalkRequest;
    use tokio::sync::mpsc;

    use std::{
        convert::TryFrom,
        net::{IpAddr, SocketAddr},
        str::FromStr,
        sync::Arc,
    };

    fn next_test_port() -> u16 {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT_OFFSET: AtomicUsize = AtomicUsize::new(0);
        const BASE_PORT: u16 = 9600;
        BASE_PORT + NEXT_OFFSET.fetch_add(1, Ordering::Relaxed) as u16
    }

    async fn server_setup() -> UtpStream {
        let ip_addr =
            socket::find_assigned_ip().expect("Could not find an IP for local connections");
        let port = next_test_port();
        let config = PortalnetConfig {
            listen_port: port,
            external_addr: Some(SocketAddr::new(ip_addr, port)),
            ..Default::default()
        };
        let mut discv5 = Discovery::new(config).unwrap();
        let enr = discv5.local_enr();
        let talk_req_rx = discv5.start().await.unwrap();

        let discv5 = Arc::new(discv5);

        let conn = UtpStream::new(
            Arc::clone(&discv5),
            enr,
            ProtocolId::History,
            UtpStreamId::OfferStream,
            None,
        );
        // TODO: Create `Discv5Socket` struct to encapsulate all socket logic
        spawn_socket_recv(talk_req_rx, conn.clone());

        conn
    }

    async fn client_setup(connected_to: Enr) -> (Enr, UtpStream) {
        let port = next_test_port();
        let matching_ip = connected_to.ip4().unwrap();
        let config = PortalnetConfig {
            listen_port: port,
            external_addr: Some(SocketAddr::new(IpAddr::V4(matching_ip), port)),
            ..Default::default()
        };
        let mut discv5 = Discovery::new(config).unwrap();
        let talk_req_rx = discv5.start().await.unwrap();

        let discv5 = Arc::new(discv5);

        let conn = UtpStream::new(
            Arc::clone(&discv5),
            connected_to,
            ProtocolId::History,
            UtpStreamId::OfferStream,
            None,
        );

        spawn_socket_recv(talk_req_rx, conn.clone());

        (discv5.local_enr(), conn)
    }

    fn spawn_socket_recv(mut talk_req_rx: mpsc::Receiver<TalkRequest>, conn: UtpStream) {
        tokio::spawn(async move {
            while let Some(request) = talk_req_rx.recv().await {
                let protocol_id =
                    ProtocolId::from_str(&hex::encode_upper(request.protocol())).unwrap();

                match protocol_id {
                    ProtocolId::Utp => {
                        let payload = request.body();
                        let packet = Packet::try_from(payload).unwrap();
                        conn.discv5_tx.send(packet).unwrap();
                    }
                    _ => {
                        panic!(
                            "Received TalkRequest on unknown protocol from={} protocol={} body={}",
                            request.node_id(),
                            hex::encode_upper(request.protocol()),
                            hex::encode(request.body()),
                        );
                    }
                }
            }
        });
    }

    #[test_log::test(tokio::test)]
    async fn test_build_selective_ack_empty_buffer() {
        let stream = server_setup().await;
        let sack = stream.build_selective_ack();

        assert_eq!(sack, vec![1, 0, 0, 0]);
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_packet() {
        // Boilerplate test setup
        let initial_connection_id: u16 = rand::random();
        let sender_connection_id = initial_connection_id + 1;
        let (_, client_enr) = generate_random_remote_enr();
        let mut stream = server_setup().await;

        // ---------------------------------
        // Test connection setup - SYN packet

        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        // Do we have a response?
        let response = stream.handle_packet(&packet, client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        // Is it of the correct type?
        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        // Same connection id on both ends during connection establishment
        assert_eq!(response.connection_id(), packet.connection_id());

        // Response acknowledges SYN
        assert_eq!(response.ack_nr(), packet.seq_nr());

        // Expect no payloadd
        assert!(response.payload().is_empty());

        // ---------------------------------
        // Test connection usage - transmitting DATA packet

        let old_packet = packet;
        let old_response = response;

        let mut packet = Packet::new();
        packet.set_type(PacketType::Data);
        packet.set_connection_id(sender_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());

        let response = stream.handle_packet(&packet, client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        // Sender (i.e., who the initiated connection and sent a SYN) has connection id equal to
        // initial connection id + 1
        // Receiver (i.e., who accepted connection) has connection id equal to initial connection id
        assert_eq!(response.connection_id(), initial_connection_id);
        assert_eq!(response.connection_id(), packet.connection_id() - 1);

        // Previous packets should be ack'ed
        assert_eq!(response.ack_nr(), packet.seq_nr());

        // Responses with no payload should not increase the sequence number
        assert!(response.payload().is_empty());
        assert_eq!(response.seq_nr(), old_response.seq_nr());

        // ---------------------------------
        // Test connection teardown - FIN packet

        let old_packet = packet;
        let old_response = response;

        let mut packet = Packet::new();
        packet.set_type(PacketType::Fin);
        packet.set_connection_id(sender_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());

        let response = stream.handle_packet(&packet, client_enr).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        let response = response.unwrap();

        assert_eq!(response.get_type(), PacketType::State);

        // FIN packets have no payload but the sequence number shouldn't increase
        assert_eq!(packet.seq_nr(), old_packet.seq_nr() + 1);

        // Nor should the ACK packet's sequence number
        assert_eq!(response.seq_nr(), old_response.seq_nr());

        // FIN should be acknowledged
        assert_eq!(response.ack_nr(), packet.seq_nr());
    }

    #[test_log::test(tokio::test)]
    async fn test_handle_state_packet() {
        let (_, server_enr) = generate_random_remote_enr();
        let (_, mut stream) = client_setup(server_enr).await;

        // Push DATA packet to send window
        let mut data_packet = Packet::new();
        data_packet.set_seq_nr(3);
        stream.cur_window += data_packet.len() as u32;
        stream.send_window.push(data_packet);

        // Handle STATE packet with ack_nr + 2 selective ack
        let mut state_packet = Packet::new();
        state_packet.set_type(State);
        state_packet.set_seq_nr(100);
        state_packet.set_ack_nr(1);
        state_packet.set_selective_ack(vec![1, 0, 0, 0]);

        stream.last_acked = 1;
        stream.handle_state_packet(&state_packet).await;

        // Send window should be empty
        assert!(stream.send_window.is_empty())
    }

    #[test_log::test(tokio::test)]
    async fn test_response_to_keepalive_ack() {
        // Boilerplate test setup
        let initial_connection_id: u16 = rand::random();
        let (_, client_enr) = generate_random_remote_enr();
        let mut stream = server_setup().await;

        // Establish connection
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        let response = stream.handle_packet(&packet, client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        let old_packet = packet;
        let old_response = response;

        // Now, send a keepalive packet
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::State);
        packet.set_connection_id(initial_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());

        let response = stream.handle_packet(&packet, client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_none());

        // Send a second keepalive packet, identical to the previous one
        let response = stream.handle_packet(&packet, client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_none());

        // Mark stream as closed
        stream.state = StreamState::Closed;
    }

    #[test_log::test(tokio::test)]
    async fn test_response_to_wrong_connection_id() {
        // Boilerplate test setup
        let initial_connection_id: u16 = rand::random();
        let (_, client_enr) = generate_random_remote_enr();
        let mut stream = server_setup().await;

        // Establish connection
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        let response = stream.handle_packet(&packet, client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        assert_eq!(response.unwrap().get_type(), PacketType::State);

        // Now, disrupt connection with a packet with an incorrect connection id
        let new_connection_id = initial_connection_id.wrapping_mul(2);

        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::State);
        packet.set_connection_id(new_connection_id);

        let response = stream.handle_packet(&packet, client_enr).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::Reset);
        assert_eq!(response.ack_nr(), packet.seq_nr());

        // Mark stream as closed
        stream.state = StreamState::Closed;
    }

    #[test_log::test(tokio::test)]
    async fn test_unordered_packets() {
        // Boilerplate test setup
        let initial_connection_id: u16 = rand::random();
        let (_, client_enr) = generate_random_remote_enr();
        let mut stream = server_setup().await;

        // Establish connection
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::Syn);
        packet.set_connection_id(initial_connection_id);

        let response = stream.handle_packet(&packet, client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        let response = response.unwrap();
        assert_eq!(response.get_type(), PacketType::State);

        let old_packet = packet;
        let old_response = response;

        let mut window: Vec<Packet> = Vec::new();

        // Now, send a keepalive packet
        let mut packet = Packet::with_payload(&[1, 2, 3]);
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_connection_id(initial_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 1);
        packet.set_ack_nr(old_response.seq_nr());
        window.push(packet);

        let mut packet = Packet::with_payload(&[4, 5, 6]);
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_connection_id(initial_connection_id);
        packet.set_seq_nr(old_packet.seq_nr() + 2);
        packet.set_ack_nr(old_response.seq_nr());
        window.push(packet);

        // Send packets in reverse order
        let response = stream.handle_packet(&window[1], client_enr.clone()).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());
        let response = response.unwrap();
        assert!(response.ack_nr() != window[1].seq_nr());

        let response = stream.handle_packet(&window[0], client_enr).await;
        assert!(response.is_ok());
        let response = response.unwrap();
        assert!(response.is_some());

        // Mark stream as closed
        stream.state = StreamState::Closed;
    }

    #[test_log::test(tokio::test)]
    async fn test_base_delay_calculation() {
        let minute_in_microseconds = 60 * 10i64.pow(6);
        let samples = vec![
            (0, 10),
            (1, 8),
            (2, 12),
            (3, 7),
            (minute_in_microseconds + 1, 11),
            (minute_in_microseconds + 2, 19),
            (minute_in_microseconds + 3, 9),
        ];
        let mut stream = server_setup().await;

        for (timestamp, delay) in samples {
            stream.update_base_delay(delay.into(), ((timestamp + delay) as u32).into());
        }

        let expected = vec![7i64, 9i64]
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        let actual = stream.base_delays.iter().cloned().collect::<Vec<_>>();
        assert_eq!(expected, actual);
        assert_eq!(
            stream.min_base_delay(),
            expected.iter().min().cloned().unwrap_or_default()
        );
    }

    #[test_log::test(tokio::test)]
    async fn test_response_to_triple_ack() {
        let mut buf = [0; BUF_SIZE];
        let mut server = server_setup().await;

        // Fits in a packet
        const LEN: usize = 50;
        let data = (0..LEN).map(|idx| idx as u8).collect::<Vec<u8>>();
        let data_clone = data.clone();
        assert_eq!(LEN, data.len());

        let (enr, mut client) = client_setup(server.connected_to.clone()).await;

        client.make_connection(12).await;

        // Expect SYN packet
        server.connected_to = enr;
        server.recv(&mut buf).await.unwrap();

        // Expect STATE packet
        client.recv(&mut buf).await.unwrap();

        // Send DATA packet
        client.send_to(&data_clone[..]).await.unwrap();

        // Receive data
        let data_packet = server.raw_receive().await.unwrap();

        assert_eq!(data_packet.get_type(), PacketType::Data);
        assert_eq!(&data_packet.payload(), &data.as_slice());
        assert_eq!(data_packet.payload().len(), data.len());

        // Send triple ACK
        let mut packet = Packet::new();
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_type(PacketType::State);
        packet.set_seq_nr(server.seq_nr);
        packet.set_ack_nr(data_packet.seq_nr() - 1);
        packet.set_connection_id(server.sender_connection_id);

        for _ in 0..3 {
            server
                .socket
                .send_talk_req(
                    server.connected_to.clone(),
                    ProtocolId::Utp,
                    packet.as_ref().to_vec(),
                )
                .await
                .unwrap();
        }

        client.recv_from(&mut buf).await.unwrap();

        // Receive data again and check that it's the same we reported as missing
        let client_addr = server.connected_to.clone();
        match server.raw_receive().await {
            Some(packet) => {
                assert_eq!(packet.get_type(), PacketType::Data);
                assert_eq!(packet.seq_nr(), data_packet.seq_nr());
                assert_eq!(packet.payload(), data_packet.payload());
                let response = server.handle_packet(&packet, client_addr.clone()).await;
                assert!(response.is_ok());
                let response = response.unwrap();
                assert!(response.is_some());
                let response = response.unwrap();
                server
                    .socket
                    .send_talk_req(client_addr, ProtocolId::Utp, response.as_ref().to_vec())
                    .await
                    .unwrap();
            }
            None => panic!("Unable to receive packet"),
        }

        client.recv(&mut buf).await.unwrap();

        // Gracefully closes connection
        let handle = tokio::spawn(async move { client.close().await });

        // Received FIN Packet
        server.recv(&mut buf).await.unwrap();
        handle.await.unwrap().unwrap();
    }

    #[test_log::test(tokio::test)]
    async fn test_sorted_buffer_insertion() {
        let mut stream = server_setup().await;

        let mut packet = Packet::new();
        packet.set_seq_nr(1);

        assert!(stream.incoming_buffer.is_empty());

        stream.insert_into_buffer(packet.clone());
        assert_eq!(stream.incoming_buffer.len(), 1);

        packet.set_seq_nr(2);
        packet.set_timestamp(128.into());

        stream.insert_into_buffer(packet.clone());
        assert_eq!(stream.incoming_buffer.len(), 2);
        assert_eq!(stream.incoming_buffer[1].seq_nr(), 2);
        assert_eq!(stream.incoming_buffer[1].timestamp(), 128.into());

        packet.set_seq_nr(3);
        packet.set_timestamp(256.into());

        stream.insert_into_buffer(packet.clone());
        assert_eq!(stream.incoming_buffer.len(), 3);
        assert_eq!(stream.incoming_buffer[2].seq_nr(), 3);
        assert_eq!(stream.incoming_buffer[2].timestamp(), 256.into());

        // Replacing a packet with a more recent version doesn't work
        packet.set_seq_nr(2);
        packet.set_timestamp(456.into());

        stream.insert_into_buffer(packet.clone());
        assert_eq!(stream.incoming_buffer.len(), 3);
        assert_eq!(stream.incoming_buffer[1].seq_nr(), 2);
        assert_eq!(stream.incoming_buffer[1].timestamp(), 128.into());
    }

    #[test_log::test(tokio::test)]
    async fn test_duplicate_packet_handling() {
        let mut buf = [0; BUF_SIZE];
        let mut server = server_setup().await;
        let (enr, mut client) = client_setup(server.connected_to.clone()).await;

        assert_eq!(server.state, StreamState::Uninitialized);
        assert_eq!(client.state, StreamState::Uninitialized);

        // Check proper difference in client's send connection id and receive connection id
        assert_eq!(
            client.sender_connection_id,
            client.receiver_connection_id + 1
        );
        server.connected_to = enr;

        client.make_connection(12).await;

        server.recv_from(&mut buf).await.unwrap();
        client.recv_from(&mut buf).await.unwrap();

        // Expect SYN packet
        assert_eq!(client.state, StreamState::Connected);

        // After establishing a new connection, the server's ids are a mirror of the client's.
        assert_eq!(
            server.receiver_connection_id,
            server.sender_connection_id + 1
        );
        assert_eq!(server.state, StreamState::Connected);

        let mut packet = Packet::with_payload(&[1, 2, 3]);
        packet.set_wnd_size(BUF_SIZE as u32);
        packet.set_connection_id(client.sender_connection_id);
        packet.set_seq_nr(client.seq_nr);
        packet.set_ack_nr(client.ack_nr);

        // Send two copies of the packet, with different timestamps
        for _ in 0..2 {
            packet.set_timestamp(now_microseconds());
            client
                .socket
                .send_talk_req(
                    client.connected_to.clone(),
                    ProtocolId::Utp,
                    packet.as_ref().to_vec(),
                )
                .await
                .unwrap();
        }

        let expected: Vec<u8> = vec![1, 2, 3];
        let mut received: Vec<u8> = vec![];

        loop {
            match server.recv_from(&mut buf).await {
                Ok((0, _src)) => break,
                Ok((len, _src)) => received.extend(buf[..len].to_vec()),
                Err(e) => panic!("{:?}", e),
            }
        }

        assert_eq!(received.len(), expected.len());
        assert_eq!(received, expected);
    }
}
