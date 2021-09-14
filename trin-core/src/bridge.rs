use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use log::warn;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::oneshot;
use tokio_tungstenite::{tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream};

use crate::jsonrpc::{JsonError, JsonNotification, JsonRequest, JsonResponse, Params};

/// An Ethereum data structure.
#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum EthData {
    /// Ethereum block.
    #[serde(rename_all = "camelCase")]
    Block {
        hash: String,
        number: String,
        parent_hash: String,
    },
    /// Ethereum block header.
    #[serde(rename_all = "camelCase")]
    BlockHeader { number: String, parent_hash: String },
}

/// A request for Ethereum data.
enum EthRequest {
    /// Request a block for some hash.
    BlockByHash {
        /// Hash of the block.
        hash: String,
        /// Include full transactions.
        transactions: bool,
    },
}

/// A type of Ethereum data available to subscribe to.
enum EthSubscription {
    NewBlockHeaders,
}

type RequestId = u32;
type SubscriptionId = String;

type SubscriptionSink<T> = UnboundedSender<T>;
type SubscriptionStream<T> = UnboundedReceiver<T>;

struct Subscription<T> {
    id: SubscriptionId,
    stream: SubscriptionStream<T>,
}

#[async_trait]
trait Bridge {
    async fn request(&mut self, request: EthRequest) -> Result<EthData, BridgeError>;
    async fn subscribe(
        &mut self,
        subscription: EthSubscription,
    ) -> Result<Subscription<EthData>, BridgeError>;
    async fn unsubscribe(&mut self, id: SubscriptionId) -> Result<bool, BridgeError>;
}

enum BridgeError {
    ChannelError,
    CommandError,
    ConnectionError,
    SerializationError,
    TransportError,
}

type Responder<T> = oneshot::Sender<T>;
type PendingRequest = Responder<Result<serde_json::Value, JsonError>>;

enum Command {
    Request {
        id: RequestId,
        request: String,
        responder: PendingRequest,
    },
    Subscribe {
        id: SubscriptionId,
        sink: SubscriptionSink<EthData>,
    },
    Unsubscribe {
        id: SubscriptionId,
    },
}

/// An Infura WebSocket bridge.
struct InfuraWsBridge {
    id: Arc<AtomicU32>,
    commands: UnboundedSender<Command>,
}

impl InfuraWsBridge {
    /// Initializes the bridge with a connection to the Infura WebSocket endpoint for `project_id`.
    async fn connect(project_id: String) -> Result<Self, BridgeError> {
        let url = format!("wss://mainnet.infura.io/ws/v3/{}", project_id);

        // TODO: Map error
        let (ws, _) = tokio_tungstenite::connect_async(url)
            .await
            .expect("failed to establish connection with Infura WebSocket server");

        let (tx, rx) = mpsc::unbounded_channel();

        let client = InfuraWsBridgeClient {
            ws,
            commands: rx,
            pending_requests: HashMap::new(),
            subscriptions: HashMap::new(),
        };
        client.spawn();

        Ok(Self {
            id: Arc::new(AtomicU32::new(0)),
            commands: tx,
        })
    }

    /// Returns the next request ID.
    fn next_id(&mut self) -> RequestId {
        self.id.fetch_add(1, Ordering::SeqCst)
    }

    fn send(&self, cmd: Command) -> Result<(), BridgeError> {
        if let Err(_) = self.commands.send(cmd) {
            return Err(BridgeError::CommandError);
        }
        Ok(())
    }

    fn eth_request(id: RequestId, request: EthRequest) -> JsonRequest {
        let jsonrpc = String::from("2.0");
        match request {
            EthRequest::BlockByHash { hash, transactions } => JsonRequest {
                id,
                params: Params::Array(vec![Value::String(hash), Value::Bool(transactions)]),
                method: String::from("eth_getBlockByHash"),
                jsonrpc,
            },
        }
    }

    fn subscribe_request(id: RequestId, subscription: EthSubscription) -> JsonRequest {
        let params = match subscription {
            EthSubscription::NewBlockHeaders => {
                Params::Array(vec![Value::String(String::from("newHeads"))])
            }
        };
        JsonRequest {
            id,
            params,
            method: String::from("eth_subscribe"),
            jsonrpc: String::from("2.0"),
        }
    }

    fn unsubscribe_request(request_id: RequestId, subscription_id: SubscriptionId) -> JsonRequest {
        let params = Params::Array(vec![Value::String(subscription_id)]);
        JsonRequest {
            id: request_id,
            params,
            method: String::from("eth_unsubscribe"),
            jsonrpc: String::from("2.0"),
        }
    }
}

#[async_trait]
impl Bridge for InfuraWsBridge {
    async fn request(&mut self, request: EthRequest) -> Result<EthData, BridgeError> {
        let id = self.next_id();
        let request = InfuraWsBridge::eth_request(id, request);
        let request = match serde_json::to_string(&request) {
            Ok(req) => req,
            Err(_) => {
                return Err(BridgeError::SerializationError);
            }
        };

        let (tx, rx) = oneshot::channel();
        let cmd = Command::Request {
            id,
            request,
            responder: tx,
        };
        self.send(cmd)?;

        match rx.await {
            Ok(Ok(response)) => match serde_json::from_value(response) {
                Ok(content) => {
                    return Ok(content);
                }
                Err(_) => {
                    return Err(BridgeError::SerializationError);
                }
            },
            Ok(Err(_)) => {
                return Err(BridgeError::TransportError);
            }
            Err(_) => {
                return Err(BridgeError::ChannelError);
            }
        }
    }

    async fn subscribe(
        &mut self,
        subscription: EthSubscription,
    ) -> Result<Subscription<EthData>, BridgeError> {
        let id = self.next_id();
        let request = InfuraWsBridge::subscribe_request(id, subscription);
        let request = match serde_json::to_string(&request) {
            Ok(req) => req,
            Err(_) => {
                return Err(BridgeError::SerializationError);
            }
        };

        let (tx, rx) = oneshot::channel();
        let cmd = Command::Request {
            id,
            request,
            responder: tx,
        };
        self.send(cmd)?;

        let result: String = match rx.await {
            Ok(Ok(response)) => match serde_json::from_value(response) {
                Ok(content) => content,
                Err(_) => {
                    return Err(BridgeError::SerializationError);
                }
            },
            Ok(Err(_)) => {
                return Err(BridgeError::TransportError);
            }
            Err(_) => {
                return Err(BridgeError::ChannelError);
            }
        };

        let (sink, stream) = mpsc::unbounded_channel();
        let subscribe = Command::Subscribe {
            id: result.clone(),
            sink,
        };
        self.send(subscribe)?;

        Ok(Subscription { id: result, stream })
    }

    async fn unsubscribe(&mut self, id: SubscriptionId) -> Result<bool, BridgeError> {
        let request_id = self.next_id();
        // TODO: Only
        let request = InfuraWsBridge::unsubscribe_request(request_id, id.clone());
        let request = match serde_json::to_string(&request) {
            Ok(req) => req,
            Err(_) => {
                return Err(BridgeError::SerializationError);
            }
        };

        let (tx, rx) = oneshot::channel();
        let cmd = Command::Request {
            id: request_id,
            request,
            responder: tx,
        };
        self.send(cmd)?;

        let result: bool = match rx.await {
            Ok(Ok(response)) => match serde_json::from_value(response) {
                Ok(content) => content,
                Err(_) => {
                    return Err(BridgeError::SerializationError);
                }
            },
            Ok(Err(_)) => {
                return Err(BridgeError::TransportError);
            }
            Err(_) => {
                return Err(BridgeError::ChannelError);
            }
        };

        if !result {
            return Err(BridgeError::TransportError);
        }

        let unsubscribe = Command::Unsubscribe { id };
        self.send(unsubscribe)?;

        Ok(true)
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(untagged)]
enum IncomingJsonMessage {
    Notification(JsonNotification),
    Response(JsonResponse),
}

struct InfuraWsBridgeClient {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    commands: UnboundedReceiver<Command>,
    pending_requests: HashMap<RequestId, PendingRequest>,
    subscriptions: HashMap<SubscriptionId, SubscriptionSink<EthData>>,
}

impl InfuraWsBridgeClient {
    fn spawn(mut self) {
        tokio::spawn(async move {
            loop {
                if let Err(_) = self.process().await {
                    panic!("WebSocket client panic");
                }
            }
        });
    }

    /// Processes either a command or a WebSocket message.
    async fn process(&mut self) -> Result<(), BridgeError> {
        tokio::select! {
            Some(cmd) = self.commands.recv() => self.service(cmd).await?,
            message = self.ws.next() => match message {
                Some(Ok(msg)) => self.handle(msg).await?,
                Some(Err(_)) => {
                    return Err(BridgeError::TransportError)
                },
                None => {
                    return Err(BridgeError::ConnectionError);
                }
            }
        }
        Ok(())
    }

    /// Processes a command.
    async fn service(&mut self, cmd: Command) -> Result<(), BridgeError> {
        match cmd {
            Command::Request {
                id,
                request,
                responder,
            } => {
                self.service_request(id, request, responder).await?;
            }
            Command::Subscribe { id, sink } => {
                self.service_subscribe(id, sink).await?;
            }
            Command::Unsubscribe { id } => {
                self.service_unsubscribe(id).await?;
            }
        }
        Ok(())
    }

    async fn service_request(
        &mut self,
        id: RequestId,
        request: String,
        responder: PendingRequest,
    ) -> Result<(), BridgeError> {
        self.pending_requests.insert(id, responder);

        if let Err(_) = self.ws.send(WsMessage::Text(request)).await {
            self.pending_requests.remove(&id);
            return Err(BridgeError::TransportError);
        }
        Ok(())
    }

    async fn service_subscribe(
        &mut self,
        id: SubscriptionId,
        sink: SubscriptionSink<EthData>,
    ) -> Result<(), BridgeError> {
        // TODO: Only call clone if necessary
        if self.subscriptions.insert(id.clone(), sink).is_some() {
            warn!("replacing existing subscription with ID {}", id);
        }
        Ok(())
    }

    async fn service_unsubscribe(&mut self, id: SubscriptionId) -> Result<(), BridgeError> {
        if self.subscriptions.remove(&id).is_none() {
            warn!("unsubscribe from non-existing subscription with ID {}", id);
        }
        Ok(())
    }

    async fn handle(&mut self, message: WsMessage) -> Result<(), BridgeError> {
        match message {
            WsMessage::Text(text) => {
                self.handle_text(text).await?;
            }
            WsMessage::Ping(ping) => {
                self.handle_ping(ping).await?;
            }
            WsMessage::Pong(_) => (),
            WsMessage::Binary(_) => {
                return Err(BridgeError::TransportError);
            }
            WsMessage::Close(_) => {
                return Err(BridgeError::ConnectionError);
            }
        }
        Ok(())
    }

    async fn handle_text(&mut self, text: String) -> Result<(), BridgeError> {
        match serde_json::from_str::<IncomingJsonMessage>(&text) {
            // Handle a request.
            Ok(IncomingJsonMessage::Response(response)) => {
                if let Some(request) = self.pending_requests.remove(&response.id) {
                    if let Err(_) = request.send(response.data.into_result()) {
                        // TODO: Handle error with different enum variant
                        return Err(BridgeError::ChannelError);
                    }
                }
            }
            // Handle a notification.
            Ok(IncomingJsonMessage::Notification(notification)) => {
                let id = notification.params.subscription;
                if let Some(subscription) = self.subscriptions.get(&id) {
                    let data: EthData = match serde_json::from_value(notification.params.result) {
                        Ok(content) => content,
                        Err(_) => {
                            return Err(BridgeError::SerializationError);
                        }
                    };
                    if let Err(_) = subscription.send(data) {
                        return Err(BridgeError::ChannelError);
                    }
                }
            }
            Err(_) => {
                return Err(BridgeError::SerializationError);
            }
        }

        Ok(())
    }

    async fn handle_ping(&mut self, ping: Vec<u8>) -> Result<(), BridgeError> {
        if let Err(_) = self.ws.send(WsMessage::Pong(ping)).await {
            return Err(BridgeError::TransportError);
        }
        Ok(())
    }
}
