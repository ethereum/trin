use async_trait::async_trait;
use ethers_core::types::{
    Address, Block, Bytes, EIP1186ProofResponse, Transaction, TransactionReceipt, TxHash, H256,
    U256, U64,
};

#[cfg(unix)]
use ethers_providers::Ipc;
use ethers_providers::{
    JsonRpcClient, Middleware, Provider, ProviderError, PubsubClient, SubscriptionStream, Ws,
};

use log::error;
use url::Url;

use std::error::Error;
use std::fmt;

#[cfg(unix)]
use std::path::Path;

// TODO: Add more comprehensive errors with more concrete types.
/// An error that can occur in communications with a bridge node.
#[derive(Debug)]
pub enum BridgeError {
    EthClientError(Box<dyn std::error::Error + Send + Sync>),
    SerializationError(Box<dyn std::error::Error + Send + Sync>),
    ConnectionFailure,
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EthClientError(error) => write!(f, "bridge ETH client error: {}", error),
            Self::SerializationError(error) => write!(f, "bridge serialization error: {}", error),
            Self::ConnectionFailure => write!(f, "bridge connection failure"),
            Self::Other(error) => write!(f, "bridge error: {}", error),
        }
    }
}

// TODO: Implement source.
impl Error for BridgeError {}

impl From<serde_json::Error> for BridgeError {
    fn from(error: serde_json::Error) -> Self {
        BridgeError::SerializationError(error.into())
    }
}

impl From<ProviderError> for BridgeError {
    fn from(error: ProviderError) -> Self {
        match error {
            ProviderError::JsonRpcClientError(error) => BridgeError::EthClientError(error),
            ProviderError::SerdeJson(error) => BridgeError::SerializationError(error.into()),
            ProviderError::HexError(error) => BridgeError::SerializationError(error.into()),
            error => BridgeError::Other(error.into()),
        }
    }
}

/// A type alias for a `Result` whose `Err` variant holds a `BridgeError`.
type Result<T> = std::result::Result<T, BridgeError>;

/// An Ethereum bridge client.
#[async_trait]
pub trait EthBridge {
    type Client: PubsubClient;

    /// Requests the balance of an account at a particular block number.
    async fn get_balance(&self, address: Address, block_number: U64) -> Result<U256>;
    /// Requests a block (with full transaction objects) by hash.
    async fn get_block(&self, hash: H256) -> Result<Option<Block<Transaction>>>;
    /// Requests the code of an account at a particular block number.
    async fn get_code(&self, address: Address, block_number: U64) -> Result<Bytes>;
    /// Requests the value of a storage slot at a particular block number.
    async fn get_storage(
        &self,
        address: Address,
        location: H256,
        block_number: U64,
    ) -> Result<H256>;
    // TODO: Replace parameters with block hash and transaction index.
    /// Requests the transaction for a given transaction hash.
    async fn get_transaction(&self, hash: H256) -> Result<Option<Transaction>>;
    /// Requests the number of transactions sent (nonce) from an account at a particular block number.
    async fn get_transaction_count(&self, address: Address, block_number: U64) -> Result<U256>;
    /// Requests the transaction receipt for a given transaction hash.
    async fn get_transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>>;
    /// Subscribes to a stream of new block headers as new blocks are appended to the chain.
    /// In the case of chain reorganizations, all new block headers will be sent.
    async fn subscribe_new_block_headers(
        &self,
    ) -> Result<SubscriptionStream<'_, Self::Client, Block<TxHash>>>;
}

/// A Go-Ethereum (Geth) bridge client. Geth clients support a superset of the standard Ethereum
/// JSON-RPC APIs.
#[async_trait]
pub trait GethBridge: EthBridge {
    type Client: PubsubClient;

    /// Requests the EIP-1186 proof for an account.
    /// EIP: https://github.com/ethereum/EIPs/issues/1186.
    async fn get_proof(
        &self,
        address: Address,
        storage_locations: &[H256],
        block_number: U64,
    ) -> Result<EIP1186ProofResponse>;
}

/// An ethers-rs Ethereum bridge client.
pub struct EthersBridge<T: JsonRpcClient> {
    provider: Provider<T>,
}

/// An ethers-rs Ethereum bridge client with WebSocket transport.
impl EthersBridge<Ws> {
    /// Attempts to establish a WebSocket connection with an Ethereum JSON-RPC server.
    pub async fn connect(url: Url) -> Result<Self> {
        match Ws::connect(url).await {
            Ok(ws) => Ok(Self {
                provider: Provider::<Ws>::new(ws),
            }),
            Err(error) => {
                error!("failure to connect to WebSocket server: {:?}", error);
                Err(BridgeError::ConnectionFailure)
            }
        }
    }
}

/// An ethers-rs Ethereum bridge client with IPC transport.
#[cfg(unix)]
impl EthersBridge<Ipc> {
    /// Attempts to establish an IPC connection with an Ethereum JSON-RPC server.
    pub async fn connect<P: AsRef<Path>>(path: P) -> Result<Self> {
        match Ipc::connect(path).await {
            Ok(ipc) => Ok(Self {
                provider: Provider::<Ipc>::new(ipc),
            }),
            Err(error) => {
                error!("failure to connect to IPC: {:?}", error);
                Err(BridgeError::ConnectionFailure)
            }
        }
    }
}

#[async_trait]
impl<T: PubsubClient> EthBridge for EthersBridge<T> {
    type Client = T;

    async fn get_balance(&self, address: Address, block_number: U64) -> Result<U256> {
        let balance = self
            .provider
            .get_balance(address, Some(block_number.into()))
            .await?;
        Ok(balance)
    }

    async fn get_block(&self, hash: H256) -> Result<Option<Block<Transaction>>> {
        let block = self.provider.get_block_with_txs(hash).await?;
        Ok(block)
    }

    async fn get_code(&self, address: Address, block_number: U64) -> Result<Bytes> {
        let code = self
            .provider
            .get_code(address, Some(block_number.into()))
            .await?;
        Ok(code)
    }

    async fn get_storage(
        &self,
        address: Address,
        location: H256,
        block_number: U64,
    ) -> Result<H256> {
        let storage = self
            .provider
            .get_storage_at(address, location, Some(block_number.into()))
            .await?;
        Ok(storage)
    }

    async fn get_transaction(&self, hash: H256) -> Result<Option<Transaction>> {
        let transaction = self.provider.get_transaction(hash).await?;
        Ok(transaction)
    }

    async fn get_transaction_count(&self, address: Address, block_number: U64) -> Result<U256> {
        let nonce = self
            .provider
            .get_transaction_count(address, Some(block_number.into()))
            .await?;
        Ok(nonce)
    }

    async fn get_transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>> {
        let receipt = self.provider.get_transaction_receipt(hash).await?;
        Ok(receipt)
    }

    async fn subscribe_new_block_headers(
        &self,
    ) -> Result<SubscriptionStream<'_, T, Block<TxHash>>> {
        let stream = self.provider.subscribe_blocks().await?;
        Ok(stream)
    }
}

#[async_trait]
impl<T: PubsubClient> GethBridge for EthersBridge<T> {
    type Client = T;

    async fn get_proof(
        &self,
        address: Address,
        storage_locations: &[H256],
        block_number: U64,
    ) -> Result<EIP1186ProofResponse> {
        let proof = self
            .provider
            .get_proof(
                address,
                storage_locations.to_vec(),
                Some(block_number.into()),
            )
            .await?;
        Ok(proof)
    }
}
