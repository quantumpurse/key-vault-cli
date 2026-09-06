use crate::config::NetworkType;
use std::io;

/// Errors that can occur during node management operations.
#[derive(Debug, thiserror::Error)]
pub enum NodeManagerError {
    /// Node binary was not found at the configured path.
    #[error("Node binary not found at {path}: {reason}")]
    BinaryNotFound { path: String, reason: String },

    /// Failed to read or write node manager configuration.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// The node process encountered an error during start, stop, or health check.
    #[error("Process error: {0}")]
    ProcessError(String),

    /// An RPC call to the node failed.
    #[error("RPC error: {0}")]
    RpcError(String),

    /// Operation requires a running node but none is active.
    #[error("No node is currently running")]
    NotRunning,

    /// The node at the endpoint serves a different chain than the
    /// wallet is configured for.
    #[error("The node is on {detected}, but the wallet is set to {expected}.")]
    NetworkMismatch {
        expected: NetworkType,
        detected: String,
    },

    /// Operation is not applicable to the current node type (e.g. starting a process for PublicRpc).
    #[error("Operation not supported for node type '{node_type}': {reason}")]
    UnsupportedOperation { node_type: String, reason: String },

    /// I/O error wrapper.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}
