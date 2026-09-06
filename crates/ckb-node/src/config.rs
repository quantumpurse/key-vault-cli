use crate::error::NodeManagerError;
use ckb_types::{h256, H256};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

/// Public RPC endpoints provided by the Nervos Foundation.
const PUBLIC_RPC_MAINNET: &str = "https://mainnet.ckb.dev";
const PUBLIC_RPC_TESTNET: &str = "https://testnet.ckb.dev";

/// Default local RPC ports.
const LOCAL_RPC_FULL_NODE: &str = "http://127.0.0.1:8114";
const LOCAL_RPC_LIGHT_CLIENT: &str = "http://127.0.0.1:9000";

/// Genesis block hashes: fixed, public, and the one thing that tells one
/// chain from another. Values come from `ckb list-hashes -b`.
const GENESIS_HASH_MAINNET: H256 =
    h256!("0x92b197aa1fba0f63633922c61c92375c9c074a93e85963554f5499fe1450d0e5");
const GENESIS_HASH_TESTNET: H256 =
    h256!("0x10639e0895502b5688a6be8cf69460d76541bfa4821629d86d62ba0aae3f9606");

/// The type of CKB node backend to connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeType {
    /// Connect to a public RPC endpoint. No local binary needed.
    PublicRpc,
    /// Run a local CKB light client process.
    LightClient,
    /// Run a local CKB full node process.
    FullNode,
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::PublicRpc => write!(f, "PublicRpc"),
            NodeType::LightClient => write!(f, "LightClient"),
            NodeType::FullNode => write!(f, "FullNode"),
        }
    }
}

/// The CKB network to connect to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkType {
    Mainnet,
    Testnet,
}

impl NetworkType {
    /// Lowercase short identifier, suitable for file names and directory
    /// segments (e.g. `tx_history_mainnet.json`, `light-client/testnet/`).
    /// Distinct from `Display` which produces the capitalized form used in
    /// user-facing UI.
    pub fn tag(&self) -> &'static str {
        match self {
            NetworkType::Mainnet => "mainnet",
            NetworkType::Testnet => "testnet",
        }
    }

    /// The network whose genesis block has this hash. `None` for a chain
    /// the wallet does not know, such as a dev or preview net.
    fn from_genesis_hash(hash: &H256) -> Option<NetworkType> {
        if *hash == GENESIS_HASH_MAINNET {
            Some(NetworkType::Mainnet)
        } else if *hash == GENESIS_HASH_TESTNET {
            Some(NetworkType::Testnet)
        } else {
            None
        }
    }

    /// Checks that a node reporting `genesis` is on this network. A node
    /// answering at the configured port proves nothing about the chain
    /// behind it, so every backend passes this before it is trusted.
    pub(crate) fn verify_genesis(&self, genesis: &H256) -> Result<(), NodeManagerError> {
        match NetworkType::from_genesis_hash(genesis) {
            Some(detected) if detected == *self => Ok(()),
            Some(detected) => Err(NodeManagerError::NetworkMismatch {
                expected: *self,
                detected: detected.to_string(),
            }),
            None => Err(NodeManagerError::NetworkMismatch {
                expected: *self,
                detected: format!("an unknown chain (genesis {:#x})", genesis),
            }),
        }
    }
}

impl fmt::Display for NetworkType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkType::Mainnet => write!(f, "Mainnet"),
            NetworkType::Testnet => write!(f, "Testnet"),
        }
    }
}

/// Configuration for the node manager.
///
/// All fields are configurable. The wallet persists this to disk so user
/// preferences survive restarts.
/// TODO: currently shared between QpCliet and LocalNodeProcess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Which backend to use. Defaults to `PublicRpc`.
    pub node_type: NodeType,

    /// Which CKB network to connect to. Defaults to `Testnet`.
    pub network: NetworkType,

    /// Path to the node binary on disk. `None` when using `PublicRpc`.
    pub binary_path: Option<PathBuf>,

    /// Directory where the node stores its chain data.
    /// Each node type gets a subdirectory (`light-client/` or `full-node/`).
    pub data_dir: PathBuf,

    /// The JSON-RPC URL to connect to.
    pub rpc_url: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_type: NodeType::PublicRpc,
            network: NetworkType::Testnet,
            binary_path: None,
            data_dir: default_data_dir(),
            rpc_url: PUBLIC_RPC_TESTNET.to_string(),
        }
    }
}

impl NodeConfig {
    /// Returns the default RPC URL for the current node type and network.
    pub fn default_rpc_url(&self) -> &'static str {
        Self::default_rpc_url_for(self.node_type, self.network)
    }

    /// Associated form of `default_rpc_url` — returns the canonical URL for
    /// any `(NodeType, NetworkType)` pair without needing a `NodeConfig`
    /// instance. Lets callers probe non-active backends (e.g. the Node
    /// Manager page showing Public RPC status while Light Client is the
    /// active backend).
    pub fn default_rpc_url_for(node_type: NodeType, network: NetworkType) -> &'static str {
        match node_type {
            NodeType::PublicRpc => match network {
                NetworkType::Mainnet => PUBLIC_RPC_MAINNET,
                NetworkType::Testnet => PUBLIC_RPC_TESTNET,
            },
            NodeType::LightClient => LOCAL_RPC_LIGHT_CLIENT,
            NodeType::FullNode => LOCAL_RPC_FULL_NODE,
        }
    }

    /// Whether this configuration requires a local node binary.
    pub fn requires_binary(&self) -> bool {
        matches!(self.node_type, NodeType::LightClient | NodeType::FullNode)
    }

    /// Returns the data subdirectory for the active node type + network.
    ///
    /// Mainnet and testnet are independent ledgers — sharing a store between
    /// them would corrupt node state, so local backends get a
    /// `<type>/<network>/` layout (e.g. `light-client/testnet/`). `PublicRpc`
    /// has no local state and uses the bare data dir.
    pub fn node_data_dir(&self) -> PathBuf {
        let net = self.network.tag();
        match self.node_type {
            NodeType::PublicRpc => self.data_dir.clone(),
            NodeType::LightClient => self.data_dir.join("light-client").join(net),
            NodeType::FullNode => self.data_dir.join("full-node").join(net),
        }
    }

    /// Loads configuration from the standard config file path.
    /// Returns `Ok(None)` if the file does not exist.
    pub fn load() -> Result<Option<Self>, NodeManagerError> {
        let path = config_file_path()?;

        if !path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let config: NodeConfig =
            serde_json::from_str(&contents).map_err(NodeManagerError::SerializationError)?;
        Ok(Some(config))
    }

    /// Loads configuration from disk, or returns defaults if no config file exists.
    pub fn load_or_default() -> Result<Self, NodeManagerError> {
        Ok(Self::load()?.unwrap_or_default())
    }

    /// Persists this configuration to disk.
    pub fn save(&self) -> Result<(), NodeManagerError> {
        let path = config_file_path()?;

        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let json =
            serde_json::to_string_pretty(self).map_err(NodeManagerError::SerializationError)?;
        let mut file = File::create(&path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}

/// Platform-standard application data directory for node data.
/// - macOS: `~/Library/Application Support/quantum-purse/node/`
/// - Linux: `~/.local/share/quantum-purse/node/`
/// - Windows: `C:\Users\<User>\AppData\Local\quantum-purse\node\`
fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("quantum-purse")
        .join("node")
}

/// Path to the node manager config file.
/// Stored alongside the node data: `<data_dir>/node_config.json`.
fn config_file_path() -> Result<PathBuf, NodeManagerError> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        NodeManagerError::ConfigError("Cannot determine platform data directory.".to_string())
    })?;
    Ok(data_dir
        .join("quantum-purse")
        .join("node")
        .join("node_config.json"))
}

#[cfg(test)]
mod tests {
    use super::{NetworkType, GENESIS_HASH_MAINNET, GENESIS_HASH_TESTNET};
    use ckb_types::H256;

    #[test]
    fn genesis_hashes_map_to_their_network() {
        assert_eq!(
            NetworkType::from_genesis_hash(&GENESIS_HASH_MAINNET),
            Some(NetworkType::Mainnet)
        );
        assert_eq!(
            NetworkType::from_genesis_hash(&GENESIS_HASH_TESTNET),
            Some(NetworkType::Testnet)
        );
    }

    #[test]
    fn unknown_genesis_maps_to_none() {
        assert_eq!(NetworkType::from_genesis_hash(&H256::default()), None);
    }

    #[test]
    fn verify_genesis_accepts_own_chain() {
        assert!(NetworkType::Mainnet
            .verify_genesis(&GENESIS_HASH_MAINNET)
            .is_ok());
        assert!(NetworkType::Testnet
            .verify_genesis(&GENESIS_HASH_TESTNET)
            .is_ok());
    }

    #[test]
    fn verify_genesis_names_both_networks_on_mismatch() {
        let err = NetworkType::Testnet
            .verify_genesis(&GENESIS_HASH_MAINNET)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "The node is on Mainnet, but the wallet is set to Testnet."
        );
    }

    #[test]
    fn verify_genesis_reports_unknown_chain() {
        let err = NetworkType::Mainnet
            .verify_genesis(&H256::default())
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("The node is on an unknown chain"),
            "{}",
            err
        );
    }
}
