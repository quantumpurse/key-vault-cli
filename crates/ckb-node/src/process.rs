use crate::config::{NetworkType, NodeConfig, NodeType};
use crate::error::NodeManagerError;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long to wait for the node to exit gracefully before sending SIGKILL.
const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Upstream light-client configs embedded at compile time. On first run
/// (or when the user deletes the file) one of these is written to
/// `<data_dir>/config.toml` with the relative `[store]` / `[network]`
/// paths rewritten to absolute paths inside the per-network directory.
const TESTNET_TEMPLATE: &str = include_str!("../../../vendor/ckb-light-client/config/testnet.toml");
const MAINNET_TEMPLATE: &str = include_str!("../../../vendor/ckb-light-client/config/mainnet.toml");

// ── Trait ────────────────────────────────────────────────────────────────

/// Lifecycle of a local CKB node process. Shared shape across the
/// supported backends. Construction is per-impl via `start(&NodeConfig)`;
/// the post-construction surface is what `dyn NodeProcess` exposes.
pub trait NodeProcess: Send {
    /// Spawn the binary and materialize any required on-disk config.
    /// Returns as soon as `Command::spawn` hands back the child handle —
    /// this is fire-and-forget; RPC readiness is *not* awaited. Each
    /// impl picks its own binary-discovery + config-prep strategy.
    ///
    /// The caller is responsible for discovering when the node is
    /// actually serving RPC (the GUI does this via `fetch_node_status`
    /// polling the `online` flag) and for surfacing early-exit failures
    /// (via the poller's `is_running` watchdog).
    ///
    /// `where Self: Sized` keeps the trait object-safe — `start` is part
    /// of the contract every impl must satisfy, but cannot be dispatched
    /// through `dyn NodeProcess`.
    fn start(config: &NodeConfig) -> Result<Self, NodeManagerError>
    where
        Self: Sized;

    /// Graceful stop (SIGTERM + grace + SIGKILL on Unix; immediate kill
    /// elsewhere). Called best-effort by `Drop`.
    fn stop(&mut self) -> Result<(), NodeManagerError>;

    /// `true` if the child hasn't exited yet. Not a strict liveness
    /// check — the RPC is the authoritative signal.
    fn is_running(&mut self) -> bool;

    /// `NodeType` this process was started for.
    fn node_type(&self) -> NodeType;
}

// ── LightClientProcess ───────────────────────────────────────────────────

/// Local `ckb-light-client` child process. Owns the binary discovery and
/// `config.toml` materialization that previously lived in a separate
/// `light_client_spawn` module.
pub struct LightClientProcess {
    child: Child,
}

impl NodeProcess for LightClientProcess {
    fn start(config: &NodeConfig) -> Result<Self, NodeManagerError> {
        if config.node_type != NodeType::LightClient {
            return Err(NodeManagerError::UnsupportedOperation {
                node_type: config.node_type.to_string(),
                reason: "LightClientProcess::start called with non-LightClient config.".to_string(),
            });
        }

        let data_dir = config.node_data_dir();
        std::fs::create_dir_all(&data_dir)?;

        ensure_light_client_config_file(config, &data_dir)?;

        let binary = locate_light_client_binary(config)?;
        let config_path = data_dir.join("config.toml");
        let log_path = data_dir.join("node.log");

        let mut command = Command::new(&binary);
        command.arg("run").arg("--config-file").arg(&config_path);

        let child = execute(command, &log_path)?;

        Ok(Self { child })
    }

    fn stop(&mut self) -> Result<(), NodeManagerError> {
        stop_child(&mut self.child)
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn node_type(&self) -> NodeType {
        NodeType::LightClient
    }
}

impl Drop for LightClientProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// ── FullNodeProcess ──────────────────────────────────────────────────────

/// Local `ckb` (full-node) child process. Owns binary discovery and
/// the chain-dir bootstrap (`ckb init`) needed before the first run on
/// each network.
pub struct FullNodeProcess {
    child: Child,
}

impl NodeProcess for FullNodeProcess {
    fn start(config: &NodeConfig) -> Result<Self, NodeManagerError> {
        if config.node_type != NodeType::FullNode {
            return Err(NodeManagerError::UnsupportedOperation {
                node_type: config.node_type.to_string(),
                reason: "FullNodeProcess::start called with non-FullNode config.".to_string(),
            });
        }

        let data_dir = config.node_data_dir();
        std::fs::create_dir_all(&data_dir)?;

        let binary = locate_full_node_binary(config)?;

        // Bootstrap the chain dir on first spawn for this network.
        // `ckb init` creates `ckb.toml`, `ckb-miner.toml`, `specs/`, etc.
        // Idempotent: skip if `ckb.toml` is already there.
        ensure_full_node_chain_dir(&binary, config.network, &data_dir)?;

        let log_path = data_dir.join("node.log");

        let mut command = Command::new(&binary);
        command.arg("run").arg("-C").arg(&data_dir);

        let child = execute(command, &log_path)?;

        Ok(Self { child })
    }

    fn stop(&mut self) -> Result<(), NodeManagerError> {
        stop_child(&mut self.child)
    }

    fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    fn node_type(&self) -> NodeType {
        NodeType::FullNode
    }
}

impl Drop for FullNodeProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

// ── Shared lifecycle helpers ─────────────────────────────────────────────

/// Spawns a pre-built `Command`, redirecting stdout+stderr to a log file
/// at `log_path` so signed `.app` bundle runs (where inherited stderr
/// vanishes) still leave a paper trail. Truncates the log on each call.
/// Per-backend `start()` implementations build their own `Command`
/// (binary path + args) and pass it here.
fn execute(mut command: Command, log_path: &Path) -> Result<Child, NodeManagerError> {
    let log_file = File::create(log_path).map_err(|e| {
        NodeManagerError::ProcessError(format!(
            "Failed to create node log at '{}': {}",
            log_path.display(),
            e
        ))
    })?;
    let log_file_err = log_file.try_clone().map_err(|e| {
        NodeManagerError::ProcessError(format!("Failed to clone log handle: {}", e))
    })?;

    // Allow Windows to start the child ckb processes with no console - or
    // "a console application that is being run without a console window"
    // https://learn.microsoft.com/windows/win32/procthread/process-creation-flags
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    command
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err))
        .spawn()
        .map_err(|e| NodeManagerError::ProcessError(format!("Failed to spawn node binary: {}", e)))
}

/// SIGTERM + grace period + SIGKILL on Unix; immediate kill elsewhere.
/// Idempotent: stopping an already-exited child returns Ok immediately.
fn stop_child(child: &mut Child) -> Result<(), NodeManagerError> {
    send_terminate_signal(child);

    let deadline = Instant::now() + SHUTDOWN_GRACE_PERIOD;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(NodeManagerError::ProcessError(format!(
                    "Error waiting for node to exit: {e}"
                )));
            }
        }
    }

    child
        .kill()
        .map_err(|e| NodeManagerError::ProcessError(format!("Failed to kill node process: {e}")))?;
    child.wait().map_err(|e| {
        NodeManagerError::ProcessError(format!("Error waiting for node process after kill: {e}"))
    })?;

    Ok(())
}

/// Sends SIGTERM on Unix; on other platforms is a no-op (caller falls
/// back to `kill()` after the grace period).
fn send_terminate_signal(child: &Child) {
    #[cfg(unix)]
    {
        let pid = child.id();
        // SAFETY: We own the child process and SIGTERM is a standard signal.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child;
    }
}

// ── Light-client config helpers ──────────────────────────────────────────

/// Resolves the path to the `ckb-light-client` executable.
///
/// Order of precedence:
/// 1. `config.binary_path` — explicit user override via Settings.
/// 2. Bundled sibling to the currently-running executable (macOS
///    `qpv2.app/Contents/MacOS/ckb-light-client`).
/// 3. Dev fallback — walk up from the current exe to find
///    `vendor/ckb-light-client/target/{release,debug}/ckb-light-client`.
fn locate_light_client_binary(config: &NodeConfig) -> Result<PathBuf, NodeManagerError> {
    let bin_name = if cfg!(windows) {
        "ckb-light-client.exe"
    } else {
        "ckb-light-client"
    };

    if let Some(path) = &config.binary_path {
        if path.exists() {
            return Ok(path.clone());
        }
        return Err(NodeManagerError::BinaryNotFound {
            path: path.display().to_string(),
            reason: "File does not exist.".to_string(),
        });
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join(bin_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors() {
            for profile in ["release", "debug"] {
                let candidate = ancestor
                    .join("vendor")
                    .join("ckb-light-client")
                    .join("target")
                    .join(profile)
                    .join(bin_name);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    Err(NodeManagerError::BinaryNotFound {
        path: "<auto-discovery>".to_string(),
        reason: "ckb-light-client binary not found. Build the submodule \
                 first: `(cd vendor/ckb-light-client && cargo build --release)`, \
                 or set the binary path under Settings."
            .to_string(),
    })
}

/// Ensures `<data_dir>/config.toml` exists, writing the embedded template
/// (with rewritten absolute store/network paths) if it's missing.
/// Idempotent — leaves an existing file untouched so users can hand-edit.
fn ensure_light_client_config_file(
    config: &NodeConfig,
    data_dir: &Path,
) -> Result<(), NodeManagerError> {
    let config_path = data_dir.join("config.toml");
    if config_path.exists() {
        return Ok(());
    }

    let template = match config.network {
        NetworkType::Mainnet => MAINNET_TEMPLATE,
        NetworkType::Testnet => TESTNET_TEMPLATE,
    };
    let rewritten = rewrite_light_client_template_paths(template, data_dir);

    std::fs::write(&config_path, rewritten)?;
    Ok(())
}

/// Rewrites the two relative paths in the upstream template
/// (`[store] path = "data/store"` and `[network] path = "data/network"`)
/// to absolute paths inside `data_dir`. Keeps the rest of the TOML
/// verbatim so the extensive bootnode list and comments aren't disturbed
/// — avoids pulling in a full TOML writer just for two lines.
fn rewrite_light_client_template_paths(template: &str, data_dir: &Path) -> String {
    let store_abs = data_dir.join("data").join("store");
    let network_abs = data_dir.join("data").join("network");

    let mut out = String::with_capacity(template.len() + 256);
    let mut section: Option<&str> = None;
    for line in template.lines() {
        let trimmed = line.trim_start();
        if let Some(header) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = Some(header.trim());
            out.push_str(line);
            out.push('\n');
            continue;
        }

        if trimmed.starts_with("path") && trimmed.contains('=') {
            match section {
                Some("store") => {
                    out.push_str(&format!("path = {:?}\n", store_abs.display().to_string()));
                    continue;
                }
                Some("network") => {
                    out.push_str(&format!("path = {:?}\n", network_abs.display().to_string()));
                    continue;
                }
                _ => {}
            }
        }

        out.push_str(line);
        out.push('\n');
    }
    out
}

// ── Full-node helpers ────────────────────────────────────────────────────

/// Resolves the path to the `ckb` executable.
///
/// Order of precedence (mirrors `locate_light_client_binary`):
/// 1. `config.binary_path` — explicit user override via Settings.
/// 2. Bundled sibling to the currently-running executable (macOS
///    `qpv2.app/Contents/MacOS/ckb`).
/// 3. Dev fallback — walk up from the current exe to find
///    `vendor/ckb/target/{release,debug}/ckb`.
fn locate_full_node_binary(config: &NodeConfig) -> Result<PathBuf, NodeManagerError> {
    let bin_name = if cfg!(windows) { "ckb.exe" } else { "ckb" };

    if let Some(path) = &config.binary_path {
        if path.exists() {
            return Ok(path.clone());
        }
        return Err(NodeManagerError::BinaryNotFound {
            path: path.display().to_string(),
            reason: "File does not exist.".to_string(),
        });
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join(bin_name);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        for ancestor in exe.ancestors() {
            for profile in ["release", "debug"] {
                let candidate = ancestor
                    .join("vendor")
                    .join("ckb")
                    .join("target")
                    .join(profile)
                    .join(bin_name);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    Err(NodeManagerError::BinaryNotFound {
        path: "<auto-discovery>".to_string(),
        reason: "ckb binary not found. Build the submodule first: \
                 `(cd vendor/ckb && cargo build -p ckb-bin --release)`, \
                 or set the binary path under Settings."
            .to_string(),
    })
}

/// Ensures the full-node chain dir at `data_dir` is initialized. Runs
/// `ckb init --chain <network> -C <data_dir>` when `<data_dir>/ckb.toml`
/// is missing; idempotent otherwise. `ckb init` writes `ckb.toml`,
/// `ckb-miner.toml`, and `specs/` for the chosen chain.
fn ensure_full_node_chain_dir(
    binary: &Path,
    network: NetworkType,
    data_dir: &Path,
) -> Result<(), NodeManagerError> {
    let toml_path = data_dir.join("ckb.toml");

    // Only run `ckb init` when the chain dir hasn't been scaffolded yet.
    if !toml_path.exists() {
        let mut command = Command::new(binary);
        command
            .arg("init")
            .arg("--chain")
            .arg(network.tag())
            .arg("-C")
            .arg(data_dir);
        // No console window for a console child.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let status = command.status().map_err(|e| {
            NodeManagerError::ProcessError(format!(
                "Failed to run `ckb init --chain {} -C {}`: {}",
                network.tag(),
                data_dir.display(),
                e
            ))
        })?;

        if !status.success() {
            return Err(NodeManagerError::ProcessError(format!(
                "`ckb init --chain {} -C {}` exited with status {}.",
                network.tag(),
                data_dir.display(),
                status
            )));
        }
    }

    // Run on every spawn (not gated on the init branch above) so existing
    // chain dirs scaffolded before this fix also get patched. The function
    // is idempotent — only writes when "Indexer" is missing from the
    // `rpc.modules` array.
    enable_indexer_rpc_module(&toml_path)?;

    Ok(())
}

/// Adds `"Indexer"` to the `rpc.modules` array in a `ckb.toml`, in
/// place. Idempotent: no-op (no disk write) when `"Indexer"` is already
/// listed. Required because `ckb init`'s default `rpc.modules` omits
/// `"Indexer"`, which makes the wallet's reads (`get_cells_capacity`,
/// `get_cells`, `get_transactions`) hit `Method not found`.
///
/// Line-based edit instead of pulling in a TOML round-tripper — the
/// upstream template declares `modules` on a single line and we don't
/// want to disturb its surrounding comments / formatting.
fn enable_indexer_rpc_module(toml_path: &Path) -> Result<(), NodeManagerError> {
    let content = std::fs::read_to_string(toml_path).map_err(|e| {
        NodeManagerError::ProcessError(format!("Failed to read '{}': {}", toml_path.display(), e))
    })?;

    let mut changed = false;
    let new_content: String = content
        .lines()
        .map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("modules") && trimmed.contains('=') && line.contains('[') {
                if line.contains("\"Indexer\"") {
                    return line.to_string();
                }
                if let Some(idx) = line.rfind(']') {
                    changed = true;
                    let mut out = String::with_capacity(line.len() + 12);
                    out.push_str(&line[..idx]);
                    out.push_str(", \"Indexer\"]");
                    out.push_str(&line[idx + 1..]);
                    return out;
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");

    if changed {
        // `lines()` strips the trailing newline; restore if present.
        let final_content = if content.ends_with('\n') {
            format!("{}\n", new_content)
        } else {
            new_content
        };
        std::fs::write(toml_path, final_content).map_err(|e| {
            NodeManagerError::ProcessError(format!(
                "Failed to write '{}': {}",
                toml_path.display(),
                e
            ))
        })?;
    }
    Ok(())
}
