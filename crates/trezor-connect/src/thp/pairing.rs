//! THP pairing phase: CodeEntry (CPace) plus credential persistence.
//!
//! Production Safe firmware does not advertise skip-pairing, so the first
//! connection to a physical device runs CodeEntry: the device displays a
//! 6-digit code, the user types it into the host, and both sides prove
//! knowledge of it via CPace without ever sending it. After a successful
//! pairing the host requests a credential bound to its static X25519 key and
//! stores it next to the wallet data; later handshakes present it and skip
//! the pairing phase (the device reports `Paired`, then shows a "Connect?"
//! confirmation — the credential is not the autoconnect kind, which the
//! firmware only issues in a later session). This mirrors trezorlib's
//! `thp/pairing.py` + `thp/credentials.py`.

use std::io::Write as _;
use std::path::PathBuf;

use protobuf::Message as _;
use sha2::{Digest, Sha256};
use trezor_thp::channel::host::Channel;
use trezor_thp::credential::{CredentialStore, FoundCredential};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

use crate::thp::client::Client;
use crate::thp::cpace;
use crate::thp::RustCrypto;
use crate::TrezorSignerError;
use trezor_client::protos::{
    ThpCodeEntryChallenge, ThpCodeEntryCommitment, ThpCodeEntryCpaceHostTag,
    ThpCodeEntryCpaceTrezor, ThpCodeEntrySecret, ThpCredentialRequest, ThpCredentialResponse,
    ThpDeviceProperties, ThpEndRequest, ThpEndResponse, ThpHandshakeCompletionReqNoisePayload,
    ThpMessageType, ThpPairingMethod, ThpPairingRequest, ThpPairingRequestApproved,
    ThpSelectMethod,
};

/// The device rejects credentials wrapped in a handshake payload larger than
/// this (`trezor_thp::channel::MAX_CREDENTIAL_LEN`).
const MAX_WRAPPED_CREDENTIAL_LEN: usize = trezor_thp::channel::MAX_CREDENTIAL_LEN;

/// Host-side interaction needed while pairing with a device.
pub trait PairingUx: Send {
    /// The device is displaying a 6-digit pairing code; return what the user
    /// typed.
    fn code_entry(&mut self) -> Result<String, TrezorSignerError>;
}

/// Prompts for the pairing code on the controlling terminal (CLI).
pub struct StdinPairing;

impl PairingUx for StdinPairing {
    fn code_entry(&mut self) -> Result<String, TrezorSignerError> {
        eprint!("Enter the 6-digit pairing code shown on your Trezor: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| TrezorSignerError::Client(format!("could not read pairing code: {e}")))?;
        Ok(line.trim().to_string())
    }
}

/// Prompts for the pairing code via the OS-native pinentry dialog (GUI).
pub struct PinentryPairing;

impl PairingUx for PinentryPairing {
    fn code_entry(&mut self) -> Result<String, TrezorSignerError> {
        let code = qpv2_core::pinentry::prompt_password(
            "Pair with your Trezor:\nenter the 6-digit code shown on the device.",
            "Code",
        )
        .map_err(TrezorSignerError::Client)?;
        Ok(code.trim().to_string())
    }
}

/// Fails if the device asks for a pairing code. Used where no interactive
/// prompt is possible (tests, background probes).
pub struct NoInteraction;

impl PairingUx for NoInteraction {
    fn code_entry(&mut self) -> Result<String, TrezorSignerError> {
        Err(TrezorSignerError::Client(
            "this Trezor requires code-entry pairing, which needs an interactive prompt".into(),
        ))
    }
}

/// On-disk shape of `trezor-credentials.json`.
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct CredentialFile {
    /// Hex, 32 bytes: the X25519 static private key identifying this host.
    host_privkey: String,
    /// One entry per paired device.
    #[serde(default)]
    credentials: Vec<CredentialEntry>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CredentialEntry {
    /// Hex: the device's static public key (its identity).
    trezor_pubkey: String,
    /// Hex: the raw pairing credential the device issued.
    credential: String,
}

/// This host's persistent THP identity: a static X25519 key plus the pairing
/// credentials devices have issued to it. Not a wallet secret — it only
/// authorizes connecting; every signature still requires device confirmation.
pub(crate) struct HostIdentity {
    host_privkey: [u8; 32],
    /// `(trezor_pubkey, raw credential)` per paired device.
    entries: Vec<([u8; 32], Vec<u8>)>,
    /// `None` when the data dir is unavailable — identity is then ephemeral.
    path: Option<PathBuf>,
}

impl HostIdentity {
    /// Load the stored identity, creating a fresh one (new random host key)
    /// if none exists. Falls back to an in-memory identity if the data dir
    /// cannot be used — pairing then just won't persist.
    pub(crate) fn load_or_create() -> Self {
        let path = match qpv2_core::db::get_data_dir() {
            Ok(dir) => Some(dir.join("trezor-credentials.json")),
            Err(e) => {
                log::warn!("Trezor credential store unavailable ({e}); pairing will not persist");
                None
            }
        };

        if let Some(p) = path.as_ref() {
            if let Some(loaded) = Self::load(p) {
                return loaded;
            }
        }

        // overwrite
        let mut host_privkey = [0u8; 32];
        getrandom::fill(&mut host_privkey).expect("getrandom failed");
        let identity = HostIdentity {
            host_privkey,
            entries: Vec::new(),
            path,
        };
        identity.save();
        identity
    }

    fn load(path: &PathBuf) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        let file: CredentialFile = serde_json::from_slice(&data)
            .map_err(|e| log::warn!("ignoring malformed {}: {e}", path.display()))
            .ok()?;
        // A malformed host key means a fresh identity and re-pairing — that
        // recovery is by design (the file is not a wallet secret), but it must
        // be visible, or the device asking to pair again looks inexplicable.
        let host_privkey: [u8; 32] = match hex::decode(&file.host_privkey)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
        {
            Some(key) => key,
            None => {
                log::warn!(
                    "{} has a malformed host key; starting a fresh identity — \
                     paired devices will ask to pair again",
                    path.display()
                );
                return None;
            }
        };
        let entries = file
            .credentials
            .iter()
            .filter_map(|c| {
                let pubkey: [u8; 32] = hex::decode(&c.trezor_pubkey).ok()?.try_into().ok()?;
                Some((pubkey, hex::decode(&c.credential).ok()?))
            })
            .collect();
        Some(HostIdentity {
            host_privkey,
            entries,
            path: Some(path.clone()),
        })
    }

    fn save(&self) {
        let Some(path) = self.path.as_ref() else {
            return;
        };
        let file = CredentialFile {
            host_privkey: hex::encode(self.host_privkey),
            credentials: self
                .entries
                .iter()
                .map(|(pubkey, credential)| CredentialEntry {
                    trezor_pubkey: hex::encode(pubkey),
                    credential: hex::encode(credential),
                })
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&file).expect("serialize credentials");
        if let Err(e) = write_private_atomic(path, &json) {
            log::warn!("could not persist Trezor credentials: {e}");
        }
    }

    /// The public half of the host identity, as sent in `ThpCredentialRequest`.
    fn host_pubkey(&self) -> [u8; 32] {
        x25519(self.host_privkey, X25519_BASEPOINT_BYTES)
    }

    /// Store (or replace) the credential a device just issued.
    fn remember(&mut self, trezor_pubkey: &[u8], credential: &[u8]) {
        let Ok(pubkey) = <[u8; 32]>::try_from(trezor_pubkey) else {
            log::warn!("device returned a malformed static pubkey; credential not stored");
            return;
        };
        self.entries.retain(|(existing, _)| *existing != pubkey);
        self.entries.push((pubkey, credential.to_vec()));
        self.save();
    }

    /// Snapshot for the Noise handshake. The handshake consumes the store, so
    /// it gets its own copy of the data.
    pub(crate) fn credential_store(&self) -> QpCredentialStore {
        let entries = self
            .entries
            .iter()
            .filter_map(|(pubkey, credential)| {
                let mut payload = ThpHandshakeCompletionReqNoisePayload::new();
                payload.set_host_pairing_credential(credential.clone());
                let wrapped = payload.write_to_bytes().ok()?;
                if wrapped.len() > MAX_WRAPPED_CREDENTIAL_LEN {
                    log::warn!("stored Trezor credential too large; skipping");
                    return None;
                }
                Some((*pubkey, wrapped))
            })
            .collect();
        QpCredentialStore {
            host_privkey: self.host_privkey,
            entries,
        }
    }
}

/// Write `data` to `path` owner-readable only, atomically. The bytes land in
/// a same-directory temp file created with mode 0600 (so the host private key
/// is never world-readable, even briefly — writing first and chmodding after
/// would leave a window) and are renamed into place, so a crash mid-write
/// cannot leave a truncated file for `load` to reject as malformed — which
/// would silently mint a fresh identity and orphan every stored credential.
/// Windows has no mode bits; it still gets the atomic rename.
fn write_private_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

/// Presents this host's static key — and, for recognized devices, the stored
/// pairing credential — during the Noise handshake.
///
/// Unlike `NullCredentialStore`, the lookup always succeeds: even for an
/// unknown device it returns the persistent host key with an empty credential,
/// so the host identity stays stable across connections (a prerequisite for
/// the credential issued at pairing time to be usable later).
pub(crate) struct QpCredentialStore {
    host_privkey: [u8; 32],
    /// `(trezor_pubkey, protobuf-wrapped credential payload)`.
    entries: Vec<([u8; 32], Vec<u8>)>,
}

impl CredentialStore for QpCredentialStore {
    fn lookup<'a>(
        &self,
        ephemeral_pubkey: &[u8],
        masked_static_pubkey: &[u8],
        dest: &'a mut [u8],
    ) -> Option<FoundCredential<'a>> {
        // The device sends its static key masked with
        // X25519(SHA-256(static || ephemeral), static); match our records
        // against it (trezorlib `credentials.matches`).
        let credential = self
            .entries
            .iter()
            .find(|(trezor_pubkey, _)| {
                let mut hasher = Sha256::new();
                hasher.update(trezor_pubkey);
                hasher.update(ephemeral_pubkey);
                let mask: [u8; 32] = hasher.finalize().into();
                x25519(mask, *trezor_pubkey).as_slice() == masked_static_pubkey
            })
            .map(|(_, wrapped)| wrapped.as_slice())
            .unwrap_or(&[]);

        let total = 32 + credential.len();
        if dest.len() < total {
            return None;
        }
        let (key_dest, cred_dest) = dest.split_at_mut(32);
        key_dest.copy_from_slice(&self.host_privkey);
        cred_dest[..credential.len()].copy_from_slice(credential);
        Some(FoundCredential {
            local_static_privkey: (&*key_dest).try_into().unwrap(),
            auth_credential: &cred_dest[..credential.len()],
        })
    }
}

/// Finish the credential phase on a channel whose handshake credential was
/// accepted (`Paired` / `PairedAutoconnect`). The device sits in its
/// credential state (TC1) after such a handshake and, for a non-autoconnect
/// credential, shows a "Connect?" confirmation; ending the phase moves the
/// channel to encrypted transport.
pub(crate) fn finish_credential_phase(
    client: &mut Client<Channel<RustCrypto>>,
) -> Result<(), TrezorSignerError> {
    let _end: ThpEndResponse = client.call_pb(
        ThpMessageType::ThpMessageType_ThpEndRequest,
        ThpEndRequest::new(),
        ThpMessageType::ThpMessageType_ThpEndResponse,
    )?;
    Ok(())
}

/// Run the pairing phase on a freshly handshaken channel whose state is
/// `Unpaired`.
///
/// The device advertises its methods in preference order and we take the
/// first, as Suite does (`packages/connect/src/device/thp/pairing.ts`). That
/// is always `CodeEntry` in practice: it is the only entry in the firmware's
/// `_DEFAULT_ENABLED_PAIRING_METHODS`, and debug builds merely append
/// `SkipPairing`/`NFC`/`QrCode` after it.
///
/// Deliberately *not* preferring `SkipPairing` when it is on offer: the
/// firmware's skip branch ends the session without issuing a credential
/// (`apps/thp/pairing.py`, `_end_pairing`), so every later connect would
/// arrive unpaired and prompt to pair again. One code entry against the
/// emulator buys the same quiet reconnects a real device gets.
pub(crate) fn run_pairing(
    client: &mut Client<Channel<RustCrypto>>,
    props: &ThpDeviceProperties,
    ux: &mut dyn PairingUx,
    identity: &mut HostIdentity,
) -> Result<(), TrezorSignerError> {
    let methods: Vec<ThpPairingMethod> = props
        .pairing_methods
        .iter()
        .filter_map(|p| p.enum_value().ok())
        .collect();
    let selected = *methods.first().ok_or_else(|| {
        TrezorSignerError::Client("the device advertised no pairing method".into())
    })?;
    if !matches!(
        selected,
        ThpPairingMethod::CodeEntry | ThpPairingMethod::SkipPairing
    ) {
        return Err(TrezorSignerError::Client(format!(
            "the device's preferred pairing method ({selected:?}) is not one \
             QuantumPurse supports (code entry)"
        )));
    }

    let mut request = ThpPairingRequest::new();
    request.set_host_name("QuantumPurse".into());
    request.set_app_name("quantum-purse".into());
    let _approved: ThpPairingRequestApproved = client.call_pb(
        ThpMessageType::ThpMessageType_ThpPairingRequest,
        request,
        ThpMessageType::ThpMessageType_ThpPairingRequestApproved,
    )?;

    if selected == ThpPairingMethod::SkipPairing {
        // Only reachable on firmware that puts skip first — no credential is
        // issued, so this connection is paired but the next one will not be.
        log::warn!("device prefers skip-pairing; it will ask to pair again next connect");
        let mut select = ThpSelectMethod::new();
        select.set_selected_pairing_method(ThpPairingMethod::SkipPairing);
        let _end: ThpEndResponse = client.call_pb(
            ThpMessageType::ThpMessageType_ThpSelectMethod,
            select,
            ThpMessageType::ThpMessageType_ThpEndResponse,
        )?;
        return Ok(());
    }

    code_entry(client, ux, identity)
}

/// The CodeEntry flow (trezorlib `pairing.CodeEntry`): commitment → challenge
/// → user-typed code → CPace → verify secret, then request an autoconnect
/// credential and end the pairing session.
fn code_entry(
    client: &mut Client<Channel<RustCrypto>>,
    ux: &mut dyn PairingUx,
    identity: &mut HostIdentity,
) -> Result<(), TrezorSignerError> {
    let mut select = ThpSelectMethod::new();
    select.set_selected_pairing_method(ThpPairingMethod::CodeEntry);
    let commitment_msg: ThpCodeEntryCommitment = client.call_pb(
        ThpMessageType::ThpMessageType_ThpSelectMethod,
        select,
        ThpMessageType::ThpMessageType_ThpCodeEntryCommitment,
    )?;
    let commitment = commitment_msg.commitment().to_vec();

    let mut challenge_bytes = [0u8; 16];
    getrandom::fill(&mut challenge_bytes).expect("getrandom failed");
    let mut challenge = ThpCodeEntryChallenge::new();
    challenge.set_challenge(challenge_bytes.to_vec());
    // The device shows the pairing code on its display from here on.
    let cpace_trezor: ThpCodeEntryCpaceTrezor = client.call_pb(
        ThpMessageType::ThpMessageType_ThpCodeEntryChallenge,
        challenge,
        ThpMessageType::ThpMessageType_ThpCodeEntryCpaceTrezor,
    )?;
    let trezor_share: [u8; 32] = cpace_trezor
        .cpace_trezor_public_key()
        .try_into()
        .map_err(|_| TrezorSignerError::Protocol("malformed CPace public key".into()))?;

    let handshake_hash = *client.channel.handshake_hash();

    let code = ux.code_entry()?;
    let code = code.trim().to_string();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TrezorSignerError::Client(
            "the pairing code must be exactly 6 digits".into(),
        ));
    }

    let cpace = cpace::cpace_host(code.as_bytes(), &handshake_hash, &trezor_share);
    let mut host_tag = ThpCodeEntryCpaceHostTag::new();
    host_tag.set_cpace_host_public_key(cpace.host_pubkey.to_vec());
    host_tag.set_tag(cpace.tag.to_vec());
    let secret_msg: ThpCodeEntrySecret = client
        .call_pb(
            ThpMessageType::ThpMessageType_ThpCodeEntryCpaceHostTag,
            host_tag,
            ThpMessageType::ThpMessageType_ThpCodeEntrySecret,
        )
        .map_err(|e| match e {
            // A Failure here is almost always a mistyped code.
            TrezorSignerError::Client(msg) => TrezorSignerError::Client(format!(
                "the device rejected the pairing code (was it typed correctly?): {msg}"
            )),
            other => other,
        })?;
    let secret = secret_msg.secret();

    // The device must prove it committed to this secret before we typed the
    // code, and the code must re-derive from the secret (trezorlib checks).
    if Sha256::digest(secret).as_slice() != commitment.as_slice() {
        return Err(TrezorSignerError::Parity(
            "pairing commitment mismatch — possible man-in-the-middle".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update([ThpPairingMethod::CodeEntry as u8]);
    hasher.update(handshake_hash);
    hasher.update(secret);
    hasher.update(challenge_bytes);
    let mut acc: u64 = 0;
    for byte in hasher.finalize() {
        acc = (acc * 256 + u64::from(byte)) % 1_000_000;
    }
    if format!("{acc:06}") != code {
        return Err(TrezorSignerError::Parity(
            "pairing code mismatch — possible man-in-the-middle".into(),
        ));
    }

    // Paired. Ask for a credential so future connections skip pairing; losing
    // it is only an inconvenience (the user would pair again). It must be a
    // regular credential: the firmware rejects `autoconnect=true` in the same
    // session as the pairing itself ("Cannot ask for autoconnect credential
    // after pairing", `apps/thp/pairing.py`).
    let mut cred_req = ThpCredentialRequest::new();
    cred_req.set_host_static_public_key(identity.host_pubkey().to_vec());
    cred_req.set_autoconnect(false);
    match client.call_pb::<ThpCredentialResponse, _>(
        ThpMessageType::ThpMessageType_ThpCredentialRequest,
        cred_req,
        ThpMessageType::ThpMessageType_ThpCredentialResponse,
    ) {
        Ok(response) => {
            identity.remember(response.trezor_static_public_key(), response.credential())
        }
        Err(e) => log::warn!("device did not issue a pairing credential: {e}"),
    }

    let _end: ThpEndResponse = client.call_pb(
        ThpMessageType::ThpMessageType_ThpEndRequest,
        ThpEndRequest::new(),
        ThpMessageType::ThpMessageType_ThpEndResponse,
    )?;
    Ok(())
}
