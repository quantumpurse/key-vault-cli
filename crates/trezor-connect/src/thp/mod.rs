//! Trezor Host Protocol (THP v2) session.
//!
//! The Safe 7 firmware speaks THP only (it rejects Protocol v1 with
//! `Failure_InvalidProtocol` at the handshake), so device access goes through an
//! encrypted Noise session rather than the legacy `trezor-client`. This module
//! ports the reference host loop from `vendor/trezor-thp/examples/host-cli`
//! (channel allocation → Noise handshake → skip-pairing → encrypted `call`) and
//! sends our existing CKB protobuf messages as raw bytes over it. The session
//! runs over either packet transport in [`transport`]: UDP to the emulator or
//! USB to a physical device.

#[allow(clippy::all)]
mod pb;

mod client;
mod cpace;
pub(crate) mod pairing;
pub(crate) mod transport;

use protobuf::Message;
use trezor_client::protos::MessageType as TcMessageType;
use trezor_thp::channel::host::{Channel, Mux};
use trezor_thp::Backend;

use client::Client;
use pairing::{HostIdentity, PairingUx};
use pb::messages_thp::ThpDeviceProperties;

use qpv2_core::types::{MultisigConfig, SpxVariant};

use crate::device::{network_name, DeviceAddress, TREZOR_CONVENTION};
use crate::thp::transport::Transport;
use crate::TrezorSignerError;

/// CKB SPHINCS+ wire message-type ids, derived from the generated protobuf
/// enum so they cannot drift from the firmware's `messages.proto`.
const MSG_FAILURE: u16 = TcMessageType::MessageType_Failure as u16;
const MSG_CKB_SPHINCS_GET_ADDRESS: u16 = TcMessageType::MessageType_CKBSphincsPlusGetAddress as u16;
const MSG_CKB_SPHINCS_ADDRESS: u16 = TcMessageType::MessageType_CKBSphincsPlusAddress as u16;

/// Noise crypto backend for THP: X25519 + AES-256-GCM + SHA-256, matching the
/// device. Mirrors the reference example's backend.
pub(crate) struct RustCrypto;

impl Backend for RustCrypto {
    type DH = trezor_noise_rust_crypto::X25519;
    type Cipher = trezor_noise_rust_crypto::Aes256Gcm;
    type Hash = trezor_noise_rust_crypto::Sha256;

    fn random_bytes(dest: &mut [u8]) {
        getrandom::fill(dest).expect("getrandom failed");
    }
}

/// An established, encrypted THP session with the device.
pub(crate) struct ThpSession {
    client: Client<Channel<RustCrypto>>,
}

impl ThpSession {
    /// Run the full THP bring-up over an established packet transport: channel
    /// allocation, Noise handshake (presenting any stored pairing credential),
    /// and — unless the credential already got us `Paired` — the pairing phase
    /// (skip-pairing on dev firmware, CodeEntry on production firmware).
    pub(crate) fn connect(
        transport: Box<dyn Transport>,
        ux: &mut dyn PairingUx,
    ) -> Result<Self, TrezorSignerError> {
        let mut identity = HostIdentity::load_or_create();

        let mut mux = Mux::<RustCrypto>::new();
        // `try_to_unlock`: the handshake needs the device's static key, which
        // lives in locked storage. With the flag clear the firmware answers
        // `DEVICE_LOCKED` and drops the channel; with it set the firmware shows
        // its PIN keyboard, waits, and then continues the handshake. Connecting
        // is always an explicit user action here, so we always ask — an
        // already-unlocked device skips the prompt and is unaffected.
        mux.request_channel(true);
        let mut client = Client::open(transport, mux);

        // 1. Channel allocation. Probed with a short timeout: a live peer
        // answers in milliseconds with no user interaction, so a dead
        // emulator port or unresponsive device fails in ~2s instead of
        // stalling the full read timeout. Widened right after — the handshake
        // may sit waiting on PIN entry, and later steps legitimately wait on
        // on-device confirmations.
        client.set_read_timeout(client::CONNECT_PROBE_TIMEOUT);
        client.call(0, &[]).map_err(|e| {
            log::debug!("channel allocation failed: {e}");
            TrezorSignerError::Client(
                "no Trezor is responding — is the device plugged in and unlocked, \
                 or the emulator running?"
                    .to_string(),
            )
        })?;
        client.set_read_timeout(client::UNLOCK_TIMEOUT);
        if !client.channel.channel_alloc_ready() {
            return Err(TrezorSignerError::Protocol(
                "channel allocation failed".into(),
            ));
        }
        let mut client = client.try_map(|c| c.complete(identity.credential_store()))?;

        // 2. Noise handshake (device properties carry the protocol version).
        client.device_properties = client.channel.device_properties().into();
        let props = ThpDeviceProperties::parse_from_bytes(&client.device_properties)
            .map_err(|e| TrezorSignerError::Protocol(format!("device properties: {e}")))?;
        if let (Some(maj), Some(min)) = (props.protocol_version_major, props.protocol_version_minor)
        {
            let maj = u8::try_from(maj).unwrap_or(0);
            let min = u8::try_from(min).unwrap_or(0);
            client.channel.set_device_protocol_version(maj, min);
        }
        // A timeout here means the device went quiet holding its handshake
        // reply, which is what it does while the PIN keyboard is up — say so
        // rather than reporting a bare protocol timeout.
        let unlock_wait = |e: TrezorSignerError| match e {
            TrezorSignerError::Timeout(_) => TrezorSignerError::Client(
                "the Trezor was not unlocked in time — unlock it on the device, \
                 then try again"
                    .to_string(),
            ),
            other => other,
        };
        client.call(0, &[]).map_err(unlock_wait)?;
        client.call(0, &[]).map_err(unlock_wait)?;
        if !client.channel.handshake_done() {
            return Err(TrezorSignerError::Protocol("handshake failed".into()));
        }
        // Past the unlock gate; the remaining steps only wait on confirmations.
        client.set_read_timeout(client::READ_TIMEOUT);
        let mut client = client.try_map(|c| c.complete())?;

        // 3. Pairing. When the stored credential was accepted the device sits
        // in its credential phase — confirm the connection and end it; a full
        // pairing (skip or CodeEntry) runs only on unpaired channels.
        if client.channel.handshake_pairing_state().is_paired() {
            pairing::finish_credential_phase(&mut client)?;
        } else {
            pairing::run_pairing(&mut client, &props, ux, &mut identity)?;
        }

        Ok(ThpSession { client })
    }

    /// Send a CKB protobuf message (by wire type id) and return the reply's
    /// type id + bytes. `ButtonRequest`s are auto-acknowledged.
    pub(crate) fn call_ckb(
        &mut self,
        message_type: u16,
        message: &[u8],
    ) -> Result<(u16, Vec<u8>), TrezorSignerError> {
        let (reply_type, reply) = self.client.call_raw(message_type, message)?;
        if reply_type == MSG_FAILURE {
            let msg = pb::messages_common::Failure::parse_from_bytes(&reply)
                .ok()
                .map(|f| f.message().to_string())
                .unwrap_or_default();
            return Err(TrezorSignerError::Client(format!(
                "device rejected the request: {msg}"
            )));
        }
        Ok((reply_type, reply))
    }

    /// Export a SPHINCS+ address, cross-checking the device's lock args against
    /// the wallet's own derivation.
    pub(crate) fn get_address(
        &mut self,
        account_index: u32,
        variant: SpxVariant,
        is_mainnet: bool,
        show_display: bool,
    ) -> Result<DeviceAddress, TrezorSignerError> {
        let want_variant = variant as u32;

        let mut req = trezor_client::protos::CKBSphincsPlusGetAddress::new();
        req.set_account_index(account_index);
        req.set_variant(want_variant);
        req.set_network(network_name(is_mainnet).to_owned());
        req.set_show_display(show_display);
        let bytes = req
            .write_to_bytes()
            .map_err(|e| TrezorSignerError::Protocol(format!("encode get_address: {e}")))?;

        let (reply_type, reply) = self.call_ckb(MSG_CKB_SPHINCS_GET_ADDRESS, &bytes)?;
        if reply_type != MSG_CKB_SPHINCS_ADDRESS {
            return Err(TrezorSignerError::Protocol(format!(
                "unexpected reply type {reply_type} for get_address"
            )));
        }
        let resp = trezor_client::protos::CKBSphincsPlusAddress::parse_from_bytes(&reply)
            .map_err(|e| TrezorSignerError::Protocol(format!("decode address: {e}")))?;

        if resp.variant() != want_variant {
            return Err(TrezorSignerError::VariantMismatch {
                got: resp.variant(),
                want: want_variant,
            });
        }

        let out = DeviceAddress {
            address: resp.address().to_string(),
            lock_args: resp.lock_args().to_vec(),
            pubkey: resp.public_key().to_vec(),
            variant: resp.variant(),
        };

        let expected = MultisigConfig::single_sig(variant, out.pubkey.clone(), TREZOR_CONVENTION)
            .lock_script_args();
        if expected.as_slice() != out.lock_args.as_slice() {
            return Err(TrezorSignerError::Parity(format!(
                "lock_args mismatch: device {} vs derived {}",
                hex::encode(&out.lock_args),
                hex::encode(expected),
            )));
        }

        Ok(out)
    }
}
