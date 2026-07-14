//! Trezor Host Protocol (THP v2) transport.
//!
//! The Safe 7 firmware speaks THP only (it rejects Protocol v1 with
//! `Failure_InvalidProtocol` at the handshake), so device access goes through an
//! encrypted Noise session rather than the legacy `trezor-client`. This module
//! ports the reference host loop from `vendor/trezor-thp/examples/host-cli`
//! (channel allocation → Noise handshake → skip-pairing → encrypted `call`) and
//! sends our existing CKB protobuf messages as raw bytes over it.

#[allow(clippy::all)]
mod pb;

mod client;

use std::net::SocketAddr;

use protobuf::Message;
use trezor_thp::channel::host::{Channel, Mux};
use trezor_thp::credential::NullCredentialStore;
use trezor_thp::Backend;

use client::Client;
use pb::messages_thp::{
    ThpDeviceProperties, ThpEndResponse, ThpMessageType, ThpPairingMethod, ThpPairingRequest,
    ThpPairingRequestApproved, ThpSelectMethod,
};

use qpv2_core::types::{MultisigConfig, SpxVariant};

use crate::device::{network_name, DeviceAddress, TREZOR_CONVENTION};
use crate::TrezorSignerError;

/// Default emulator UDP port.
const DEFAULT_UDP_PORT: u16 = 21324;

/// CKB SPHINCS+ wire message-type ids (from the firmware `messages.proto`).
const MSG_FAILURE: u16 = 3;
const MSG_CKB_SPHINCS_GET_ADDRESS: u16 = 5520;
const MSG_CKB_SPHINCS_ADDRESS: u16 = 5521;

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
    /// Connect to the local emulator and run the full THP bring-up:
    /// channel allocation, Noise handshake, and skip-pairing.
    pub(crate) fn connect() -> Result<Self, TrezorSignerError> {
        let addr = SocketAddr::from(([127, 0, 0, 1], DEFAULT_UDP_PORT));

        let mut mux = Mux::<RustCrypto>::new();
        mux.request_channel(false);
        let mut client = Client::open(addr, mux)?;

        // 1. Channel allocation.
        client.call(0, &[])?;
        if !client.channel.channel_alloc_ready() {
            return Err(TrezorSignerError::Protocol(
                "channel allocation failed".into(),
            ));
        }
        let mut client = client.try_map(|c| c.complete(NullCredentialStore))?;

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
        client.call(0, &[])?;
        client.call(0, &[])?;
        if !client.channel.handshake_done() {
            return Err(TrezorSignerError::Protocol("handshake failed".into()));
        }
        let mut client = client.try_map(|c| c.complete())?;

        // 3. Pairing — the emulator/host pair is unauthenticated (skip-pairing).
        do_pairing(&mut client, &props)?;

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

/// Skip-pairing: the emulator advertises `SkipPairing`, so we request pairing
/// and immediately select the no-authentication method.
fn do_pairing(
    client: &mut Client<Channel<RustCrypto>>,
    props: &ThpDeviceProperties,
) -> Result<(), TrezorSignerError> {
    let supports_skip = props
        .pairing_methods
        .iter()
        .filter_map(|p| p.enum_value().ok())
        .any(|m| m == ThpPairingMethod::SkipPairing);
    if !supports_skip {
        return Err(TrezorSignerError::Protocol(
            "device does not support skip-pairing".into(),
        ));
    }

    let mut request = ThpPairingRequest::new();
    request.set_host_name("QuantumPurse".into());
    request.set_app_name("quantum-purse".into());
    let _approved: ThpPairingRequestApproved = client.call_pb(
        ThpMessageType::ThpMessageType_ThpPairingRequest,
        request,
        ThpMessageType::ThpMessageType_ThpPairingRequestApproved,
    )?;

    let mut select = ThpSelectMethod::new();
    select.set_selected_pairing_method(ThpPairingMethod::SkipPairing);
    let _end: ThpEndResponse = client.call_pb(
        ThpMessageType::ThpMessageType_ThpSelectMethod,
        select,
        ThpMessageType::ThpMessageType_ThpEndResponse,
    )?;

    Ok(())
}
