//! Device discovery, connection, and the `get_address` round-trip.

use crate::TrezorSignerError;
use qpv2_core::types::{MultisigConfig, SingleSigConvention, SpxVariant};
use trezor_client::protos;

/// The single-sig convention a Trezor account uses. The firmware hard-codes the
/// config header `[0x80, 0x00, 0x01, 0x01, flag]` (`required_first_n = 0`), which
/// is QuantumPurse's [`SingleSigConvention::V1`]. Using `Standard`
/// (`required_first_n = 1`) here would derive a different lock script and address.
pub const TREZOR_CONVENTION: SingleSigConvention = SingleSigConvention::V1;

/// A device visible to the host (USB or the local emulator over UDP).
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Human-readable description (model + transport).
    pub label: String,
    /// Model name, e.g. "Trezor" or "Trezor Emulator".
    pub model: String,
    /// Whether this is the UDP emulator rather than physical hardware.
    pub is_emulator: bool,
}

/// A SPHINCS+ address exported from the device.
#[derive(Debug, Clone)]
pub struct DeviceAddress {
    /// Bech32m CKB address.
    pub address: String,
    /// 32-byte blake2b lock script args.
    pub lock_args: Vec<u8>,
    /// SPHINCS+ public key bytes.
    pub pubkey: Vec<u8>,
    /// SPHINCS+ variant id (48..=59) the device used.
    pub variant: u32,
}

/// An open connection to a Trezor device.
pub struct TrezorDevice {
    pub(crate) inner: trezor_client::Trezor,
}

/// Map a `trezor-client` error into our error type, preserving its message
/// (which includes device-side `Failure` text such as a user rejection).
pub(crate) fn client_err(e: trezor_client::Error) -> TrezorSignerError {
    TrezorSignerError::Client(e.to_string())
}

/// The network string the firmware expects.
pub(crate) fn network_name(is_mainnet: bool) -> &'static str {
    if is_mainnet {
        "Mainnet"
    } else {
        "Testnet"
    }
}

/// List all connected devices (USB) and the local emulator (UDP), if present.
pub fn list_devices() -> Vec<DeviceInfo> {
    trezor_client::find_devices(false)
        .into_iter()
        .map(|d| DeviceInfo {
            label: d.to_string(),
            model: d.model.to_string(),
            is_emulator: d.model == trezor_client::Model::TrezorEmulator,
        })
        .collect()
}

/// Open the first available device (the emulator when it is the only one
/// present) and initialize a session.
pub fn open() -> Result<TrezorDevice, TrezorSignerError> {
    let mut devices = trezor_client::find_devices(false);
    if devices.is_empty() {
        return Err(TrezorSignerError::NoDevice);
    }
    let mut trezor = devices.remove(0).connect().map_err(client_err)?;
    trezor.init_device(None).map_err(client_err)?;
    Ok(TrezorDevice { inner: trezor })
}

impl TrezorDevice {
    /// Human-readable model name of the connected device.
    pub fn model(&self) -> String {
        self.inner.model().to_string()
    }

    /// Export a SPHINCS+ address for `account_index` under `variant`.
    ///
    /// The returned `lock_args` are cross-checked against a locally recomputed
    /// value (blake2b over the config header + public key) so a firmware/host
    /// mismatch is caught before the address is ever used.
    pub fn get_address(
        &mut self,
        account_index: u32,
        variant: SpxVariant,
        is_mainnet: bool,
        show_display: bool,
    ) -> Result<DeviceAddress, TrezorSignerError> {
        let want_variant = variant as u32;

        let mut req = protos::CKBSphincsPlusGetAddress::new();
        req.set_account_index(account_index);
        req.set_variant(want_variant);
        req.set_network(network_name(is_mainnet).to_owned());
        req.set_show_display(show_display);

        let resp: protos::CKBSphincsPlusAddress = trezor_client::client::handle_interaction(
            self.inner
                .call(req, Box::new(|_, m: protos::CKBSphincsPlusAddress| Ok(m)))
                .map_err(client_err)?,
        )
        .map_err(client_err)?;

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

        // Defense-in-depth: the device's lock_args must equal what the wallet
        // derives from the same public key + variant (V1 convention).
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
