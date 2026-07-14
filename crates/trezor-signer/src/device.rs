//! Device discovery, connection, and the `get_address` round-trip.
//!
//! The device is driven over THP (see [`crate::thp`]); this module holds the
//! public handle and the shared address/convention types.

use qpv2_core::types::{SingleSigConvention, SpxVariant};

use crate::thp::ThpSession;
use crate::TrezorSignerError;

/// The single-sig convention a Trezor account uses. The firmware hard-codes the
/// config header `[0x80, 0x00, 0x01, 0x01, flag]` (`required_first_n = 0`), which
/// is QuantumPurse's [`SingleSigConvention::V1`]. Using `Standard`
/// (`required_first_n = 1`) here would derive a different lock script and address.
pub const TREZOR_CONVENTION: SingleSigConvention = SingleSigConvention::V1;

/// A device visible to the host.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Human-readable description.
    pub label: String,
    /// Model name.
    pub model: String,
    /// Whether this is the local emulator.
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

/// An open THP connection to a Trezor device.
pub struct TrezorDevice {
    pub(crate) session: ThpSession,
}

/// The network string the firmware expects.
pub(crate) fn network_name(is_mainnet: bool) -> &'static str {
    if is_mainnet {
        "Mainnet"
    } else {
        "Testnet"
    }
}

/// The devices the host can reach. THP has no cheap enumeration (a probe is a
/// full connect), so this advertises the local emulator endpoint.
pub fn list_devices() -> Vec<DeviceInfo> {
    vec![DeviceInfo {
        label: "Trezor (THP, 127.0.0.1:21324)".to_string(),
        model: "Trezor".to_string(),
        is_emulator: true,
    }]
}

/// Open a THP session with the device (currently the local emulator).
pub fn open() -> Result<TrezorDevice, TrezorSignerError> {
    Ok(TrezorDevice {
        session: ThpSession::connect()?,
    })
}

impl TrezorDevice {
    /// Display label for the connected device.
    pub fn model(&self) -> String {
        "Trezor Safe".to_string()
    }

    /// Export a SPHINCS+ address for `account_index` under `variant`. The
    /// returned `lock_args` are cross-checked against the wallet's own
    /// derivation inside the THP session.
    pub fn get_address(
        &mut self,
        account_index: u32,
        variant: SpxVariant,
        is_mainnet: bool,
        show_display: bool,
    ) -> Result<DeviceAddress, TrezorSignerError> {
        self.session
            .get_address(account_index, variant, is_mainnet, show_display)
    }
}
