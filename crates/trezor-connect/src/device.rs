//! Device discovery, connection, and the `get_address` round-trip.
//!
//! The device is driven over THP (see [`crate::thp`]); this module holds the
//! public handle and the shared address/convention types.

use std::net::SocketAddr;

use qpv2_core::types::{SingleSigConvention, SpxVariant};

use crate::thp::pairing::{NoInteraction, PairingUx};
use crate::thp::transport::{
    scan_usb, Transport, UdpTransport, UsbLocation, UsbTransport, EMULATOR_PORT,
};
use crate::thp::ThpSession;
use crate::TrezorSignerError;

/// The single-sig convention a Trezor account uses. The firmware hard-codes the
/// config header `[0x80, 0x01, 0x01, 0x01, flag]` (`required_first_n = 1`), which
/// is QuantumPurse's [`SingleSigConvention::Standard`]. Using `V1`
/// (`required_first_n = 0`) here would derive a different lock script and address,
/// and `get_address`'s parity check would reject every account.
pub const TREZOR_CONVENTION: SingleSigConvention = SingleSigConvention::Standard;

/// Where a discovered device lives — determines the transport used to reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLocation {
    /// The local firmware emulator, over UDP loopback.
    Emulator {
        /// Emulator UDP port (default 21324).
        port: u16,
    },
    /// A physical device on the USB bus.
    Usb {
        /// libusb bus number.
        bus: u8,
        /// libusb device address on that bus.
        address: u8,
    },
}

/// A device visible to the host.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// Human-readable description.
    pub label: String,
    /// Model name.
    pub model: String,
    /// How to reach the device; pass to [`open_device`].
    pub location: DeviceLocation,
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

/// The devices the host can reach: every Trezor enumerated on the USB bus,
/// plus the local emulator endpoint (which is advertised unconditionally —
/// probing it would cost a full THP connect).
pub fn list_devices() -> Vec<DeviceInfo> {
    let mut devices: Vec<DeviceInfo> = scan_usb()
        .into_iter()
        .map(|loc| DeviceInfo {
            label: format!("Trezor (USB bus {} addr {})", loc.bus, loc.address),
            model: "Trezor".to_string(),
            location: DeviceLocation::Usb {
                bus: loc.bus,
                address: loc.address,
            },
        })
        .collect();
    devices.push(DeviceInfo {
        label: format!("Trezor emulator (UDP 127.0.0.1:{EMULATOR_PORT})"),
        model: "Trezor".to_string(),
        location: DeviceLocation::Emulator {
            port: EMULATOR_PORT,
        },
    });
    devices
}

/// Open the first reachable device: a physical Trezor if one is on the USB
/// bus, otherwise the local emulator. Set `QPV2_TREZOR_EMULATOR=1` to skip
/// the USB scan and force the emulator.
///
/// A first-time connection to production firmware runs code-entry pairing;
/// `ux` supplies the 6-digit code the device displays. Paired devices skip
/// the code entry via the stored credential, but still show a "Connect?"
/// confirmation on the device each session (the credential is not the
/// autoconnect kind).
pub fn open(ux: &mut dyn PairingUx) -> Result<TrezorDevice, TrezorSignerError> {
    if std::env::var_os("QPV2_TREZOR_EMULATOR").is_none() {
        if let Some(loc) = scan_usb().into_iter().next() {
            return open_transport(Box::new(UsbTransport::connect(loc)?), ux);
        }
    }
    open_transport(emulator_transport(EMULATOR_PORT)?, ux)
}

/// Open a specific device previously returned by [`list_devices`].
pub fn open_device(
    info: &DeviceInfo,
    ux: &mut dyn PairingUx,
) -> Result<TrezorDevice, TrezorSignerError> {
    let transport: Box<dyn Transport> = match info.location {
        DeviceLocation::Usb { bus, address } => {
            Box::new(UsbTransport::connect(UsbLocation { bus, address })?)
        }
        DeviceLocation::Emulator { port } => emulator_transport(port)?,
    };
    open_transport(transport, ux)
}

/// Open the local firmware emulator on the default port, without a pairing UX.
///
/// Requires an emulator this host has already paired with: pairing takes the
/// device's preferred method, which is code entry, and [`NoInteraction`] turns
/// that into a clear error rather than blocking. Pair once by hand (the GUI, or
/// the `thp_get_address` example) and the stored credential keeps every later
/// call here unattended.
pub fn open_emulator() -> Result<TrezorDevice, TrezorSignerError> {
    open_transport(emulator_transport(EMULATOR_PORT)?, &mut NoInteraction)
}

fn emulator_transport(port: u16) -> Result<Box<dyn Transport>, TrezorSignerError> {
    Ok(Box::new(UdpTransport::connect(SocketAddr::from((
        [127, 0, 0, 1],
        port,
    )))?))
}

fn open_transport(
    transport: Box<dyn Transport>,
    ux: &mut dyn PairingUx,
) -> Result<TrezorDevice, TrezorSignerError> {
    Ok(TrezorDevice {
        session: ThpSession::connect(transport, ux)?,
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
