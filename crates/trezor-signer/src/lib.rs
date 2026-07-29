//! Trezor Safe hardware signer for QuantumPurse.
//!
//! QuantumPurse builds a CKB transaction as usual, then instead of signing it
//! with the software [`qpv2_core::KeyVault`] it streams the transaction to a
//! Trezor device, which recomputes the CKB signing message (`ckb_tx_message_all`,
//! `blake2b` personal `ckb-sphincs+-msg`) on-device, SPHINCS+-signs it, and
//! returns the fully assembled witness lock. The host does no cryptography — it
//! only streams the transaction and reassembles the signature.
//!
//! Transport and protocol are separate layers. The device is driven over THP
//! v2 (an encrypted Noise session — the only protocol the Safe 7 firmware
//! accepts) riding either the UDP loopback transport (emulator) or USB
//! (physical device); Bluetooth is a future milestone.

mod conv;
mod device;
mod error;
mod stream;
mod thp;

pub use device::{
    list_devices, open, open_device, open_emulator, DeviceAddress, DeviceInfo, DeviceLocation,
    TrezorDevice, TREZOR_CONVENTION,
};
pub use error::TrezorSignerError;
pub use stream::SignedWitness;
pub use thp::pairing::{NoInteraction, PairingUx, PinentryPairing, StdinPairing};

/// The default SPHINCS+ variant used when the caller does not specify one:
/// `SpxVariant::Sha2128S` (id 49, `SLH-DSA-SHA2-128s`) — matching the Trezor
/// firmware default and the wallet's typical single-sig account.
pub const DEFAULT_VARIANT: qpv2_core::types::SpxVariant = qpv2_core::types::SpxVariant::Sha2128S;
