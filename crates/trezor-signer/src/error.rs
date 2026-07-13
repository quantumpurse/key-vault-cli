//! Error type for the Trezor signer.

/// Errors surfaced while talking to a Trezor device.
#[derive(thiserror::Error, Debug)]
pub enum TrezorSignerError {
    /// No Trezor device (or emulator) was found.
    #[error("no Trezor device found")]
    NoDevice,

    /// The underlying `trezor-client` returned an error. This includes a
    /// device-side `Failure` such as the user rejecting the action on-device.
    #[error("device error: {0}")]
    Client(String),

    /// The host could not supply a previous transaction the device requested
    /// for its trustless input-capacity check.
    #[error("missing previous transaction for {0}")]
    MissingPrevTx(String),

    /// The device drove the streaming protocol into an unexpected state.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Converting the CKB transaction into the device's protobuf shapes failed.
    #[error("conversion error: {0}")]
    Conversion(String),

    /// The device returned a different SPHINCS+ variant than requested.
    #[error("variant mismatch: device returned {got}, expected {want}")]
    VariantMismatch { got: u32, want: u32 },

    /// A device response did not match what the wallet independently computed
    /// (e.g. lock args derived from the returned public key).
    #[error("parity check failed: {0}")]
    Parity(String),
}
