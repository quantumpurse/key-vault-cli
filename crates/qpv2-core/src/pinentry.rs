//! Out-of-process password input via the `pinentry` crate.
//!
//! Replaces the in-process egui modal: keystrokes never enter this
//! binary's address space. The crate spawns a platform-specific child
//! pinentry process; we receive the password as a single kernel-pipe
//! read at submit time, copy it once into a zeroize-on-drop
//! `SecureString`, and drop it the moment the vault op returns.
//!
//! Lookup is binary-adjacent only — `current_exe().parent()/<binary>`.
//! For release this resolves inside the app bundle / install dir; for
//! `cargo run` the build script (`build.rs`) copies the from-source
//! build (`vendor/pinentry-build/`) next to `target/{debug,release}/qpv2-gui`.
//! There is no `$PATH` fallback by design, so dev and release exercise
//! the same resolution path.
//!
//! Every call in this module blocks the calling thread until the dialog
//! closes: each Assuan command waits on the child's reply, and pinentry
//! replies to the final one only when the user presses a button. A prompt
//! answered in a few seconds can run on the egui update loop; one the user
//! may sit in for minutes, such as the seed-phrase display, must not:
//! Windows reports a window hung after about five seconds without frames.
//! Such prompts run on a worker thread and the GUI shows a locking overlay
//! meanwhile (see `App::export_seed_phrase`).

use crate::SecureString;
use pinentry::{Error as PinentryError, MessageDialog, PassphraseInput};
use secrecy::ExposeSecret;
use std::path::PathBuf;

/// Platform name used in error messages.
#[cfg(target_os = "macos")]
const PINENTRY_NAME: &str = "pinentry-mac";
#[cfg(target_os = "linux")]
const PINENTRY_NAME: &str = "pinentry-gtk-2";
#[cfg(target_os = "windows")]
const PINENTRY_NAME: &str = "pinentry-w32.exe";

/// Resolves the bundled pinentry binary adjacent to the current exe.
///
/// macOS: `pinentry-mac` is a Cocoa .app — the binary needs its
/// sibling `Resources/` (nibs, etc.) to draw the dialog, so we
/// bundle the entire `.app` and resolve the inner Mach-O.
///
/// Linux/Windows: plain binary sitting next to the wallet exe.
fn pinentry_path() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe() failed: {}", e))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "current_exe() has no parent".to_string())?;

    #[cfg(target_os = "macos")]
    let path = dir
        .join("pinentry-mac.app")
        .join("Contents")
        .join("MacOS")
        .join("pinentry-mac");

    #[cfg(target_os = "linux")]
    let path = dir.join("pinentry-gtk-2");

    #[cfg(target_os = "windows")]
    let path = dir.join("pinentry-w32.exe");

    if !path.exists() {
        let msg = format!(
            "{} not found at {}. Release: bundle is broken. \
			 Dev: run `vendor/build-pinentry.sh` and rebuild so build.rs \
			 stages the binary next to the wallet exe.",
            PINENTRY_NAME,
            path.display()
        );
        eprintln!("auth: {}", msg);
        return Err(msg);
    }
    Ok(path)
}

/// gpg-error code the bundled pinentry returns when the typed or pasted
/// input is longer than its limit (`PINENTRY_MAX_PASSPHRASE_LENGTH` in
/// `vendor/pinentry/pinentry/pinentry.h`). It refuses rather than clips,
/// so the user has to be told why. The `pinentry` crate has no named
/// variant for this code.
const GPG_ERR_TOO_LARGE: u16 = 67;

/// Maps pinentry errors to user-facing strings.
fn map_err(e: PinentryError) -> String {
    match e {
        PinentryError::Cancelled => "Cancelled.".to_string(),
        PinentryError::Timeout => "Password entry timed out.".to_string(),
        PinentryError::Io(e) => format!("Password dialog I/O error: {}", e),
        PinentryError::Encoding(_) => "Password is not valid UTF-8.".to_string(),
        PinentryError::Gpg(g) if g.code() == GPG_ERR_TOO_LARGE => {
            "Input is longer than the 1024-character limit of the entry dialog.".to_string()
        }
        PinentryError::Gpg(g) => format!("Password dialog error: {}", g),
    }
}

/// Open a single-field password dialog. `description` appears above
/// the field, `prompt` immediately to the left of it. The returned
/// `SecureString` is zeroize-on-drop; the caller is responsible for
/// not cloning it into unmanaged buffers.
pub fn prompt_password(description: &str, prompt: &str) -> Result<SecureString, String> {
    let path = pinentry_path()?;
    let mut input = PassphraseInput::with_binary(&path)
        .ok_or_else(|| format!("{} not executable at {}", PINENTRY_NAME, path.display()))?;
    let secret = input
        .with_title("Quantum Purse")
        .with_description(description)
        .with_prompt(prompt)
        .with_ok("Authorize")
        .with_cancel("Cancel")
        .interact()
        .map_err(map_err)?;
    Ok(SecureString::from_string(
        secret.expose_secret().to_string(),
    ))
}

/// Prompt for a BIP39 seed phrase via pinentry. The `variant`
/// determines the expected word count, which is shown in the dialog
/// description so the user knows what to enter.
pub fn prompt_seed_phrase(variant: crate::types::SpxVariant) -> Result<SecureString, String> {
    let word_count = variant.required_bip39_size_in_word_total();
    let path = pinentry_path()?;
    let mut input = PassphraseInput::with_binary(&path)
        .ok_or_else(|| format!("{} not executable at {}", PINENTRY_NAME, path.display()))?;
    let secret = input
        .with_title("Quantum Purse")
        .with_description(&format!(
            "Enter your seed phrase to import.\n\
             The selected variant ({}) expects {} words separated by spaces.",
            variant, word_count
        ))
        .with_prompt("Seed phrase:")
        .with_ok("Import")
        .with_cancel("Cancel")
        .interact()
        .map_err(map_err)?;
    Ok(SecureString::from_string(
        secret.expose_secret().to_string(),
    ))
}

/// Open a password dialog with a confirmation field. pinentry's
/// `SETREPEAT` makes the binary itself enforce match — we receive a
/// single `SecretString` only after both fields agree. `mismatch_error`
/// is what the dialog shows in-place when they don't.
pub fn prompt_password_with_confirmation(
    description: &str,
    prompt: &str,
    confirm_prompt: &str,
    mismatch_error: &str,
) -> Result<SecureString, String> {
    let path = pinentry_path()?;
    let mut input = PassphraseInput::with_binary(&path)
        .ok_or_else(|| format!("{} not executable at {}", PINENTRY_NAME, path.display()))?;
    let secret = input
        .with_title("Quantum Purse")
        .with_description(description)
        .with_prompt(prompt)
        .with_confirmation(confirm_prompt, mismatch_error)
        .with_ok("Create")
        .with_cancel("Cancel")
        .interact()
        .map_err(map_err)?;
    Ok(SecureString::from_string(
        secret.expose_secret().to_string(),
    ))
}

/// Display a seed phrase in a one-button pinentry dialog.
/// The text is rendered by the pinentry process — never enters
/// egui's address space or GPU texture cache.
pub fn show_seed_phrase(seed_phrase: &str) -> Result<(), String> {
    let path = pinentry_path()?;
    let mut dialog = MessageDialog::with_binary(&path)
        .ok_or_else(|| format!("{} not executable at {}", PINENTRY_NAME, path.display()))?;
    dialog
        .with_title("Quantum Purse")
        .with_ok("Done")
        .show_message(seed_phrase)
        .map_err(map_err)
}
