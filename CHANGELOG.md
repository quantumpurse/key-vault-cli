# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-06-XX

First major release. Adds the GUI and expands the CLI with multi-wallet support, hardware-backed authentication, and on-chain operations.

### Added — GUI
- Desktop wallet application for macOS, Windows, and Linux.
- Dashboard showing total balance, per-account balances, spendable vs DAO-locked breakdown, and recent transactions.
- Send CKB with account selection, amount input, fee rate, and "send all" option.
- NervosDAO support: deposit, request withdrawal, and withdraw with interest estimation and APC display.
- Choose between Public RPC, Light Client, or Full Node backends. Switch between Mainnet and Testnet. Settings persist across sessions.
- Manage multiple wallets: create, rename, delete, switch, import/export mnemonic.
- Unlock with Touch ID (macOS), TPM PIN (Windows and Linux), or FIDO2 hardware key.
- Password and mnemonic entry handled in a separate secure process.

### Added — CLI
- Multi-wallet support with `--wallet <name>` flag and auto-generated names.
- Keychain and FIDO2 authentication.
- Raw SPHINCS+ verification command.
- Mnemonic import and export.

### Security
- Hardware-backed credential storage on all platforms: Secure Enclave (macOS), TPM (Windows, Linux), FIDO2 hardware keys.
- Passwords and mnemonics never enter the wallet process — handled by a dedicated pinentry dialog.
- Private keys derived on-the-fly and never stored. Sensitive data zeroized on drop.
