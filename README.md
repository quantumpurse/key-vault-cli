# QPV2

QPV2 is a pure Rust Quantum Purse built on top of [Quantum Purse V1's core](https://github.com/quantumpurse/key-vault-wasm). QPV2 is Optimized for security and performance. Design by human, developed in collaboration with Claude Opus and Fable.

### Crates

- **`qpv2-core`** — SPHINCS+ key management and signing.
- **`qpv2-cli`** — is QPV2 but with Command Line Interface.
- **`qpv2-gui`** — is QPV2 but is a GUI (egui).
- **`keychain`** — is multi-platform hardware backed key keeper and manager (Apple Keychain, TMP2.0 on Windows and Linus).
- **`ckb-node`** — CKB node abstraction and wallet-domain helpers.
- **`trezor-connect`** — Trezor Safe hardware connector.
- **`ckb-fips205-utils`** — copied from the [quantum-resistant-lock-script project](https://github.com/nervosnetwork/quantum-resistant-lock-script) and primarily used for `CKB_TX_MESSAGE_ALL`.

### Build & Run

Dependencies: Rust & Cargo

All platforms require git submodules before building:
```shell
git clone https://github.com/quantumpurse/quantum-purse-v2.git
cd quantum-purse-v2
git submodule update --init
```

#### macOS

Build toolchain: `brew install automake gettext && xcode-select --install`

```shell
# CLI
cargo build -p qpv2-cli --release

# GUI (builds, bundles, and optionally signs the .app)
./build.sh <cli|gui> [--release] [--sign] [--clean] [--profile <path>]
# --sign requires an Apple develop id. Skip if you don't have one.
# --profile embeds a provisioning profile, which macOS requires before Touch ID
# will work. Needs an Apple develop id too. Skip if you don't have one.
# --clean will rebuild fresh.
# --release will build optimized release bin (faster). Without this flag, it will build debug binary (slower, but watchable)
./launch.sh <cli|gui> [--release]
# --release will run the optimized release bin (faster). Without this flag, it will build debug binary (slower, but watchable)
```

#### Linux

Install system dependencies first — the build will fail without them:
```shell
sudo apt-get install -y gettext libgtk2.0-dev libdbus-1-dev libtss2-dev libudev-dev
```

Build:
```shell
# CLI
cargo build -p qpv2-cli --release
# → target/release/qpv2-cli

# GUI (builds the GUI, pinentry-gtk-2, ckb-light-client, and ckb full node, then packages everything into a tarball)
./crates/qpv2-gui/scripts/bundle-linux.sh [--release]
# → target/<profile>/qpv2-gui-linux-<arch>/  (+ .tar.gz)
```

Run:
```shell
# CLI
./target/release/qpv2-cli --help

# GUI (launch.sh is macOS-only; on Linux run the binary directly)
./target/debug/qpv2-gui-linux-x86_64/qpv2-gui          # debug
./target/release/qpv2-gui-linux-x86_64/qpv2-gui         # release
```

#### Windows

Build toolchain:
- Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the "Desktop development with C++" workload (provides the MSVC linker). 
- Install [LLVM](https://releases.llvm.org/) (`winget install LLVM.LLVM`). Required by RocksDB's bindgen to find `libclang.dll`.
- Install [MSYS2](https://www.msys2.org) and open **"MSYS2 MINGW64"** from the Start menu (not UCRT64 or plain MSYS2), then run: `pacman -S mingw-w64-x86_64-toolchain automake autoconf libtool make gettext-devel`. 
- Add `C:\msys64\mingw64\bin` to the system PATH so that `gcc` resolves to the 64-bit toolchain. In an admin PowerShell: `[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "Machine") + ";C:\msys64\mingw64\bin", "Machine")` — then restart PowerShell.

```powershell
# CLI
cargo build -p qpv2-cli --release

# GUI
.\crates\qpv2-gui\scripts\bundle-windows.ps1 [-Release]
# If PowerShell blocks the script, run it with:
powershell -ExecutionPolicy Bypass -File .\crates\qpv2-gui\scripts\bundle-windows.ps1 [-Release]
# → target\<profile>\qpv2-gui-windows-x86_64\  (+ .zip)
```

### Tests

```shell
cargo test --workspace
```

### Trezor emulator
Emulator MUST be used for testing purposes only. If you wish to test this wallet with Trezor emulator, here's how to start the emulator (tested on macos). From the repo root (`vendor/trezor-firmware`):

###### 1. Install Nix (one-time)
```
sh <(curl -L https://nixos.org/nix/install)
```
###### 2. Init submodules (one-time, or after pulling new changes)
```
git submodule update --init --recursive --force
```
###### 3. Enter Nix shell (sets up compilers and system deps)
```
nix-shell
```
###### 4. Install Python dependencies
```
uv sync
source .venv/bin/activate
```
###### 5. Build and run
```
cd core
make build_unix
make emu
```

### Secrets Input

Password/mnemonic entry in QPV2 happens **outside the wallet's own process** - through a dedicated, OS-native dialog spawned as a child process called [Pinentry](https://www.gnupg.org/related_software/pinentry/index.html).

### Credential Store Authentication

When a wallet is created with `--keychain` (CLI) or the keychain button
(GUI), a random 32-byte AES key is generated and stored in the
platform's credential store. The encrypted master seed lives on disk;
the credential store only holds the encryption key.

##### 1. macOS — Data Protection Keychain + Secure Enclave

Items are stored in the Data Protection Keychain with
`BiometryCurrentSet` access control. The encryption key (K1) never
leaves the Secure Enclave in plaintext except at the moment it is
returned to the app. The full key hierarchy below is hardware-enforced
— the main CPU never sees any intermediate key.

###### Key hierarchy

```
K1 (the 32-byte AES encryption key your app stores)
  │── encrypted by ── Per-item key (random AES-256, unique to this keychain item)
                          │── wrapped by ── Class key
                                               │── derived from ── KDF(hardware UID + user passcode)
                                               │── additionally wrapped by ── Biometric subsystem key
                                                                                 │── released only on Touch ID match
                                                                                 │── bound to current fingerprint set
```

- **Hardware UID**: A 256-bit AES key fused into the Secure Enclave at
  manufacturing. It cannot be read by software, firmware, or Apple —
  it is only usable as an input to the Enclave's internal AES engine.
  This is the root of trust that makes ciphertext device-bound.

- **Class key**: Derived from the hardware UID and the user's device
  passcode via a KDF with timed iterations (100–150 ms) to resist
  brute-force. Derived once at first unlock after boot, then held in
  Secure Enclave RAM in biometric-wrapped form. Evicted on reboot,
  after ~48 hours without passcode entry, or after 5 failed biometric
  attempts — all of which force a passcode re-entry.

- **Biometric subsystem key**: Generated inside the Secure Enclave and
  held by its biometric subsystem. Released only upon a successful
  Touch ID match over a hardware-encrypted channel between the
  fingerprint sensor and the Enclave (the main CPU never sees
  biometric data). Once released, it unwraps the class key for a
  single operation and is immediately discarded from working memory.

- **Per-item key**: A random AES-256 key generated by the Secure
  Enclave at item creation. Encrypts K1 via AES-256-GCM. Wrapped by
  the class key using NIST AES Key Wrap (RFC 3394). The wrapped form
  is stored on disk; the plaintext per-item key exists only inside the
  Enclave during encrypt/decrypt operations.

###### Retrieval flow

When `retrieve_key()` is called:

1. Touch ID sensor captures a fingerprint scan and sends it to the
   Secure Enclave over a dedicated hardware channel.
2. Secure Enclave compares the scan against stored templates. On
   match, the biometric subsystem releases its key.
3. Secure Enclave uses the biometric key to unwrap the class key
   (which has been in RAM in wrapped form since boot).
4. Secure Enclave uses the class key to unwrap the per-item key.
5. Secure Enclave uses the per-item key to decrypt K1.
6. K1 is returned to the app. The biometric key is discarded from
   working memory.

###### What Apple does not publicly document

The exact nature of the biometric subsystem key (random at enrollment
vs. derived from template hashes), the precise mechanism that binds it
to the enrollment set, and whether the biometric wrapping is per-item
or per-class are not disclosed. The security *properties* above are
documented in the [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web);
the internal cryptographic construction is not.

##### 2. Windows — TPM seal via the Platform Crypto Provider

The 32-byte vault encryption key is sealed under the TPM using the
Platform Crypto Provider's well-known seal key
(`TPM_RSA_SRK_SEAL_KEY`), via `NCryptEncrypt` with
`NCRYPT_SEALING_FLAG`. A user-chosen PIN of at least six characters becomes the sealed object's
authorization value, passed as the seal password, and the opaque blob
is stored to `pcp_sealed_blob.bin` on disk. On unlock the PIN is
supplied again and `NCryptDecrypt` returns the 32 bytes. The sealed
blob is useless on another machine.

The PIN is not sent verbatim: a TPM authorization value is capped at
the name algorithm's digest size (32 bytes under SHA-256), so the PIN
is expanded through HKDF-SHA256 to exactly that length. This removes
any length limit on the PIN itself and makes the value independent of
character encoding.

This is the same construction as the Linux path below, and the same
family of operation BitLocker uses for its volume master key.

##### 3. Linux — TPM seal via `tss-esapi`

The 32-byte vault encryption key is sealed under the TPM's Storage
Root Key (SRK) using `TPM2_Create`. A user-chosen PIN of at least six characters,
expanded through HKDF-SHA256 to the 32-byte authorization value exactly as on
Windows, is set as the sealed object's `authValue` during creation and verified on-chip
during every unseal — failed attempts count toward the TPM's
dictionary attack lockout. The sealed blobs (Private + Public) are
persisted to `tpm_sealed_blob.bin` on disk. On unlock, the SRK is
recreated from a well-known template (deterministic — same template
always produces the same SRK on the same TPM), the blobs are loaded,
the PIN is verified by the TPM, and `TPM2_Unseal` returns the
32 bytes. The key never leaves the TPM in plaintext except during the
unseal operation, and the sealed blob is useless on another machine.

Binary blob format: `[u32 LE: private_len][private bytes][public bytes]`.

Requires `libtss2-dev` (Ubuntu/Debian), `tpm2-tss-devel` (Fedora),
or `tpm2-tss` (Arch) at build time. Device access via `/dev/tpmrm0`
(kernel resource manager).

The previous Secret Service D-Bus implementation is preserved in
`sw_backed/linux_secret_service.rs` for reference.

##### 4. Platform comparison

| Scenario | Plain file | DPAPI / Secret Service | Apple Keychain + Touch ID | TPM seal (Windows) | TPM seal (Linux) | FIDO2 Hardware Key |
|---|---|---|---|---|---|---|
| Malware running as user | Reads key freely | Reads key freely | Blocked — Secure Enclave requires Touch ID per access | Blocked — requires the PIN per access | Blocked — TPM requires authorization policy | Blocked — requires physical device + PIN + tap |
| Another user on same machine | Can read if file permissions allow | Cannot decrypt (tied to user session) | Cannot access (Keychain bound to user + biometric) | Cannot access without the PIN (seal is machine-bound, not user-bound) | Cannot access (TPM sealed to user session) | Cannot access — no device, no PIN |
| Stolen disk, booted from USB | Reads key in plaintext | Cannot decrypt without user's login password | Cannot decrypt — key sealed in Secure Enclave hardware | Cannot decrypt — sealed blob useless without this TPM | Cannot decrypt — sealed blob useless without TPM | Cannot decrypt — credential_id blob useless without device |
| Admin with Mimikatz while user logged in | Reads key freely | Can extract DPAPI master key from memory | Key never leaves Secure Enclave in plaintext | Key never leaves the TPM in plaintext — nothing to extract | Key never leaves TPM in plaintext | Key never leaves FIDO2 device — HMAC computed on-chip |
| Remote attacker with shell as user | Reads key freely | Reads key freely | Blocked — no physical presence for Touch ID | Blocked — needs the PIN | Can unseal if process reaches `/dev/tpmrm0` | Blocked — no physical device to tap |

The DPAPI (Windows) and Secret Service (Linux) implementations are
preserved for reference. Both are replaced by hardware-backed options:
TPM seal on both Windows and Linux.

##### 5. Hardware-backed authentication architecture

All hardware-backed methods share the same core pattern: an opaque
hardware operation gated by authentication produces or releases a key.

| | FIDO2 (hmac-secret) | TPM seal (Windows) | TPM seal (Linux) | Apple Secure Enclave |
|---|---|---|---|---|
| Hardware holds | wrapping_key (permanent, fused) | SRK, via the provider's well-known seal key | SRK (deterministic from well-known template) | Per-item key wrapped by class key derived from hardware UID |
| Client stores on disk | credential_id = Encrypt(wrapping_key, CredRandom) | pcp_sealed_blob.bin (opaque sealed object) | tpm_sealed_blob.bin (Private + Public) | Keychain item (encrypted by per-item key) |
| On use | Device decrypts blob → HMAC(CredRandom, salt) → returns derived key | TPM unseals blob → returns original key | TPM loads sealed blob → TPM2_Unseal → returns key | Secure Enclave unwraps per-item key → decrypts → returns key |
| Authentication gate | PIN (verified on-device, 8 retries) | PIN (TPM authorization value, HKDF-expanded to 32 bytes) | TPM authorization policy | Touch ID (biometric match in Secure Enclave) |
| Secret origin | Generated inside the device (CredRandom) | Generated on the client | Generated on the client | Generated on the client |
| Key leaves hardware? | Never — only HMAC derivative returned | Only during unseal operation | Only during unseal operation | Only during decrypt operation |
