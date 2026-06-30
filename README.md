# QPV2

Rust Quantum Purse. Secure and Performant. There are 2 UI options: CLI and GUI (egui). Design by human, developed in collaboration with Claude Opus (4.5 / 4.6).

### Crates

- **`qpv2-core`** — Core library. Seed generation, AES-256-GCM encryption, HKDF-SHA256 key derivation, Scrypt password hashing, SPHINCS+ signing across all 12 parameter sets, and file-based JSON storage with multi-wallet support.
- **`qpv2-cli`** — CLI binary built with `clap`. Supports all authentication methods (password, keychain, FIDO2). Multi-wallet management, account derivation, raw signing, and CKB transaction signing.
- **`qpv2-gui`** — GUI binary built with `egui`/`eframe`. Supports all authentication methods. Provides node management, CKB transfers, NervosDAO operations.
- **`keychain`** — Multi-platform credential storage. Touch ID via Data Protection Keychain (macOS), Windows Hello + TPM via Microsoft Passport KSP (Windows), TPM 2.0 seal/unseal with PIN (Linux), and FIDO2 hmac-secret extension for hardware security keys.
- **`node-manager`** — CKB node lifecycle and RPC abstraction.
- **`ckb-fips205-utils`** — CKB transaction hashing utilities for SPHINCS+. Computes `CKB_TX_MESSAGE_ALL` signing message from mock transactions. Feature-gated for verifying, signing, message extraction, and serde support.

### Custom BIP39
BIP39 is chosen as the mnemonic backup format due to its user-friendliness and quantum resistance.

SPHINCS+ offers 12 parameter sets, grouped by three security parameters: 128-bit, 192-bit, and 256-bit. These require seeds of 48 bytes, 72 bytes, and 96 bytes respectively used across key generation and signing. As BIP39 supports max 32 bytes so this library introduces a custom(combined) BIP39 mnemonic backup format for each security parameter of SPHINCS+ as below:

|    SPHINCS+ security parameter      |  BIP39 entropy level  |   Word count    |
|-------------------------------------|-----------------------|-----------------|
|    128 bit ~ 48 bytes ~ 3*16 bytes  |       3*16 bytes      | 3*12 = 36 words |
|    192 bit ~ 72 bytes ~ 3*24 bytes  |       3*24 bytes      | 3*18 = 54 words |
|    256 bit ~ 96 bytes ~ 3*32 bytes  |       3*32 bytes      | 3*24 = 72 words |

###### For example:
- SHA2-256s will require users to back up 72 words of mnemonic phrase.
- SHAKE-192s will require users to back up 54 words of mnemonic phrase.
- SHA2-128f will require users to back up 36 words of mnemonic phrase.

### Key Derivation Function

From the single master seed, quantum-purse-v2 can derive many child keys using Key Derivation Function(KDF). Pure Hash-based KDF is the top choice for this project. Although using [BIP32](https://en.bitcoin.it/wiki/BIP_0032) carefully (with only hardened key derivation and never generate ECDSA public keys) can satisfy however the benefits of the tricky usage at this point(2025) is unclear. Thus, a fresh start with HKDF seems better because it's simpler - meaning the implementation will be easier to audit.

###### Key Tree:
```
master_seed
   ├─ index 0 → sphincs+ key 1
   ├─ index 1 → sphincs+ key 2
   ├─ index 2 → sphincs+ key 3
   └─ ...
```

###### Derivation Flow:
```
master_seed
     │
     ▼
(seed_part1, seed_part2, seed_part3)
     │
     ├─ HKDF("ckb/quantum-purse/sphincs-plus/", index)
     │
     ▼
(sk_seed, sk_prf, pk_seed)
     │
     ├─ sphincs+_key_gen()
     │
     ▼
(sphincs+ public_key, sphincs+ private_key)
```

### Build & Run

Dependencies: Rust & Cargo (1.70+)

All platforms require git submodules before building:
```shell
git clone https://github.com/quantumpurse/quantum-purse-v2.git
cd quantum-purse-v2
git submodule update --init --recursive
```

##### macOS

Build toolchain: `brew install automake gettext && xcode-select --install`

```shell
# CLI
cargo build -p qpv2-cli --release

# GUI (builds, bundles, and optionally signs the .app)
./build.sh <cli|gui> [--release] [--sign] [--clean]   # gui → target/<profile>/qpv2.app
./launch.sh <cli|gui> [--release]
```

##### Linux

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

##### Windows

Build toolchain: Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the "Desktop development with C++" workload (provides the MSVC linker). Then install MSYS2 and in the MSYS2 shell: `pacman -S mingw-w64-x86_64-toolchain automake autoconf libtool make gettext-devel`. Add the MSYS2 mingw64 bin directory (e.g. `C:\msys64\mingw64\bin`) to the system PATH so that `gcc` resolves to the 64-bit toolchain.

```powershell
# CLI
cargo build -p qpv2-cli --release

# GUI
.\crates\qpv2-gui\scripts\bundle-windows.ps1 [-Release]
# → target\<profile>\qpv2-gui-windows-x86_64\  (+ .zip)
```

### Tests

```shell
cargo test --workspace
```

### Use CLI

The CLI supports multiple wallets. The global `--wallet <name>` option selects which wallet to operate on. For `init` and `mnemonic import`, the name is optional — a random name (e.g. "brave-curie") is auto-generated if omitted. For other commands, it auto-selects if only one wallet exists; if multiple wallets exist, it must be specified. Wallets can be renamed later.

```shell
# Show help
qpv2-cli --help
```

Commands that require authentication (export, new account, sign, etc.) auto-detect the wallet's auth method. Password wallets prompt for a password; keychain wallets use the platform's native credential store (Touch ID on macOS, Windows Hello on Windows, TPM on Linux).

### Launch Scripts (macOS only)
```shell
# Launch the dev GUI
./launch.sh gui

# Launch the prod GUI
./launch.sh gui --release
```

On Linux and Windows, run the binary directly from the bundle output directory (see Build & Run above).

### Node Backends

The GUI lets the user pick how the wallet talks to the CKB chain. Each
backend is selectable from the Node Manager tab and persists across
sessions.

| Backend       | What it is                                         | When to use |
|---------------|----------------------------------------------------|-------------|
| **Public RPC**| Remote JSON-RPC endpoint (default).                | Quick start, no local resources. |
| **Light Client** | Local `ckb-light-client` child process; header-only sync, per-script cell index. | Privacy-preserving; modest disk + bandwidth. |
| **Full Node** | Local `ckb` child process; full chain verification, full indexer. | Maximum sovereignty; ~100 GB disk and multi-day sync. |

### Password Input

Password entry in QPV2 happens **outside the wallet's own process** —
through a dedicated, OS-native dialog spawned as a child process. The
wallet binary itself never sees a keystroke during typing; it only
reads the final password from a kernel pipe at the moment the user
submits, copies it once into a zeroize-on-drop `SecureString`, and
drops it the moment the vault op (sign / decrypt / new account)
returns.

### Credential Store Authentication

When a wallet is created with `--keychain` (CLI) or the keychain button
(GUI), a random 32-byte AES key is generated and stored in the
platform's credential store. The encrypted master seed lives on disk;
the credential store only holds the encryption key.

#### macOS — Data Protection Keychain + Secure Enclave

Items are stored in the Data Protection Keychain with
`BiometryCurrentSet` access control. The encryption key (K1) never
leaves the Secure Enclave in plaintext except at the moment it is
returned to the app. The full key hierarchy below is hardware-enforced
— the main CPU never sees any intermediate key.

##### Key hierarchy

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

##### Retrieval flow

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

##### What Apple does not publicly document

The exact nature of the biometric subsystem key (random at enrollment
vs. derived from template hashes), the precise mechanism that binds it
to the enrollment set, and whether the biometric wrapping is per-item
or per-class are not disclosed. The security *properties* above are
documented in the [Apple Platform Security Guide](https://support.apple.com/guide/security/welcome/web);
the internal cryptographic construction is not.

#### Windows — TPM + Windows Hello (Microsoft Passport KSP)

An RSA-2048 key pair is created inside the TPM via the Microsoft
Passport Key Storage Provider. The 32-byte vault encryption key is
encrypted with `NCryptEncrypt` (RSA-OAEP SHA-256) and the ~256-byte
ciphertext is stored to `wrapped_key.bin` on disk. On unlock,
`NCryptDecrypt` triggers a Windows Hello biometric/PIN prompt before
the TPM releases the private key. The RSA private key never leaves
the TPM.

The previous DPAPI Credential Manager implementation is preserved in
`sw_backed/windows_dpapi.rs` for reference.

#### Linux — TPM seal via `tss-esapi`

The 32-byte vault encryption key is sealed under the TPM's Storage
Root Key (SRK) using `TPM2_Create`. A user-chosen PIN is set as the
sealed object's `authValue` during creation and verified on-chip
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

#### Platform comparison

| Scenario | Plain file | DPAPI / Secret Service | Apple Keychain + Touch ID | TPM + Windows Hello | TPM seal | FIDO2 Hardware Key |
|---|---|---|---|---|---|---|
| Malware running as user | Reads key freely | Reads key freely | Blocked — Secure Enclave requires Touch ID per access | Blocked — requires biometric/PIN prompt per access | Blocked — TPM requires authorization policy | Blocked — requires physical device + PIN + tap |
| Another user on same machine | Can read if file permissions allow | Cannot decrypt (tied to user session) | Cannot access (Keychain bound to user + biometric) | Cannot access (TPM key bound to user + biometric) | Cannot access (TPM sealed to user session) | Cannot access — no device, no PIN |
| Stolen disk, booted from USB | Reads key in plaintext | Cannot decrypt without user's login password | Cannot decrypt — key sealed in Secure Enclave hardware | Cannot decrypt — key sealed inside TPM hardware | Cannot decrypt — sealed blob useless without TPM | Cannot decrypt — credential_id blob useless without device |
| Admin with Mimikatz while user logged in | Reads key freely | Can extract DPAPI master key from memory | Key never leaves Secure Enclave in plaintext | Key never leaves TPM in plaintext — nothing to extract | Key never leaves TPM in plaintext | Key never leaves FIDO2 device — HMAC computed on-chip |
| Remote attacker with shell as user | Reads key freely | Reads key freely | Blocked — no physical presence for Touch ID | Blocked — no physical presence for biometric prompt | Can unseal if process reaches `/dev/tpmrm0` | Blocked — no physical device to tap |

The DPAPI (Windows) and Secret Service (Linux) implementations are
preserved for reference. Both are replaced by hardware-backed options:
TPM + Windows Hello on Windows and TPM seal on Linux.

#### Hardware-backed authentication architecture

All hardware-backed methods share the same core pattern: an opaque
hardware operation gated by authentication produces or releases a key.

| | FIDO2 (hmac-secret) | TPM + Windows Hello | TPM seal (Linux) | Apple Secure Enclave |
|---|---|---|---|---|
| Hardware holds | wrapping_key (permanent, fused) | RSA private key (persistent in TPM) | SRK (deterministic from well-known template) | Per-item key wrapped by class key derived from hardware UID |
| Client stores on disk | credential_id = Encrypt(wrapping_key, CredRandom) | wrapped_key.bin = Encrypt(RSA_pub, AES_key) | tpm_sealed_blob.bin (Private + Public) | Keychain item (encrypted by per-item key) |
| On use | Device decrypts blob → HMAC(CredRandom, salt) → returns derived key | TPM decrypts blob → returns original key | TPM loads sealed blob → TPM2_Unseal → returns key | Secure Enclave unwraps per-item key → decrypts → returns key |
| Authentication gate | PIN (verified on-device, 8 retries) | Windows Hello biometric/PIN | TPM authorization policy | Touch ID (biometric match in Secure Enclave) |
| Secret origin | Generated inside the device (CredRandom) | Generated on the client | Generated on the client | Generated on the client |
| Key leaves hardware? | Never — only HMAC derivative returned | Only during unseal operation | Only during unseal operation | Only during decrypt operation |
