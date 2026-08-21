use assert_cmd::Command;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const PASSWORD: &str = "CorrectHorseBatteryStaple!2026";

struct CliSandbox {
    home: TempDir,
    data_home: TempDir,
}

impl CliSandbox {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().expect("create temporary HOME"),
            data_home: tempfile::tempdir().expect("create temporary data dir"),
        }
    }

    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("qpv2-cli").expect("qpv2-cli binary");
        cmd.env("HOME", self.home.path())
            .env("XDG_DATA_HOME", self.data_home.path())
            .env("APPDATA", self.data_home.path())
            .env("LOCALAPPDATA", self.data_home.path());
        cmd
    }

    fn wallet_dir(&self, id: u32) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.home
                .path()
                .join("Library/Application Support/quantum-purse/wallets")
                .join(id.to_string())
        } else if cfg!(target_os = "windows") {
            self.data_home
                .path()
                .join("quantum-purse/wallets")
                .join(id.to_string())
        } else {
            self.data_home
                .path()
                .join("quantum-purse/wallets")
                .join(id.to_string())
        }
    }
}

fn run_success(sandbox: &CliSandbox, args: &[&str], stdin: &str) -> String {
    let output = sandbox
        .cmd()
        .args(args)
        .write_stdin(stdin)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).expect("stdout is utf-8")
}

fn run_failure(sandbox: &CliSandbox, args: &[&str], stdin: &str) -> String {
    let output = sandbox
        .cmd()
        .args(args)
        .write_stdin(stdin)
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    String::from_utf8(output).expect("stderr is utf-8")
}

fn password_input(times: usize) -> String {
    std::iter::repeat(PASSWORD)
        .take(times)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn extract_lock_args(output: &str) -> String {
    let value = output
        .lines()
        .find_map(|line| line.split_once("Identifier(CKB quantum lock script args): "))
        .map(|(_, lock_args)| lock_args.trim())
        .expect("account identifier in output");

    assert_eq!(value.len(), 64);
    assert!(
        value.chars().all(|c| c.is_ascii_hexdigit()),
        "lock args must be hex: {value}"
    );

    value.to_string()
}

fn extract_field(output: &str, prefix: &str) -> String {
    output
        .lines()
        .find_map(|line| line.split_once(prefix))
        .map(|(_, value)| value)
        .map(str::trim)
        .expect("field in output")
        .to_string()
}

#[test]
fn wallet_list_starts_empty_in_isolated_data_dir() {
    let sandbox = CliSandbox::new();

    let output = run_success(&sandbox, &["wallet", "list"], "");

    assert!(output.contains("No wallets found"));
}

#[test]
fn init_wallet_creates_isolated_file_vault_and_lists_metadata() {
    let sandbox = CliSandbox::new();

    let init_output = run_success(
        &sandbox,
        &["--wallet", "alpha", "init", "--variant", "Sha2128S"],
        &password_input(2),
    );

    assert!(init_output.contains("Initializing wallet 'alpha'"));
    assert!(init_output.contains("Required mnemonic words: 36"));
    assert!(init_output.contains("Master seed generated successfully"));

    let wallet_dir = sandbox.wallet_dir(0);
    assert!(wallet_dir.join("seed.json").exists());
    assert!(wallet_dir.join("meta.json").exists());

    let list_output = run_success(&sandbox, &["wallet", "list"], "");
    assert!(list_output.contains("[0] alpha"));
    assert!(list_output.contains("Variant               : Sha2128S"));
    assert!(list_output.contains("Authentication        : Password"));
    assert!(list_output.contains("Single-sig convention : Standard"));
    assert!(list_output.contains("Accounts              : 0"));
}

#[test]
fn account_sign_verify_and_wallet_rename_round_trip() {
    let sandbox = CliSandbox::new();

    run_success(
        &sandbox,
        &["--wallet", "alpha", "init", "--variant", "Sha2128S"],
        &password_input(2),
    );

    let account_output = run_success(
        &sandbox,
        &["--wallet", "alpha", "account", "new"],
        &password_input(1),
    );
    let lock_args = extract_lock_args(&account_output);

    let list_output = run_success(&sandbox, &["--wallet", "alpha", "account", "list"], "");
    assert!(list_output.contains("Single-sig (1):"));
    assert!(list_output.contains(&lock_args));

    let sign_output = run_success(
        &sandbox,
        &[
            "--wallet",
            "alpha",
            "sign",
            "--identifier",
            &lock_args,
            "--message",
            "deadbeef",
        ],
        &password_input(1),
    );
    let signature = extract_field(&sign_output, "Signature:");
    let public_key = extract_field(&sign_output, "Public Key:");
    assert!(!signature.is_empty());
    assert!(!public_key.is_empty());

    let verify_output = run_success(
        &sandbox,
        &[
            "verify",
            "--variant",
            "Sha2128S",
            "--public-key",
            &public_key,
            "--message",
            "deadbeef",
            "--signature",
            &signature,
        ],
        "",
    );
    assert!(verify_output.contains("Signature is valid"));

    let renamed = run_success(
        &sandbox,
        &["--wallet", "alpha", "wallet", "rename", "--to", "beta"],
        "",
    );
    assert!(renamed.contains("Wallet renamed from 'alpha' to 'beta'"));

    let wallet_list = run_success(&sandbox, &["wallet", "list"], "");
    assert!(wallet_list.contains("[0] beta"));
    assert!(!wallet_list.contains("[0] alpha"));
}

#[test]
fn mnemonic_export_import_and_v1_legacy_convention_are_covered() {
    let sandbox = CliSandbox::new();

    run_success(
        &sandbox,
        &["--wallet", "standard", "init", "--variant", "Sha2128S"],
        &password_input(2),
    );
    let seed_path = sandbox.home.path().join("seed.txt");
    let seed_path_string = seed_path.to_string_lossy().into_owned();
    run_success(
        &sandbox,
        &[
            "--wallet",
            "standard",
            "mnemonic",
            "export",
            "--output",
            &seed_path_string,
        ],
        &password_input(1),
    );
    assert!(seed_path.exists());
    assert_eq!(
        std::fs::read_to_string(&seed_path)
            .expect("read seed phrase")
            .split_whitespace()
            .count(),
        36
    );

    run_success(
        &sandbox,
        &[
            "--wallet",
            "legacy",
            "mnemonic",
            "import",
            "--variant",
            "Sha2128S",
            "--seed-file",
            &seed_path_string,
            "--v1",
        ],
        &password_input(2),
    );

    let wallet_list = run_success(&sandbox, &["wallet", "list"], "");
    assert!(wallet_list.contains("[0] standard"));
    assert!(wallet_list.contains("[1] legacy"));
    assert!(wallet_list.contains("Single-sig convention : Standard"));
    assert!(wallet_list.contains("Single-sig convention : V1"));

    let standard_account = run_success(
        &sandbox,
        &["--wallet", "standard", "account", "new"],
        &password_input(1),
    );
    let legacy_account = run_success(
        &sandbox,
        &["--wallet", "legacy", "account", "new"],
        &password_input(1),
    );

    let standard_lock_args = extract_lock_args(&standard_account);
    let legacy_lock_args = extract_lock_args(&legacy_account);
    assert_ne!(
        standard_lock_args, legacy_lock_args,
        "v1 imports must preserve the legacy single-sig address convention"
    );
}

#[test]
fn duplicate_wallet_name_and_password_mismatch_fail_cleanly() {
    let sandbox = CliSandbox::new();

    run_success(
        &sandbox,
        &["--wallet", "alpha", "init", "--variant", "Sha2128S"],
        &password_input(2),
    );

    let duplicate = run_failure(
        &sandbox,
        &["--wallet", "alpha", "init", "--variant", "Sha2128S"],
        &password_input(2),
    );
    assert!(duplicate.contains("Wallet 'alpha' already exists."));

    let mismatch = run_failure(
        &sandbox,
        &["--wallet", "mismatch", "init", "--variant", "Sha2128S"],
        &format!("{PASSWORD}\n{PASSWORD}x\n"),
    );
    assert!(mismatch.contains("Passwords do not match"));
    assert!(!wallet_exists(&sandbox.wallet_dir(1)));
}

fn wallet_exists(path: &Path) -> bool {
    path.exists()
}
