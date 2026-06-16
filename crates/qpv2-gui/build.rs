//! Stages the platform-appropriate pinentry binary into
//! `target/{debug,release}/` so that `pinentry::pinentry_path()`
//! resolves it at runtime via `current_exe().parent()`.
//!
//! Source: `vendor/pinentry-build/{OS}-{ARCH}/` produced by
//! `vendor/build-pinentry.sh`. If missing, emits a build warning —
//! the GUI compiles but the password flow will error at runtime.

#[cfg(target_os = "macos")]
use std::path::Path;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(target_os = "macos")]
    stage_pinentry_macos();

    #[cfg(target_os = "linux")]
    stage_pinentry_linux();

    #[cfg(target_os = "windows")]
    {
        stage_pinentry_windows();

        // Embed the app icon into the .exe (Explorer file icon + the
        // default taskbar icon). Path is relative to this crate's root.
        println!("cargo:rerun-if-changed=../../assets/icon/icon.ico");
        winresource::WindowsResource::new()
            .set_icon("../../assets/icon/icon.ico")
            .compile()
            .expect("embed Windows app icon");
    }
}

fn profile_dir() -> Option<PathBuf> {
    let out_dir = std::env::var_os("OUT_DIR")?;
    let out = PathBuf::from(out_dir);
    out.ancestors().nth(3).map(|d| d.to_path_buf())
}

fn workspace_root() -> Option<PathBuf> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let manifest_path = PathBuf::from(manifest);
    manifest_path.parent()?.parent().map(|p| p.to_path_buf())
}

/// Maps Rust's `std::env::consts::ARCH` to `uname -m` output
/// used by `vendor/build-pinentry.sh` for the build directory name.
fn uname_arch() -> &'static str {
    match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        other => other,
    }
}

#[cfg(target_os = "macos")]
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if ty.is_symlink() {
            let target = std::fs::read_link(&from)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &to)?;
            #[cfg(not(unix))]
            {
                let _ = target;
            }
        } else {
            std::fs::copy(&from, &to)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perm = std::fs::metadata(&to)?.permissions();
                perm.set_mode(perm.mode() | 0o200);
                std::fs::set_permissions(&to, perm)?;
            }
        }
    }
    Ok(())
}

// ─── macOS ────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn stage_pinentry_macos() {
    let profile = match profile_dir() {
        Some(d) => d,
        None => return,
    };
    let root = match workspace_root() {
        Some(r) => r,
        None => return,
    };

    let vendor_app = root
        .join("vendor")
        .join("pinentry-build")
        .join(format!("Darwin-{}", uname_arch()))
        .join("pinentry-mac.app");

    if !vendor_app.exists() {
        println!(
            "cargo:warning=pinentry-mac.app not found at {}. \
			 Run `vendor/build-pinentry.sh` first.",
            vendor_app.display()
        );
        return;
    }

    let dst = profile.join("pinentry-mac.app");
    let _ = std::fs::remove_dir_all(&dst);
    if let Err(e) = copy_dir_recursive(&vendor_app, &dst) {
        println!(
            "cargo:warning=Failed to copy vendor pinentry-mac.app: {}",
            e
        );
    }
}

// ─── Linux ────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn stage_pinentry_linux() {
    let profile = match profile_dir() {
        Some(d) => d,
        None => return,
    };
    let root = match workspace_root() {
        Some(r) => r,
        None => return,
    };

    let vendor_bin = root
        .join("vendor")
        .join("pinentry-build")
        .join(format!("Linux-{}", uname_arch()))
        .join("pinentry-gtk-2");

    if !vendor_bin.exists() {
        println!(
            "cargo:warning=pinentry-gtk-2 not found at {}. \
			 Run `vendor/build-pinentry.sh` first.",
            vendor_bin.display()
        );
        return;
    }

    let dst = profile.join("pinentry-gtk-2");
    let _ = std::fs::remove_file(&dst);
    if let Err(e) = std::fs::copy(&vendor_bin, &dst) {
        println!("cargo:warning=Failed to copy vendor pinentry-gtk-2: {}", e);
    }
}

// ─── Windows ──────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn stage_pinentry_windows() {
    let profile = match profile_dir() {
        Some(d) => d,
        None => return,
    };
    let root = match workspace_root() {
        Some(r) => r,
        None => return,
    };

    let vendor_bin = root
        .join("vendor")
        .join("pinentry-build")
        .join(format!("MINGW64_NT-{}", uname_arch()))
        .join("pinentry-w32.exe");

    if !vendor_bin.exists() {
        println!(
            "cargo:warning=pinentry-w32.exe not found at {}. \
			 Run `vendor/build-pinentry.sh` first.",
            vendor_bin.display()
        );
        return;
    }

    let dst = profile.join("pinentry-w32.exe");
    let _ = std::fs::remove_file(&dst);
    if let Err(e) = std::fs::copy(&vendor_bin, &dst) {
        println!(
            "cargo:warning=Failed to copy vendor pinentry-w32.exe: {}",
            e
        );
    }
}
