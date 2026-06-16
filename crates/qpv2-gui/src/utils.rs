//! Shared utility functions.

use qpv2_core::constants::{
    CKB_MAINNET_CODE_HASH, CKB_MAINNET_HASH_TYPE, CKB_TESTNET_CODE_HASH, CKB_TESTNET_HASH_TYPE,
};

/// Converts a hex-encoded wallet lock_args to a CKB address.
///
/// Assumes the wallet's quantum-resistant lock script code_hash / hash_type.
/// Use `script_to_address` for arbitrary external locks instead.
pub(crate) fn lock_args_to_address(
    lock_args: &str,
    is_mainnet: bool,
) -> Result<ckb_sdk::Address, String> {
    use ckb_sdk::{Address, AddressPayload, NetworkType};
    use ckb_types::{bytes::Bytes, core::ScriptHashType};

    let (code_hash_hex, hash_type_str, network) = if is_mainnet {
        (
            CKB_MAINNET_CODE_HASH,
            CKB_MAINNET_HASH_TYPE,
            NetworkType::Mainnet,
        )
    } else {
        (
            CKB_TESTNET_CODE_HASH,
            CKB_TESTNET_HASH_TYPE,
            NetworkType::Testnet,
        )
    };

    let code_hash_bytes = hex::decode(code_hash_hex.trim_start_matches("0x"))
        .map_err(|e| format!("Failed to decode code_hash: {:?}", e))?;
    let mut code_hash_array = [0u8; 32];
    code_hash_array.copy_from_slice(&code_hash_bytes);

    let script_hash_type = match hash_type_str {
        "type" => ScriptHashType::Type,
        "data1" => ScriptHashType::Data1,
        _ => return Err(format!("Unsupported hash_type: {}", hash_type_str)),
    };

    let args_bytes =
        hex::decode(lock_args).map_err(|e| format!("Failed to decode lock_args: {:?}", e))?;

    let payload = AddressPayload::new_full(
        script_hash_type,
        code_hash_array.into(),
        Bytes::from(args_bytes),
    );
    Ok(Address::new(network, payload, true))
}

/// Converts an arbitrary on-chain lock `Script` to its bech32m address string.
///
/// Unlike `lock_args_to_address`, this accepts any lock script (any code_hash /
/// hash_type), so it works for external recipients in the Address Book.
pub(crate) fn script_to_address(script: &ckb_types::packed::Script, is_mainnet: bool) -> String {
    use ckb_sdk::{Address, AddressPayload, NetworkType};

    let network = if is_mainnet {
        NetworkType::Mainnet
    } else {
        NetworkType::Testnet
    };
    let payload = AddressPayload::from(script.clone());
    Address::new(network, payload, true).to_string()
}

/// Format shannons as a numeric CKB string without the unit suffix.
/// Shows up to `decimals` decimal places, trailing zeros trimmed.
pub(crate) fn format_ckb_with_decimals(shannons: u64, decimals: usize) -> String {
    use super::types::CKB_DECIMAL_PLACES;
    let whole = shannons / CKB_DECIMAL_PLACES;
    let frac = shannons % CKB_DECIMAL_PLACES;
    if frac == 0 {
        format!("{}", whole)
    } else {
        let frac_str = format!("{:08}", frac);
        let end = decimals.min(8);
        let trimmed = frac_str[..end].trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    }
}

/// Format shannons as a numeric CKB string, up to 2 decimal places.
pub(crate) fn format_ckb(shannons: u64) -> String {
    format_ckb_with_decimals(shannons, 2)
}

/// Format a number with thousands separators (e.g. `9999` -> `"9,999"`).
pub(crate) fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

/// Format a balance in shannons to a human-readable CKB string.
/// 1 CKB = 100,000,000 shannons.
pub(crate) fn format_ckb_balance(shannons: u64) -> String {
    use super::types::CKB_DECIMAL_PLACES;
    let whole = shannons / CKB_DECIMAL_PLACES;
    let frac = shannons % CKB_DECIMAL_PLACES;
    if frac == 0 {
        format!("{} CKB", format_with_commas(whole))
    } else {
        let frac_str = format!("{:08}", frac);
        format!("{}.{} CKB", format_with_commas(whole), &frac_str[..2])
    }
}

/// Current Unix time in whole seconds (0 if the clock is pre-epoch).
pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a Unix timestamp as relative time ("3h ago", "1d ago").
pub(crate) fn format_relative_time(timestamp_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let diff = now.saturating_sub(timestamp_secs);

    if diff < 60 {
        "just now".to_string()
    } else if diff < 3600 {
        format!("{}m ago", diff / 60)
    } else if diff < 86400 {
        format!("{}h ago", diff / 3600)
    } else {
        format!("{}d ago", diff / 86400)
    }
}
