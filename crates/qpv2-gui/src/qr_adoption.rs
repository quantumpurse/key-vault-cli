//! Cache for the chain-derived QR-lock adoption series, one file per
//! network. The series is rebuilt from the indexer on a slow cadence;
//! the cache exists so the dashboard renders the last known chart
//! immediately on launch instead of "LOADING HISTORY".

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct QrAdoptionCache {
    /// `(unix_seconds, total_shannons)` weekly points, oldest first.
    pub series: Vec<(u64, u64)>,
}

fn cache_path(network_tag: &str) -> Result<PathBuf, String> {
    let dir = qpv2_core::db::get_data_dir().map_err(|e| format!("data dir: {}", e))?;
    Ok(dir.join(format!("qr_adoption_{}.json", network_tag)))
}

impl QrAdoptionCache {
    pub fn load(network_tag: &str) -> Result<Option<Self>, String> {
        let path = cache_path(network_tag)?;
        if !path.exists() {
            return Ok(None);
        }
        let mut buf = String::new();
        File::open(&path)
            .map_err(|e| format!("open: {}", e))?
            .read_to_string(&mut buf)
            .map_err(|e| format!("read: {}", e))?;
        let cache: Self = serde_json::from_str(&buf).map_err(|e| format!("parse: {}", e))?;
        Ok(Some(cache))
    }

    /// Atomic write (tmp + rename) so a crash mid-save can't truncate
    /// the cache.
    pub fn save(&self, network_tag: &str) -> Result<(), String> {
        let final_path = cache_path(network_tag)?;
        let tmp_path = final_path.with_extension("json.tmp");
        let json = serde_json::to_string(self).map_err(|e| format!("serialize: {}", e))?;
        {
            let mut file = File::create(&tmp_path).map_err(|e| format!("create tmp: {}", e))?;
            file.write_all(json.as_bytes())
                .map_err(|e| format!("write: {}", e))?;
        }
        fs::rename(&tmp_path, &final_path).map_err(|e| format!("rename: {}", e))?;
        Ok(())
    }
}

/// Loads the cached series for `network_tag`, logging (not hiding)
/// failures — a stale-schema or corrupt cache should be visible in the
/// log, not a silent mystery. Returns empty on any failure.
pub(crate) fn load_series(network_tag: &str) -> Vec<(u64, u64)> {
    match QrAdoptionCache::load(network_tag) {
        Ok(Some(cache)) => cache.series,
        Ok(None) => Vec::new(),
        Err(e) => {
            tracing::warn!("qr adoption: cache load ({}): {}", network_tag, e);
            Vec::new()
        }
    }
}

/// Persists `series` for `network_tag`, logging failures.
pub(crate) fn save_series(network_tag: &str, series: &[(u64, u64)]) {
    let cache = QrAdoptionCache {
        series: series.to_vec(),
    };
    if let Err(e) = cache.save(network_tag) {
        tracing::error!("qr adoption: cache save ({}): {}", network_tag, e);
    }
}
