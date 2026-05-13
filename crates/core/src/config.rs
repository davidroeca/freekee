//! Static configuration loaded from `~/.config/freekee/config.toml`
//! (or the platform equivalent). Currently a single `default_db` key;
//! when more keys arrive, add fields to [`Config`] with serde defaults
//! so older config files still load.
//!
//! Resolution precedence for the database path lives in the CLI: an
//! explicit `--db` arg wins over `$FREEKEE_DB`, which wins over the
//! config file's `default_db`. This module owns only the file read +
//! parse; it does not touch the environment.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Parsed contents of `config.toml`. Unknown keys are silently ignored
/// so adding fields in future versions doesn't break older configs.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub default_db: Option<PathBuf>,
}

impl Config {
    /// Platform-specific path to `config.toml`. Returns `None` if no
    /// config directory is reachable for this user.
    pub fn default_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("freekee").join("config.toml"))
    }

    /// Load the config at `path`. Returns `Config::default()` if the
    /// file doesn't exist. Surfaces an [`Error::Config`] on read or
    /// parse failure so the CLI can print a clear diagnostic.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(crate::Error::Config(format!(
                    "could not read config file {}: {e}",
                    path.display(),
                )));
            }
        };
        toml::from_str::<Self>(&text).map_err(|e| {
            crate::Error::Config(format!(
                "could not parse config file {}: {e}",
                path.display(),
            ))
        })
    }
}
