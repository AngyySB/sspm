//! Reading and writing the vault file on disk, in JSON form.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::Context;

use crate::structs::File;

/// Path to the vault file, following the XDG base directory spec
/// ($XDG_DATA_HOME, falling back to ~/.local/share). Creates the
/// containing directory if it doesn't exist yet.
pub fn vault_path() -> anyhow::Result<PathBuf> {
    let data_home = match std::env::var_os("XDG_DATA_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = std::env::var_os("HOME").context("HOME environment variable is not set")?;
            PathBuf::from(home).join(".local/share")
        }
    };

    let dir = data_home.join("sspm");
    fs::create_dir_all(&dir).context("failed to create sspm data directory")?;
    Ok(dir.join("sspm.json"))
}

/// Writes the given vault state to disk as pretty-printed JSON.
pub fn write_json(f: &File) -> anyhow::Result<()> {
    let path = vault_path()?;
    let json = serde_json::to_string_pretty(f)?;
    fs::write(&path, json)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Reads and parses the vault file from disk.
pub fn read_json() -> anyhow::Result<File> {
    let d = fs::read_to_string(vault_path()?)?;
    Ok(serde_json::from_str(&d)?)
}

/// Loads the vault file, with a friendly error message on failure.
pub fn get_json() -> anyhow::Result<File> {
    read_json().context("error reading json")
}
