//! Shared helpers for path templating, binary-name derivation, CLI path validation, and file hashing.

use anyhow::Result;
use std::{
    fs::File,
    hash::Hasher,
    io::{self, Read},
    path::{Path, PathBuf},
};

pub fn existing_file(value: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(value);
    if path.is_file() {
        Ok(path)
    } else if path.exists() {
        Err(format!("`{}` exists but is not a file", path.display()))
    } else {
        Err(format!("file not found `{}`", path.display()))
    }
}

pub fn target_name_from_binary(binary: &Path) -> String {
    binary
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| binary.display().to_string())
}

pub fn render_campaign_path(path: &Path, output_root: &Path, target_name: &str) -> PathBuf {
    let rendered = path
        .display()
        .to_string()
        .replace("{output}", &output_root.display().to_string())
        .replace("{target_name}", target_name);

    PathBuf::from(rendered)
}

pub fn hash_file(path: &Path) -> Result<u64> {
    let mut hasher = twox_hash::XxHash64::with_seed(0);
    let mut file = File::open(path)?;
    let mut buf = [0; 8 * 1024];

    loop {
        match file.read(&mut buf) {
            Ok(0) => return Ok(hasher.finish()),
            Ok(n) => hasher.write(&buf[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
}
