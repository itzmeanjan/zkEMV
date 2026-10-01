//! Prepares ProveKit keys for the app: `prepare-keys <out-dir> <circuit.json>...` writes
//! `<out-dir>/<stem>.pkp` and `<out-dir>/<stem>.pkv` for each compiled circuit.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let out = PathBuf::from(args.next().context("usage: prepare-keys <out-dir> <circuit.json>...")?);
    std::fs::create_dir_all(&out)?;
    for circuit in args.map(PathBuf::from) {
        let stem = circuit.file_stem().context("circuit path without a file name")?;
        let (pk, vk) = emv::prepare(&std::fs::read(&circuit).with_context(|| circuit.display().to_string())?)?;
        write(&out.join(stem).with_extension("pkp"), &pk.to_bytes()?)?;
        write(&out.join(stem).with_extension("pkv"), &vk.to_bytes()?)?;
    }
    Ok(())
}

fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| path.display().to_string())
}
