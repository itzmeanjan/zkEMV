//! Writes everything generated from the synthetic taps: the circuits' fixtures and each
//! circuit's test vectors. Run by `make fixtures`.

mod inputs;
mod layout;
mod merkle;
mod rsa;
mod synthetic;

use std::{fs, path::PathBuf};

use num_bigint::BigUint;
use rand_chacha::{ChaCha20Rng, rand_core::RngCore};

use inputs::Inputs;
use synthetic::KINDS;

/// Named in the generated files.
const GENERATOR: &str = "emv/tests/fixtures";

/// Seeded, so the generated files are the same on every run and platform.
type Rng = ChaCha20Rng;

fn repository() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/.."))
}

fn generate() -> Vec<(PathBuf, String)> {
    let circuits = repository().join("circuits");
    let fixtures = circuits.join("fixtures");
    let ca_keys = fs::read(repository().join("data/certificate-authority-public-keys.json")).unwrap();
    let generated = synthetic::generate(&ca_keys);

    let mut files: Vec<(PathBuf, String)> = KINDS
        .iter()
        .zip(&generated.taps)
        .map(|(kind, tap)| (fixtures.join(format!("{}.json", kind.package)), tap.json.clone()))
        .collect();
    files.push((fixtures.join("test-ca-keys.json"), generated.ca_table.clone()));
    files.push((fixtures.join("bin-table.json"), generated.bin_table.clone()));

    for (kind, tap) in KINDS.iter().zip(&generated.taps) {
        let package = circuits.join(kind.package);
        let static_data_capacity = circuit_global(&package, "STATIC_DATA_MAX_BYTE_LEN");
        let inputs = Inputs::new(kind, tap, &generated.ca_modulus, &generated.bin_table, static_data_capacity);
        files.push((package.join("src/tests/vectors.nr"), inputs.to_noir()));
    }
    files
}

#[test]
#[ignore = "rewrites tracked files; run by `make fixtures`"]
fn generate_fixtures() {
    for (path, contents) in generate() {
        fs::write(path, contents).unwrap();
    }
}

/// A `u32` global declared in the circuit's main file.
fn circuit_global(package: &std::path::Path, name: &str) -> usize {
    let main = fs::read_to_string(package.join("src/main.nr")).unwrap();
    let declaration = format!("global {name}: u32 = ");
    main.lines()
        .find_map(|line| line.strip_prefix(&declaration)?.strip_suffix(';')?.parse().ok())
        .unwrap_or_else(|| panic!("{}: no global {name}", package.display()))
}

/// Big-endian, left-padded to `byte_len`.
fn be_bytes(n: &BigUint, byte_len: usize) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    [vec![0; byte_len - bytes.len()], bytes].concat()
}

fn random_bytes(rng: &mut Rng, byte_len: usize) -> Vec<u8> {
    let mut bytes = vec![0; byte_len];
    rng.fill_bytes(&mut bytes);
    bytes
}
