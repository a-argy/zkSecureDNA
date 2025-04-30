use anyhow::{Context, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, instrument};

const ENTRY_BYTE_LENGTH: usize = 40;
const HASH_BYTE_LENGTH: usize = 32;
const HLT_FILENAME: &str = "hlt.json";
const BUILD_INFO_FILENAME: &str = "BUILD_INFO.json";
const INDEX_DIR_NAME: &str = "index";

#[derive(Error, Debug)]
pub enum HdbAccError {
    #[error("Invalid entry size in file {0}: expected multiple of {ENTRY_BYTE_LENGTH}, got {1}")]
    InvalidEntrySize(PathBuf, usize),
    #[error("IO Error during HDB processing")]
    IoError(#[from] io::Error),
}

/// Converts a 32-byte hash (typically little-endian) into an Fr element.
/// Uses arkworks' modular reduction.
fn hash_bytes_to_fr(bytes: &[u8; HASH_BYTE_LENGTH]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

/// Iterates through the HDB shard files in the given root directory,
/// reads all entries, extracts the 32-byte hashes, converts them to
/// BLS12-381 scalar field elements (Fr), and returns them as a Vec.
///
/// Skips the 'index' directory, 'hlt.json', 'BUILD_INFO.json', and
/// any files with extensions.
#[instrument(skip(hdb_root_path))]
pub fn load_hdb_hashes_as_scalars(hdb_root_path: impl AsRef<Path>) -> Result<Vec<Fr>> {
    let root = hdb_root_path.as_ref();
    info!(path = %root.display(), "Loading HDB hashes from directory");

    let mut all_scalars = Vec::new();
    let mut shard_paths = Vec::new();

    for entry_result in fs::read_dir(root)
        .with_context(|| format!("Failed to read HDB directory '{}'", root.display()))? {
        let dir_entry = entry_result.with_context(|| "Failed to read directory entry")?;
        let path = dir_entry.path();

        // --- Filtering Logic --- 
        // 1. Skip directories (specifically the 'index' directory)
        if dir_entry.file_type()?.is_dir() {
            if dir_entry.file_name() == INDEX_DIR_NAME {
                debug!(path = %path.display(), "Skipping index directory");
            }
            continue;
        }

        // 2. Skip specific files by name
        if let Some(filename_osstr) = path.file_name() {
            let filename = filename_osstr.to_string_lossy();
            if filename == HLT_FILENAME || filename == BUILD_INFO_FILENAME {
                debug!(path = %path.display(), "Skipping known metadata file");
                continue;
            }
        } else {
            // Should not happen for files, but good practice
            continue; 
        }

        // 3. Skip files with any extension (like .i, .wip, etc.)
        if path.extension().is_some() {
            debug!(path = %path.display(), "Skipping file with extension");
            continue;
        }

        // Assume remaining files are HDB shards (hex names like '00', 'fe')
        shard_paths.push(path);
    }

    // Optional: Sort for deterministic order
    shard_paths.sort();

    info!(count = shard_paths.len(), "Found HDB shard files to process");

    for shard_path in shard_paths {
        debug!(path = %shard_path.display(), "Processing shard file");
        let file = File::open(&shard_path)
            .with_context(|| format!("Failed to open shard file '{}'", shard_path.display()))?;
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)
            .with_context(|| format!("Failed to read shard file '{}'", shard_path.display()))?;

        if buffer.len() % ENTRY_BYTE_LENGTH != 0 {
            return Err(HdbAccError::InvalidEntrySize(shard_path.clone(), buffer.len()).into());
        }

        for chunk in buffer.chunks_exact(ENTRY_BYTE_LENGTH) {
            // Extract the first 32 bytes (hash)
            let hash_bytes: &[u8; HASH_BYTE_LENGTH] = chunk[..HASH_BYTE_LENGTH]
                .try_into()
                .expect("Chunk size is guaranteed to be correct by chunks_exact");

            // Convert to Fr
            let scalar = hash_bytes_to_fr(hash_bytes);
            all_scalars.push(scalar);
        }
    }

    info!(total_hashes = all_scalars.len(), "Finished loading and converting HDB hashes");
    Ok(all_scalars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    // Helper to create a dummy HDB structure for testing
    fn create_test_hdb() -> (tempfile::TempDir, Vec<Fr>) {
        let dir = tempdir().unwrap();
        let mut expected_scalars = Vec::new();

        // Create shard '00'
        let path00 = dir.path().join("00");
        let mut file00 = File::create(&path00).unwrap();
        for i in 0..3 {
            let mut entry = [0u8; ENTRY_BYTE_LENGTH];
            entry[0] = 0x00; // prefix byte
            entry[1] = i;    // make hash unique
            file00.write_all(&entry).unwrap();
            expected_scalars.push(hash_bytes_to_fr(entry[..HASH_BYTE_LENGTH].try_into().unwrap()));
        }

        // Create shard '02'
        let path02 = dir.path().join("02");
        let mut file02 = File::create(&path02).unwrap();
         for i in 10..12 {
            let mut entry = [0u8; ENTRY_BYTE_LENGTH];
            entry[0] = 0x02; // prefix byte
            entry[1] = i;    // make hash unique
            file02.write_all(&entry).unwrap();
            expected_scalars.push(hash_bytes_to_fr(entry[..HASH_BYTE_LENGTH].try_into().unwrap()));
        }

        // Create dummy index dir and files to be ignored
        fs::create_dir(dir.path().join(INDEX_DIR_NAME)).unwrap();
        File::create(dir.path().join(INDEX_DIR_NAME).join("00.i")).unwrap();
        File::create(dir.path().join(HLT_FILENAME)).unwrap();
        File::create(dir.path().join(BUILD_INFO_FILENAME)).unwrap();
        File::create(dir.path().join("some_other_file.txt")).unwrap();

        // Sort expected scalars like the function does (based on file path sort order)
        expected_scalars.sort_by_key(|s| format!("{}", s)); // Approximate sort

        (dir, expected_scalars)
    }

    #[test]
    fn test_load_hdb_hashes() {
        let (hdb_dir, mut expected_scalars) = create_test_hdb();
        let mut loaded_scalars = load_hdb_hashes_as_scalars(hdb_dir.path()).unwrap();

        // Sort both vectors for comparison since hash order within a file is preserved,
        // but the order between files depends on fs::read_dir (which we sort by path)
        loaded_scalars.sort_by_key(|s| format!("{}", s));
        expected_scalars.sort_by_key(|s| format!("{}", s));

        assert_eq!(loaded_scalars.len(), 5);
        assert_eq!(loaded_scalars, expected_scalars);
    }

     #[test]
    fn test_load_hdb_hashes_empty_dir() {
        let dir = tempdir().unwrap();
        let loaded_scalars = load_hdb_hashes_as_scalars(dir.path()).unwrap();
        assert!(loaded_scalars.is_empty());
    }

    #[test]
    fn test_load_hdb_invalid_entry_size() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("00");
        let mut file = File::create(&path).unwrap();
        file.write_all(&[0u8; ENTRY_BYTE_LENGTH - 1]).unwrap(); // Write incomplete entry

        let result = load_hdb_hashes_as_scalars(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err.downcast_ref::<HdbAccError>(), Some(HdbAccError::InvalidEntrySize(_, sz)) if *sz == ENTRY_BYTE_LENGTH - 1));
    }
} 