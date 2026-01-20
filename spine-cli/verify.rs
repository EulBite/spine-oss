// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Eul Bite

//! Independent WAL verification without trusting Spine server.
//!
//! Reads WAL files directly from disk and verifies:
//! - Hash chain integrity (each event links to previous)
//! - Signature validity (Ed25519)
//! - Sequence continuity (no gaps)
//! - Timestamp monotonicity
//!
//! ## Signature Contract
//!
//! The WAL signer MUST sign `compute_entry_hash(entry)`, which includes:
//! - sequence (u64 LE bytes)
//! - timestamp_ns (i64 LE bytes)
//! - prev_hash (UTF-8 bytes)
//! - payload_hash (UTF-8 bytes)
//!
//! Any change to this contract requires updating both the signer and verifier.

use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::Path;
use thiserror::Error;

// Shared types - single source of truth for hash computation
use crate::wal_types::{
    collect_wal_segments, compute_entry_hash, validate_entry_hashes, WalEntry, GENESIS_PREV_HASH,
};

#[derive(Error, Debug)]
pub enum VerifyError {
    #[error("IO error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("Parse error in {file} line {line}: {details}")]
    Parse {
        file: String,
        line: usize,
        details: String,
    },

    #[error("Chain break at sequence {sequence}: expected {expected}, found {found}")]
    ChainBreak {
        sequence: u64,
        expected: String,
        found: String,
    },

    #[error("Invalid signature at sequence {sequence}")]
    InvalidSignature { sequence: u64 },

    #[error("Sequence gap: missing {missing} after {previous}")]
    SequenceGap { previous: u64, missing: u64 },

    #[error("Timestamp regression at sequence {sequence}: {previous} -> {current}")]
    TimestampRegression {
        sequence: u64,
        previous: i64,
        current: i64,
    },

    #[error("Root hash mismatch: expected {expected}, computed {computed}")]
    RootMismatch { expected: String, computed: String },

    #[error("Invalid genesis: prev_hash should be {expected}, found {found}")]
    InvalidGenesis { expected: String, found: String },

    #[error("Invalid hash format at sequence {sequence}: {details}")]
    InvalidHashFormat { sequence: u64, details: String },
}

impl VerifyError {
    /// Convert to VerificationError for accumulation in results
    fn to_verification_error(&self, sequence: Option<u64>) -> VerificationError {
        let error_type = match self {
            VerifyError::Io { .. } => "io_error",
            VerifyError::Parse { .. } => "parse_error",
            VerifyError::ChainBreak { .. } => "chain_break",
            VerifyError::InvalidSignature { .. } => "invalid_signature",
            VerifyError::SequenceGap { .. } => "sequence_gap",
            VerifyError::TimestampRegression { .. } => "timestamp_regression",
            VerifyError::RootMismatch { .. } => "root_mismatch",
            VerifyError::InvalidGenesis { .. } => "invalid_genesis",
            VerifyError::InvalidHashFormat { .. } => "invalid_hash_format",
        };

        VerificationError {
            sequence,
            error_type: error_type.to_string(),
            details: self.to_string(),
        }
    }
}

/// Result of verification operation
#[derive(Debug, Serialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub events_verified: u64,
    pub signatures_verified: u64,
    pub chain_root: String,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub first_timestamp: Option<i64>,
    pub last_timestamp: Option<i64>,
    pub errors: Vec<VerificationError>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct VerificationError {
    pub sequence: Option<u64>,
    pub error_type: String,
    pub details: String,
}

pub fn run(
    wal_path: &Path,
    expected_root: Option<&str>,
    output_path: Option<&Path>,
    fail_fast: bool,
    format: crate::OutputFormat,
) -> Result<bool, Box<dyn std::error::Error>> {
    let result = verify_wal(wal_path, expected_root, fail_fast)?;

    // Output based on format preference
    match format {
        crate::OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        crate::OutputFormat::Text => {
            if let Some(output) = output_path {
                let json = serde_json::to_string_pretty(&result)?;
                fs::write(output, json)?;
            } else {
                print_result(&result);
            }
        }
        crate::OutputFormat::Quiet => {
            // Write to file if specified, otherwise just return exit code
            if let Some(output) = output_path {
                let json = serde_json::to_string_pretty(&result)?;
                fs::write(output, json)?;
            }
        }
    }

    Ok(result.valid)
}

fn verify_wal(
    wal_path: &Path,
    expected_root: Option<&str>,
    fail_fast: bool,
) -> Result<VerificationResult, VerifyError> {
    let mut result = VerificationResult {
        valid: true,
        events_verified: 0,
        signatures_verified: 0,
        chain_root: String::new(),
        first_sequence: None,
        last_sequence: None,
        first_timestamp: None,
        last_timestamp: None,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    let segments = collect_segments(wal_path)?;

    if segments.is_empty() {
        result.warnings.push("No WAL segments found".to_string());
        return Ok(result);
    }

    let mut prev_hash: Option<String> = None;
    let mut prev_sequence: Option<u64> = None;
    let mut prev_timestamp: Option<i64> = None;
    let mut running_hash = Hasher::new();

    for segment_path in &segments {
        let file = File::open(segment_path).map_err(|e| VerifyError::Io {
            path: segment_path.display().to_string(),
            source: e,
        })?;

        let reader = BufReader::new(file);

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.map_err(|e| VerifyError::Io {
                path: segment_path.display().to_string(),
                source: e,
            })?;

            if line.trim().is_empty() {
                continue;
            }

            let entry: WalEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(e) => {
                    let parse_err = VerifyError::Parse {
                        file: segment_path.display().to_string(),
                        line: line_num + 1,
                        details: e.to_string(),
                    };
                    if fail_fast {
                        return Err(parse_err);
                    }
                    // Accumulate error and continue to next line
                    result.errors.push(parse_err.to_verification_error(None));
                    result.valid = false;
                    continue;
                }
            };

            if result.first_sequence.is_none() {
                result.first_sequence = Some(entry.sequence);
                result.first_timestamp = Some(entry.timestamp_ns);
            }
            result.last_sequence = Some(entry.sequence);
            result.last_timestamp = Some(entry.timestamp_ns);

            if prev_hash.is_none() {
                if entry.sequence != 1 {
                    let err = VerifyError::InvalidGenesis {
                        expected: format!("sequence=1, prev_hash={}", &GENESIS_PREV_HASH[..16]),
                        found: format!("sequence={}", entry.sequence),
                    };
                    if fail_fast {
                        return Err(err);
                    }
                    result
                        .errors
                        .push(err.to_verification_error(Some(entry.sequence)));
                    result.valid = false;
                }
                if entry.prev_hash != GENESIS_PREV_HASH {
                    let err = VerifyError::InvalidGenesis {
                        expected: GENESIS_PREV_HASH.to_string(),
                        found: entry.prev_hash.clone(),
                    };
                    if fail_fast {
                        return Err(err);
                    }
                    result
                        .errors
                        .push(err.to_verification_error(Some(entry.sequence)));
                    result.valid = false;
                }
            }

            if let Some(ref expected_prev) = prev_hash {
                if entry.prev_hash != *expected_prev {
                    let err = VerifyError::ChainBreak {
                        sequence: entry.sequence,
                        expected: expected_prev.clone(),
                        found: entry.prev_hash.clone(),
                    };
                    if fail_fast {
                        return Err(err);
                    }
                    result
                        .errors
                        .push(err.to_verification_error(Some(entry.sequence)));
                    result.valid = false;
                }
            }

            if let Some(prev_seq) = prev_sequence {
                if entry.sequence != prev_seq + 1 {
                    let err = VerifyError::SequenceGap {
                        previous: prev_seq,
                        missing: prev_seq + 1,
                    };
                    if fail_fast {
                        return Err(err);
                    }
                    result
                        .errors
                        .push(err.to_verification_error(Some(entry.sequence)));
                    result.valid = false;
                }
            }

            if let Some(prev_ts) = prev_timestamp {
                if entry.timestamp_ns < prev_ts {
                    let err = VerifyError::TimestampRegression {
                        sequence: entry.sequence,
                        previous: prev_ts,
                        current: entry.timestamp_ns,
                    };
                    if fail_fast {
                        return Err(err);
                    }
                    result
                        .errors
                        .push(err.to_verification_error(Some(entry.sequence)));
                    result.valid = false;
                }
            }

            if let (Some(sig_hex), Some(pk_hex)) = (&entry.signature, &entry.public_key) {
                match verify_signature(&entry, sig_hex, pk_hex) {
                    Ok(true) => result.signatures_verified += 1,
                    Ok(false) | Err(_) => {
                        let err = VerifyError::InvalidSignature {
                            sequence: entry.sequence,
                        };
                        if fail_fast {
                            return Err(err);
                        }
                        result
                            .errors
                            .push(err.to_verification_error(Some(entry.sequence)));
                        result.valid = false;
                    }
                }
            }

            // Validate hash field formats (BLAKE3 = 64 hex chars, Ed25519 sig = 128 hex)
            // This runs after semantic checks (genesis, chain, timestamp) to prioritize those errors
            let hash_errors = validate_entry_hashes(&entry);
            if !hash_errors.is_empty() {
                for error_msg in hash_errors {
                    let err = VerifyError::InvalidHashFormat {
                        sequence: entry.sequence,
                        details: error_msg,
                    };
                    if fail_fast {
                        return Err(err);
                    }
                    result
                        .errors
                        .push(err.to_verification_error(Some(entry.sequence)));
                    result.valid = false;
                }
            }

            let entry_hash = compute_entry_hash(&entry);
            running_hash.update(entry_hash.as_bytes());
            prev_hash = Some(entry_hash);
            prev_sequence = Some(entry.sequence);
            prev_timestamp = Some(entry.timestamp_ns);
            result.events_verified += 1;
        }
    }

    result.chain_root = hex::encode(running_hash.finalize().as_bytes());

    if let Some(expected) = expected_root {
        let normalized = expected
            .trim()
            .strip_prefix("0x")
            .unwrap_or(expected.trim())
            .to_lowercase();

        if result.chain_root != normalized {
            let err = VerifyError::RootMismatch {
                expected: normalized,
                computed: result.chain_root.clone(),
            };
            if fail_fast {
                return Err(err);
            }
            result.errors.push(err.to_verification_error(None));
            result.valid = false;
        }
    } else if result.events_verified > 0 {
        // Warn when no expected root provided - only internal consistency was verified
        result.warnings.push(
            "No expected root provided: verified internal consistency only. \
             For full tamper-detection, compare chain_root against an external anchor."
                .to_string(),
        );
    }

    Ok(result)
}

fn collect_segments(wal_path: &Path) -> Result<Vec<std::path::PathBuf>, VerifyError> {
    collect_wal_segments(wal_path).map_err(|e| VerifyError::Io {
        path: wal_path.display().to_string(),
        source: e,
    })
}

/// Verify Ed25519 signature on entry hash.
///
/// The signature must be over `compute_entry_hash(entry)` - see wal_types module.
///
/// # Why We Verify Against Entry Hash (not payload)
///
/// The signer commits to entry_hash = H(seq || ts || prev_hash || payload_hash).
/// This means a valid signature proves:
/// 1. The signer knew the exact sequence position (no reordering)
/// 2. The signer knew the timestamp (no backdating after the fact)
/// 3. The signer knew the chain state (prev_hash binds all history)
/// 4. The signer knew the payload (payload_hash)
///
/// A signature over just payload_hash would allow replay: copy a signed payload
/// to a different position in the chain with a new sequence number.
fn verify_signature(entry: &WalEntry, sig_hex: &str, pk_hex: &str) -> Result<bool, VerifyError> {
    let sig_bytes = hex::decode(sig_hex).map_err(|_| VerifyError::InvalidSignature {
        sequence: entry.sequence,
    })?;

    let pk_bytes = hex::decode(pk_hex).map_err(|_| VerifyError::InvalidSignature {
        sequence: entry.sequence,
    })?;

    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::InvalidSignature {
            sequence: entry.sequence,
        })?;

    let pk_array: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidSignature {
            sequence: entry.sequence,
        })?;

    let verifying_key =
        VerifyingKey::from_bytes(&pk_array).map_err(|_| VerifyError::InvalidSignature {
            sequence: entry.sequence,
        })?;

    // Message is the entry hash - this MUST match what the signer signs
    let message = compute_entry_hash(entry);
    Ok(verifying_key.verify(message.as_bytes(), &signature).is_ok())
}

fn print_result(result: &VerificationResult) {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║              SPINE WAL VERIFICATION REPORT                   ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    let status = if result.valid {
        "✓ VALID"
    } else {
        "✗ INVALID"
    };
    let status_color = if result.valid { "\x1b[32m" } else { "\x1b[31m" };
    println!("║  Status: {status_color}{status}\x1b[0m");
    println!("║  Events verified: {}", result.events_verified);
    println!("║  Signatures verified: {}", result.signatures_verified);

    if let (Some(first), Some(last)) = (result.first_sequence, result.last_sequence) {
        println!("║  Sequence range: {first} - {last}");
    }

    // Guard against empty chain_root (defensive, shouldn't happen with events)
    if result.chain_root.len() >= 16 {
        println!("║  Chain root: {}...", &result.chain_root[..16]);
    } else if !result.chain_root.is_empty() {
        println!("║  Chain root: {}", result.chain_root);
    }

    println!("╠══════════════════════════════════════════════════════════════╣");

    if !result.errors.is_empty() {
        println!("║  ERRORS:");
        for err in &result.errors {
            let seq = err
                .sequence
                .map(|s| s.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!("║    [seq {}] {}: {}", seq, err.error_type, err.details);
        }
    }

    if !result.warnings.is_empty() {
        println!("║  WARNINGS:");
        for warn in &result.warnings {
            println!("║    ⚠ {warn}");
        }
    }

    println!("╚══════════════════════════════════════════════════════════════╝\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal_types::compute_entry_hash;
    use std::io::Write;
    use tempfile::TempDir;

    /// Create a valid test entry with proper 64-char hex payload hash.
    /// If payload_hash is shorter than 64 chars, it's padded to form a valid hash.
    fn create_entry(
        sequence: u64,
        timestamp_ns: i64,
        prev_hash: &str,
        payload_hash: &str,
    ) -> String {
        // Ensure payload_hash is a valid 64-char hex string for testing
        let valid_payload = if payload_hash.len() < 64 {
            format!(
                "{:0<64}",
                payload_hash
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect::<String>()
            )
        } else {
            payload_hash.to_string()
        };
        serde_json::json!({
            "sequence": sequence,
            "timestamp_ns": timestamp_ns,
            "prev_hash": prev_hash,
            "payload_hash": valid_payload
        })
        .to_string()
    }

    /// Helper to compute hash for test data - uses shared implementation
    fn compute_test_entry_hash(
        sequence: u64,
        timestamp_ns: i64,
        prev_hash: &str,
        payload_hash: &str,
    ) -> String {
        // Use same padding logic as create_entry for consistency
        let valid_payload = if payload_hash.len() < 64 {
            format!(
                "{:0<64}",
                payload_hash
                    .chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect::<String>()
            )
        } else {
            payload_hash.to_string()
        };
        let entry = WalEntry {
            format_version: 1,
            sequence,
            timestamp_ns,
            prev_hash: prev_hash.to_string(),
            payload_hash: valid_payload,
            event_type: None,
            source: None,
            signature: None,
            public_key: None,
            key_id: None,
            event_id: None,
            stream_id: None,
            hash_alg: None,
            payload: None,
            receipt: None,
        };
        compute_entry_hash(&entry)
    }

    #[test]
    fn test_verify_empty_wal() {
        let dir = TempDir::new().unwrap();
        let result = verify_wal(dir.path(), None, false).unwrap();

        assert!(result.valid);
        assert_eq!(result.events_verified, 0);
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("No WAL segments")));
    }

    #[test]
    fn test_verify_valid_genesis() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        let genesis = create_entry(1, 1000000, GENESIS_PREV_HASH, "abc123");
        writeln!(file, "{genesis}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(result.valid);
        assert_eq!(result.events_verified, 1);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_verify_invalid_genesis() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Genesis with wrong prev_hash
        let genesis = create_entry(1, 1000000, "deadbeef", "abc123");
        writeln!(file, "{genesis}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == "invalid_genesis"));
    }

    #[test]
    fn test_verify_valid_chain() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Genesis
        let genesis = create_entry(1, 1000000, GENESIS_PREV_HASH, "payload1");
        writeln!(file, "{genesis}").unwrap();

        // Compute hash of genesis for linking
        let genesis_hash = compute_test_entry_hash(1, 1000000, GENESIS_PREV_HASH, "payload1");

        // Second entry linked to genesis
        let entry2 = create_entry(2, 2000000, &genesis_hash, "payload2");
        writeln!(file, "{entry2}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(result.valid);
        assert_eq!(result.events_verified, 2);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_verify_chain_break() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Genesis
        let genesis = create_entry(1, 1000000, GENESIS_PREV_HASH, "payload1");
        writeln!(file, "{genesis}").unwrap();

        // Second entry with WRONG prev_hash (tampered)
        let entry2 = create_entry(2, 2000000, "tampered_hash_not_matching", "payload2");
        writeln!(file, "{entry2}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.error_type == "chain_break"));
    }

    #[test]
    fn test_verify_sequence_gap() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Genesis (sequence 1)
        let genesis = create_entry(1, 1000000, GENESIS_PREV_HASH, "payload1");
        writeln!(file, "{genesis}").unwrap();

        let genesis_hash = compute_test_entry_hash(1, 1000000, GENESIS_PREV_HASH, "payload1");

        // Skip sequence 2, jump to 3
        let entry3 = create_entry(3, 3000000, &genesis_hash, "payload3");
        writeln!(file, "{entry3}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.error_type == "sequence_gap"));
    }

    #[test]
    fn test_verify_timestamp_regression() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Genesis with timestamp 2000000
        let genesis = create_entry(1, 2000000, GENESIS_PREV_HASH, "payload1");
        writeln!(file, "{genesis}").unwrap();

        let genesis_hash = compute_test_entry_hash(1, 2000000, GENESIS_PREV_HASH, "payload1");

        // Second entry with EARLIER timestamp (regression)
        let entry2 = create_entry(2, 1000000, &genesis_hash, "payload2");
        writeln!(file, "{entry2}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == "timestamp_regression"));
    }

    #[test]
    fn test_verify_root_mismatch() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        let genesis = create_entry(1, 1000000, GENESIS_PREV_HASH, "payload1");
        writeln!(file, "{genesis}").unwrap();

        // Provide wrong expected root
        let result = verify_wal(dir.path(), Some("wrong_root_hash"), false).unwrap();
        assert!(!result.valid);
        assert!(result
            .errors
            .iter()
            .any(|e| e.error_type == "root_mismatch"));
    }

    #[test]
    fn test_fail_fast_stops_on_first_error() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Invalid genesis
        let genesis = create_entry(1, 1000000, "bad_genesis", "payload1");
        writeln!(file, "{genesis}").unwrap();

        // This entry would also have errors, but we should stop at genesis
        let entry2 = create_entry(3, 500000, "also_wrong", "payload2");
        writeln!(file, "{entry2}").unwrap();

        let result = verify_wal(dir.path(), None, true);
        assert!(result.is_err());

        // Should be InvalidGenesis, not later errors
        let err = result.unwrap_err();
        assert!(err.to_string().contains("genesis"));
    }

    #[test]
    fn test_accumulates_multiple_errors_without_fail_fast() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Invalid genesis
        let genesis = create_entry(1, 1000000, "bad_genesis", "payload1");
        writeln!(file, "{genesis}").unwrap();

        // Also has chain break and sequence gap
        let entry2 = create_entry(3, 500000, "wrong_prev", "payload2");
        writeln!(file, "{entry2}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(!result.valid);

        // Should have multiple errors accumulated
        assert!(result.errors.len() >= 2);
    }

    #[test]
    fn test_verify_genesis_wrong_sequence() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Genesis with correct prev_hash but wrong sequence (should be 1)
        let genesis = create_entry(42, 1000000, GENESIS_PREV_HASH, "payload1");
        writeln!(file, "{genesis}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(!result.valid);

        // Should detect invalid genesis due to wrong sequence
        let has_genesis_error = result
            .errors
            .iter()
            .any(|e| e.error_type == "invalid_genesis" && e.details.contains("sequence"));
        assert!(
            has_genesis_error,
            "Expected invalid_genesis error about sequence, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_verify_genesis_both_wrong_sequence_and_prev_hash() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        // Genesis with both wrong sequence and wrong prev_hash
        let genesis = create_entry(99, 1000000, "deadbeef", "payload1");
        writeln!(file, "{genesis}").unwrap();

        let result = verify_wal(dir.path(), None, false).unwrap();
        assert!(!result.valid);

        // Should have two genesis errors: one for sequence, one for prev_hash
        let genesis_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.error_type == "invalid_genesis")
            .collect();
        assert_eq!(
            genesis_errors.len(),
            2,
            "Expected 2 invalid_genesis errors, got: {:?}",
            genesis_errors
        );
    }
}
