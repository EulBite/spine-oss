// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Eul Bite

//! Shared WAL types and cryptographic primitives for CLI tools.
//!
//! This module provides the canonical definitions used by both `verify` and
//! `export` commands. Having a single source of truth ensures that chain
//! root computations are consistent across all tools.
//!
//! ## Entry Hash Contract
//!
//! The `compute_entry_hash` function defines the canonical hash that:
//! 1. Links each WAL entry to its predecessor (`prev_hash` field)
//! 2. Is signed by Ed25519 when signatures are enabled
//! 3. Is accumulated to produce the `chain_root`
//!
//! Any change to this function is a **breaking change** that requires:
//! - Updating the WAL writer in `spine` server
//! - Potentially migrating existing WAL files
//! - Version bumping the WAL format

use blake3::Hasher;
use serde::{Deserialize, Deserializer, Serialize};
use std::ffi::OsStr;

/// Deserialize timestamp from either i64 (nanoseconds) or ISO string.
///
/// # Errors
/// Returns an error if:
/// - ISO string cannot be parsed
/// - Timestamp is outside representable nanosecond range (~1677-2262 AD)
fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TimestampValue {
        Nanos(i64),
        IsoString(String),
    }

    match TimestampValue::deserialize(deserializer)? {
        TimestampValue::Nanos(ns) => Ok(ns),
        TimestampValue::IsoString(s) => {
            // Parse ISO 8601 timestamp to nanoseconds
            let dt = chrono::DateTime::parse_from_rfc3339(&s)
                .or_else(|_| {
                    // Try parsing without timezone (assume UTC)
                    chrono::NaiveDateTime::parse_from_str(&s, "%Y-%m-%dT%H:%M:%S%.f")
                        .map(|dt| dt.and_utc().fixed_offset())
                })
                .map_err(|e| D::Error::custom(format!("Invalid timestamp format: {}", e)))?;

            // Fail explicitly if timestamp is outside nanosecond range
            dt.timestamp_nanos_opt()
                .ok_or_else(|| D::Error::custom(format!(
                    "Timestamp out of range for nanoseconds: {} (valid range: ~1677-2262 AD)",
                    s
                )))
        }
    }
}

/// Genesis block must have this prev_hash (64 zeros = 32 null bytes hex-encoded)
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Validation result for hex strings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexValidation {
    /// Valid hex string with expected length
    Valid,
    /// Invalid: wrong length (expected 64 hex chars for BLAKE3)
    InvalidLength { expected: usize, actual: usize },
    /// Invalid: contains non-hex characters
    InvalidChars { position: usize, char: char },
}

/// Validate a hex-encoded hash string (BLAKE3 = 64 hex chars).
///
/// Returns `HexValidation::Valid` if:
/// - Length is exactly 64 characters
/// - All characters are valid hex (0-9, a-f, A-F)
#[inline]
pub fn validate_hex_hash(hash: &str) -> HexValidation {
    const EXPECTED_LEN: usize = 64; // BLAKE3 = 32 bytes = 64 hex chars

    if hash.len() != EXPECTED_LEN {
        return HexValidation::InvalidLength {
            expected: EXPECTED_LEN,
            actual: hash.len(),
        };
    }

    for (pos, ch) in hash.chars().enumerate() {
        if !ch.is_ascii_hexdigit() {
            return HexValidation::InvalidChars { position: pos, char: ch };
        }
    }

    HexValidation::Valid
}

/// Validate a WAL entry's hash fields.
///
/// Checks that prev_hash and payload_hash are valid 64-character hex strings.
/// Returns a list of validation errors (empty if all valid).
#[allow(dead_code)]
pub fn validate_entry_hashes(entry: &WalEntry) -> Vec<String> {
    let mut errors = Vec::new();

    match validate_hex_hash(&entry.prev_hash) {
        HexValidation::Valid => {}
        HexValidation::InvalidLength { expected, actual } => {
            errors.push(format!(
                "prev_hash invalid length: expected {} chars, got {}",
                expected, actual
            ));
        }
        HexValidation::InvalidChars { position, char } => {
            errors.push(format!(
                "prev_hash contains invalid char '{}' at position {}",
                char, position
            ));
        }
    }

    match validate_hex_hash(&entry.payload_hash) {
        HexValidation::Valid => {}
        HexValidation::InvalidLength { expected, actual } => {
            errors.push(format!(
                "payload_hash invalid length: expected {} chars, got {}",
                expected, actual
            ));
        }
        HexValidation::InvalidChars { position, char } => {
            errors.push(format!(
                "payload_hash contains invalid char '{}' at position {}",
                char, position
            ));
        }
    }

    if let Some(ref sig) = entry.signature {
        if sig.len() != 128 {  // Ed25519 signature = 64 bytes
            errors.push(format!(
                "signature invalid length: expected 128 chars, got {}",
                sig.len()
            ));
        } else if !sig.chars().all(|c| c.is_ascii_hexdigit()) {
            errors.push("signature contains invalid hex characters".to_string());
        }
    }

    if let Some(ref pk) = entry.public_key {
        if pk.len() != 64 {  // Ed25519 public key = 32 bytes
            errors.push(format!(
                "public_key invalid length: expected 64 chars, got {}",
                pk.len()
            ));
        } else if !pk.chars().all(|c| c.is_ascii_hexdigit()) {
            errors.push("public_key contains invalid hex characters".to_string());
        }
    }

    errors
}

/// Current WAL format version.
/// Increment when making breaking changes to the record structure.
///
/// Version history:
///   1 - Initial format (2025-01): All fields documented below
///
/// Compatibility: CLI supports reading all previous versions.
#[allow(dead_code)]
pub const WAL_FORMAT_VERSION: u32 = 1;

/// WAL entry as stored on disk.
///
/// This structure supports both the Spine server WAL format and the SDK's
/// local WAL format (LocalRecord).
///
/// # Field Aliases
///
/// For compatibility with various WAL formats and pipelines, key fields
/// support alternative names via serde aliases:
/// - `sequence`: also accepts `seq`
/// - `timestamp_ns`: also accepts `ts_ns`, `ts`, `timestamp`, `ts_client`
/// - `prev_hash`: also accepts `previous_hash`, `prev`
/// - `payload_hash`: also accepts `hash`, `event_hash`
/// - `signature`: also accepts `sig`, `sig_client`
/// - `public_key`: also accepts `pubkey`, `pk`, `key_id`
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WalEntry {
    /// Format version for forward compatibility (defaults to 1 for old records)
    #[serde(default = "default_format_version")]
    pub format_version: u32,

    /// Monotonically increasing sequence number (1-indexed)
    #[serde(alias = "seq")]
    pub sequence: u64,

    /// Unix timestamp in nanoseconds (or ISO string for SDK format)
    #[serde(alias = "ts_ns", alias = "ts", alias = "timestamp", alias = "ts_client")]
    #[serde(deserialize_with = "deserialize_timestamp")]
    pub timestamp_ns: i64,

    /// Hash of the previous entry (hex-encoded BLAKE3 or SHA256)
    /// First entry must have `GENESIS_PREV_HASH`
    #[serde(alias = "previous_hash", alias = "prev")]
    pub prev_hash: String,

    /// Hash of the event payload (hex-encoded BLAKE3 or SHA256)
    #[serde(alias = "hash", alias = "event_hash")]
    pub payload_hash: String,

    /// Event type identifier (e.g., "user.login")
    #[serde(default)]
    pub event_type: Option<String>,

    /// Source system that generated the event
    #[serde(default)]
    pub source: Option<String>,

    /// Ed25519 signature over canonical payload (hex-encoded)
    #[serde(default, alias = "sig", alias = "sig_client")]
    pub signature: Option<String>,

    /// Public key that created the signature (hex-encoded, 64 chars)
    #[serde(default, alias = "pubkey", alias = "pk")]
    pub public_key: Option<String>,

    /// Key ID - short identifier for the signing key (SDK format)
    #[serde(default)]
    pub key_id: Option<String>,

    // --- SDK LocalRecord fields ---

    /// Unique event identifier (SDK format: evt_<uuid>)
    #[serde(default)]
    pub event_id: Option<String>,

    /// Stream identifier (SDK format: stream_<hash>)
    #[serde(default)]
    pub stream_id: Option<String>,

    /// Hash algorithm used (blake3 or sha256)
    #[serde(default)]
    pub hash_alg: Option<String>,

    /// The actual event payload (SDK format)
    #[serde(default)]
    pub payload: Option<serde_json::Value>,

    /// Server receipt (SDK format, when synced to Spine)
    #[serde(default)]
    pub receipt: Option<Receipt>,
}

/// Server receipt proving an event was accepted.
///
/// This is what makes an event "audit-grade" vs just a "client claim".
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Receipt {
    /// ID of the acknowledged event
    pub event_id: String,

    /// Hash of the event payload (must match client's)
    pub payload_hash: String,

    /// Server timestamp (RFC3339)
    pub server_time: String,

    /// Server-assigned sequence number
    pub server_seq: i64,

    /// Server's Ed25519 signature over receipt data
    pub receipt_sig: String,

    /// ID of the server signing key
    pub server_key_id: String,

    /// Signature algorithm (ed25519)
    #[serde(default = "default_sig_alg")]
    pub sig_alg: String,

    /// Batch ID when event was sealed (None if pending)
    #[serde(default)]
    pub batch_id: Option<String>,
}

fn default_sig_alg() -> String {
    "ed25519".to_string()
}

fn default_format_version() -> u32 {
    1 // Default to v1 for old records without format_version field
}

/// Collect WAL segment files from a directory.
///
/// Supports both `.wal` and `.jsonl` extensions for compatibility.
/// Files are sorted by name (lexicographic), which works correctly
/// with zero-padded or timestamp-based naming schemes.
///
/// # Naming Conventions Supported
///
/// - `00000001.wal`, `00000002.wal` (zero-padded numeric)
/// - `wal_20250101_120000.jsonl` (timestamp-based)
/// - `segment_001.wal` (prefixed numeric)
pub fn collect_wal_segments(wal_path: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let entries = std::fs::read_dir(wal_path)?;
    let mut segments = Vec::new();

    for entry in entries {
        let path = entry?.path();
        if let Some(ext) = path.extension() {
            // Use OsStr::new for portable extension comparison across platforms
            if ext == OsStr::new("wal") || ext == OsStr::new("jsonl") {
                segments.push(path);
            }
        }
    }

    // Sort lexicographically - works with zero-padded or timestamp names
    segments.sort();
    Ok(segments)
}

/// Compute the canonical hash of a WAL entry.
///
/// This hash is used for:
/// - Chain linking: `entry[n].prev_hash == compute_entry_hash(entry[n-1])`
/// - Signing: Ed25519 signs this hash
/// - Chain root: Accumulated across all entries
///
/// # Design Rationale
///
/// Why hash (seq, timestamp, prev_hash, payload_hash) instead of just payload?
/// - Binding seq prevents replay attacks (same payload, different position)
/// - Binding timestamp proves ordering (forensic timeline reconstruction)
/// - Binding prev_hash creates the chain (any tampering invalidates successors)
/// - This is a Merkle-like structure where each entry commits to all predecessors
///
/// # Fields Included
///
/// The hash covers these fields in order:
/// 1. `sequence` (8 bytes, little-endian u64)
/// 2. `timestamp_ns` (8 bytes, little-endian i64)
/// 3. `prev_hash` (UTF-8 bytes of hex string)
/// 4. `payload_hash` (UTF-8 bytes of hex string)
///
/// # Signing Contract
///
/// ```text
/// message   = compute_entry_hash(entry)  // 64 hex chars, UTF-8 encoded
/// signature = Ed25519::sign(signing_key, message.as_bytes())
/// ```
///
/// The signature is over the UTF-8 bytes of the hex string, NOT the raw 32-byte hash.
/// Any change to this contract is a breaking change.
///
/// # Stability Warning
///
/// This function's output MUST remain stable across versions.
/// Changing it breaks chain verification for existing WAL files.
#[inline]
pub fn compute_entry_hash(entry: &WalEntry) -> String {
    let mut hasher = Hasher::new();
    hasher.update(&entry.sequence.to_le_bytes());
    hasher.update(&entry.timestamp_ns.to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(entry.payload_hash.as_bytes());
    hex::encode(hasher.finalize().as_bytes())
}

/// Compute chain root from a sequence of entry hashes.
///
/// The chain root is a single hash that commits to the entire event stream.
/// It can be used to verify that an export matches the original WAL.
///
/// # Ordering Requirement
///
/// The caller MUST provide entry hashes in strict sequence order (oldest to newest).
/// Changing the order produces a different root. This is intentional: it ensures
/// the root commits to both the content AND the ordering of events.
///
/// # Example
///
/// ```ignore
/// let hashes = entries.iter().map(compute_entry_hash);
/// let root = compute_chain_root(hashes);
/// ```
#[allow(dead_code)]
pub fn compute_chain_root<I, S>(entry_hashes: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut hasher = Hasher::new();
    for hash in entry_hashes {
        hasher.update(hash.as_ref().as_bytes());
    }
    hex::encode(hasher.finalize().as_bytes())
}

/// Compute chain root directly from a slice of WAL entries.
///
/// Convenience wrapper that computes entry hashes and chain root in one call.
/// Ensures consistent hash computation across all tools.
///
/// # Ordering Requirement
///
/// Entries MUST be in sequence order (oldest first). See [`compute_chain_root`].
#[allow(dead_code)]
pub fn compute_chain_root_from_entries(entries: &[WalEntry]) -> String {
    let hashes = entries.iter().map(compute_entry_hash);
    compute_chain_root(hashes)
}

/// Result of entry hash verification
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashVerification {
    /// Hash matches expected value
    Valid,
    /// Hash does not match (contains expected and actual)
    Mismatch { expected: String, actual: String },
    /// Entry is genesis but prev_hash is not zero or sequence is not 1
    InvalidGenesis { reason: String },
}

/// Verify that an entry's prev_hash matches the computed hash of the previous entry.
///
/// For genesis (first entry), validates both:
/// - `sequence == 1`
/// - `prev_hash == GENESIS_PREV_HASH`
#[allow(dead_code)]
pub fn verify_chain_link(current: &WalEntry, previous: Option<&WalEntry>) -> HashVerification {
    match previous {
        None => {
            // Genesis entry must have sequence 1 AND zero prev_hash
            if current.sequence != 1 {
                return HashVerification::InvalidGenesis {
                    reason: format!(
                        "genesis must have sequence=1, found sequence={}",
                        current.sequence
                    ),
                };
            }
            if current.prev_hash != GENESIS_PREV_HASH {
                return HashVerification::InvalidGenesis {
                    reason: format!(
                        "genesis prev_hash must be {}, found {}",
                        &GENESIS_PREV_HASH[..16],
                        &current.prev_hash
                    ),
                };
            }
            HashVerification::Valid
        }
        Some(prev) => {
            let expected_hash = compute_entry_hash(prev);
            if current.prev_hash == expected_hash {
                HashVerification::Valid
            } else {
                HashVerification::Mismatch {
                    expected: expected_hash,
                    actual: current.prev_hash.clone(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(seq: u64, ts: i64, prev: &str, payload: &str) -> WalEntry {
        WalEntry {
            sequence: seq,
            timestamp_ns: ts,
            prev_hash: prev.to_string(),
            payload_hash: payload.to_string(),
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
        }
    }

    #[test]
    fn test_entry_hash_deterministic() {
        let entry = make_entry(1, 1000, GENESIS_PREV_HASH, "payload123");

        let hash1 = compute_entry_hash(&entry);
        let hash2 = compute_entry_hash(&entry);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_entry_hash_changes_with_sequence() {
        let entry1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        let entry2 = make_entry(2, 1000, GENESIS_PREV_HASH, "payload");

        assert_ne!(compute_entry_hash(&entry1), compute_entry_hash(&entry2));
    }

    #[test]
    fn test_entry_hash_changes_with_timestamp() {
        let entry1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        let entry2 = make_entry(1, 2000, GENESIS_PREV_HASH, "payload");

        assert_ne!(compute_entry_hash(&entry1), compute_entry_hash(&entry2));
    }

    #[test]
    fn test_entry_hash_changes_with_prev_hash() {
        let entry1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");
        let entry2 = make_entry(1, 1000, "different_prev_hash", "payload");

        assert_ne!(compute_entry_hash(&entry1), compute_entry_hash(&entry2));
    }

    #[test]
    fn test_verify_genesis_valid() {
        let genesis = make_entry(1, 1000, GENESIS_PREV_HASH, "payload");

        assert_eq!(verify_chain_link(&genesis, None), HashVerification::Valid);
    }

    #[test]
    fn test_verify_genesis_invalid() {
        let bad_genesis = make_entry(1, 1000, "not_zero", "payload");

        let result = verify_chain_link(&bad_genesis, None);
        assert!(matches!(result, HashVerification::InvalidGenesis { .. }));
        
        // Verify the reason mentions prev_hash
        if let HashVerification::InvalidGenesis { reason } = result {
            assert!(reason.contains("prev_hash"));
        }
    }

    #[test]
    fn test_verify_genesis_wrong_sequence() {
        // Genesis with correct prev_hash but wrong sequence
        let bad_genesis = make_entry(42, 1000, GENESIS_PREV_HASH, "payload");

        let result = verify_chain_link(&bad_genesis, None);
        assert!(matches!(result, HashVerification::InvalidGenesis { .. }));

        // Verify the reason mentions sequence
        if let HashVerification::InvalidGenesis { reason } = result {
            assert!(reason.contains("sequence"));
            assert!(reason.contains("42"));
        }
    }

    #[test]
    fn test_verify_chain_link_valid() {
        let entry1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload1");
        let entry1_hash = compute_entry_hash(&entry1);

        let entry2 = make_entry(2, 2000, &entry1_hash, "payload2");

        assert_eq!(
            verify_chain_link(&entry2, Some(&entry1)),
            HashVerification::Valid
        );
    }

    #[test]
    fn test_verify_chain_link_mismatch() {
        let entry1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload1");
        let entry2 = make_entry(2, 2000, "wrong_hash", "payload2");

        assert!(matches!(
            verify_chain_link(&entry2, Some(&entry1)),
            HashVerification::Mismatch { .. }
        ));
    }

    #[test]
    fn test_chain_root_computation() {
        let hashes = vec!["hash1", "hash2", "hash3"];
        let root = compute_chain_root(hashes.clone());

        // Should be deterministic
        assert_eq!(root, compute_chain_root(hashes));

        // Different input = different root
        let different_root = compute_chain_root(vec!["hash1", "hash2"]);
        assert_ne!(root, different_root);
    }

    #[test]
    fn test_chain_root_order_matters() {
        let root1 = compute_chain_root(vec!["a", "b"]);
        let root2 = compute_chain_root(vec!["b", "a"]);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_chain_root_from_entries() {
        let entry1 = make_entry(1, 1000, GENESIS_PREV_HASH, "payload1");
        let entry1_hash = compute_entry_hash(&entry1);
        let entry2 = make_entry(2, 2000, &entry1_hash, "payload2");

        let entries = vec![entry1.clone(), entry2.clone()];

        // compute_chain_root_from_entries should match manual computation
        let root_from_entries = compute_chain_root_from_entries(&entries);
        let root_manual = compute_chain_root(vec![
            compute_entry_hash(&entry1),
            compute_entry_hash(&entry2),
        ]);

        assert_eq!(root_from_entries, root_manual);
    }

    #[test]
    fn test_chain_root_from_entries_empty() {
        let entries: Vec<WalEntry> = vec![];
        let root = compute_chain_root_from_entries(&entries);

        // Empty chain should still produce a valid (deterministic) hash
        assert_eq!(root.len(), 64); // 32 bytes = 64 hex chars

        // Should be deterministic
        assert_eq!(root, compute_chain_root_from_entries(&entries));
    }

    #[test]
    fn test_validate_hex_hash_valid() {
        assert_eq!(validate_hex_hash(GENESIS_PREV_HASH), HexValidation::Valid);
        assert_eq!(
            validate_hex_hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
            HexValidation::Valid
        );
        // Mixed case is valid
        assert_eq!(
            validate_hex_hash("ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789"),
            HexValidation::Valid
        );
    }

    #[test]
    fn test_validate_hex_hash_invalid_length() {
        assert!(matches!(
            validate_hex_hash("abc123"),
            HexValidation::InvalidLength { expected: 64, actual: 6 }
        ));
        assert!(matches!(
            validate_hex_hash(""),
            HexValidation::InvalidLength { expected: 64, actual: 0 }
        ));
    }

    #[test]
    fn test_validate_hex_hash_invalid_chars() {
        // 'g' is not a hex digit
        let result = validate_hex_hash("ghijklmnopqrstuvwxyz0123456789abcdef0123456789abcdef0123456789ab");
        assert!(matches!(result, HexValidation::InvalidChars { position: 0, char: 'g' }));

        // Invalid char in the middle (X is at position 43)
        let result = validate_hex_hash("abcdef0123456789abcdef0123456789abcdef01234X6789abcdef0123456789");
        assert!(matches!(result, HexValidation::InvalidChars { position: 43, char: 'X' }));
    }

    #[test]
    fn test_validate_entry_hashes_valid() {
        let entry = make_entry(1, 1000, GENESIS_PREV_HASH, GENESIS_PREV_HASH);
        let errors = validate_entry_hashes(&entry);
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn test_validate_entry_hashes_invalid_prev_hash() {
        let entry = make_entry(1, 1000, "short", GENESIS_PREV_HASH);
        let errors = validate_entry_hashes(&entry);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("prev_hash"));
        assert!(errors[0].contains("length"));
    }

    #[test]
    fn test_validate_entry_hashes_invalid_payload_hash() {
        let entry = make_entry(1, 1000, GENESIS_PREV_HASH, "not_hex!!");
        let errors = validate_entry_hashes(&entry);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("payload_hash"));
    }

    #[test]
    fn test_validate_entry_hashes_both_invalid() {
        let entry = make_entry(1, 1000, "bad", "also_bad");
        let errors = validate_entry_hashes(&entry);
        assert_eq!(errors.len(), 2);
    }
}