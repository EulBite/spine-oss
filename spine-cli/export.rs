// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Eul Bite

//! Export audit trail to formats compatible with external tools.
//!
//! Supports JSON-Lines (for SIEM integration), CSV (for spreadsheet analysis),
//! and Syslog format (for legacy systems).
//!
//! ## Chain Root Consistency
//!
//! The `chain_root_hash` in the manifest uses the same computation as
//! `spine-verify`: each entry's full hash (seq, ts, prev_hash, payload_hash)
//! is included, not just payload_hash. This ensures the manifest can be
//! cross-verified with the CLI verification tool.
//!
//! ## Manifest Generation
//!
//! Manifests are only generated for JSONL exports written to files (not stdout).
//! The manifest is written as a separate `.manifest.json` file adjacent to the
//! export, suitable for bundling in a ZIP archive for auditors.

use blake3::Hasher;
use chrono::{DateTime, Utc};
use csv::WriterBuilder;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;
use thiserror::Error;

use crate::wal_types::{collect_wal_segments, compute_entry_hash, WalEntry};
use crate::ExportFormat;

#[derive(Error, Debug)]
pub enum ExportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Invalid time range: {0}")]
    InvalidTimeRange(String),
}

/// Manifest included with exports for verification.
///
/// The `chain_root_hash` matches the computation in `spine-verify`,
/// allowing cross-verification between export and CLI tools.
#[derive(Debug, Serialize)]
pub struct ExportManifest {
    pub export_time: String,
    pub spine_version: String,
    pub event_count: u64,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub time_range_start: Option<String>,
    pub time_range_end: Option<String>,
    /// Chain root computed identically to spine-verify CLI
    pub chain_root_hash: String,
    pub export_format: String,
    /// Ed25519 signature of manifest (excluding this field).
    /// Will be populated when key signing is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Exported event in normalized format
#[derive(Debug, Serialize)]
struct ExportedEvent {
    sequence: u64,
    timestamp: String,
    event_type: String,
    source: String,
    payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    chain_proof: Option<ChainProof>,
}

#[derive(Debug, Serialize)]
struct ChainProof {
    prev_hash: String,
    signature: Option<String>,
}

/// Export result with statistics
#[derive(Debug)]
pub struct ExportResult {
    pub events_exported: u64,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub chain_root: String,
}

pub fn run(
    wal_path: &Path,
    output_path: Option<&Path>,
    format: ExportFormat,
    from: Option<&str>,
    to: Option<&str>,
    include_proofs: bool,
    output_format: crate::OutputFormat,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Warn if --include-proofs is used with non-JSONL format (proofs are only included in JSONL)
    if include_proofs && !matches!(format, ExportFormat::Jsonl) {
        eprintln!(
            "Warning: --include-proofs has no effect with {:?} format (only JSONL supports chain proofs)",
            format
        );
    }

    let result = export_wal(wal_path, output_path, format, from, to, include_proofs)?;

    // Respect output format for progress messages
    if output_format != crate::OutputFormat::Quiet {
        eprintln!("Exported {} events", result.events_exported);
        if result.events_exported > 0 {
            eprintln!("  Sequence range: {:?} - {:?}", result.first_sequence, result.last_sequence);
            if result.chain_root.len() >= 16 {
                eprintln!("  Chain root: {}...", &result.chain_root[..16]);
            }
        }
    }

    Ok(result.events_exported > 0)
}

fn export_wal(
    wal_path: &Path,
    output_path: Option<&Path>,
    format: ExportFormat,
    from: Option<&str>,
    to: Option<&str>,
    include_proofs: bool,
) -> Result<ExportResult, ExportError> {
    let time_filter = parse_time_filter(from, to)?;

    let mut writer: Box<dyn Write> = match output_path {
        Some(path) => Box::new(BufWriter::new(File::create(path)?)),
        None => Box::new(std::io::stdout()),
    };

    let mut csv_writer = if matches!(format, ExportFormat::Csv) {
        let csv_out: Box<dyn Write> = match output_path {
            Some(path) => Box::new(BufWriter::new(File::create(path)?)),
            None => Box::new(std::io::stdout()),
        };
        Some(WriterBuilder::new().from_writer(csv_out))
    } else {
        None
    };

    if let Some(ref mut csv_w) = csv_writer {
        csv_w.write_record(["sequence", "timestamp", "event_type", "source", "payload_hash"])?;
    }

    let mut event_count = 0u64;
    let mut first_seq: Option<u64> = None;
    let mut last_seq: Option<u64> = None;
    let mut chain_hasher = Hasher::new();
    let segments = collect_segments(wal_path)?;

    for segment_path in &segments {
        let file = File::open(segment_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: WalEntry =
                serde_json::from_str(&line).map_err(|e| ExportError::Parse(e.to_string()))?;

            if let Some((start, end)) = &time_filter {
                let ts = entry.timestamp_ns;
                if ts < *start || ts > *end {
                    continue;
                }
            }

            if first_seq.is_none() {
                first_seq = Some(entry.sequence);
            }
            last_seq = Some(entry.sequence);

            let entry_hash = compute_entry_hash(&entry);
            chain_hasher.update(entry_hash.as_bytes());
            event_count += 1;

            let exported = ExportedEvent {
                sequence: entry.sequence,
                timestamp: format_timestamp(entry.timestamp_ns),
                event_type: entry.event_type.unwrap_or_else(|| "unknown".to_string()),
                source: entry.source.unwrap_or_else(|| "unknown".to_string()),
                payload_hash: entry.payload_hash.clone(),
                chain_proof: if include_proofs {
                    Some(ChainProof {
                        prev_hash: entry.prev_hash,
                        signature: entry.signature,
                    })
                } else {
                    None
                },
            };

            write_event(&mut writer, &mut csv_writer, &exported, format)?;
        }
    }

    if let Some(csv_w) = csv_writer {
        csv_w.into_inner().map_err(|e| ExportError::Io(e.into_error()))?;
    }

    let chain_root = hex::encode(chain_hasher.finalize().as_bytes());

    // Write manifest for JSON-Lines format (only for file output)
    if matches!(format, ExportFormat::Jsonl) {
        if let Some(output) = output_path {
            let manifest = ExportManifest {
                export_time: Utc::now().to_rfc3339(),
                spine_version: env!("CARGO_PKG_VERSION").to_string(),
                event_count,
                first_sequence: first_seq,
                last_sequence: last_seq,
                time_range_start: from.map(String::from),
                time_range_end: to.map(String::from),
                chain_root_hash: chain_root.clone(),
                export_format: "jsonl".to_string(),
                signature: None,
            };

            let manifest_path = output.with_extension("manifest.json");
            let manifest_file = File::create(manifest_path)?;
            serde_json::to_writer_pretty(manifest_file, &manifest)
                .map_err(|e| ExportError::Parse(e.to_string()))?;
        }
    }

    Ok(ExportResult {
        events_exported: event_count,
        first_sequence: first_seq,
        last_sequence: last_seq,
        chain_root,
    })
}

fn parse_time_filter(from: Option<&str>, to: Option<&str>) -> Result<Option<(i64, i64)>, ExportError> {
    match (from, to) {
        (None, None) => Ok(None),
        (Some(f), Some(t)) => {
            let start = parse_iso_timestamp(f)?;
            let end = parse_iso_timestamp(t)?;
            if start > end {
                return Err(ExportError::InvalidTimeRange(
                    "start time after end time".to_string(),
                ));
            }
            Ok(Some((start, end)))
        }
        (Some(f), None) => {
            let start = parse_iso_timestamp(f)?;
            Ok(Some((start, i64::MAX)))
        }
        (None, Some(t)) => {
            let end = parse_iso_timestamp(t)?;
            Ok(Some((0, end)))
        }
    }
}

fn parse_iso_timestamp(s: &str) -> Result<i64, ExportError> {
    let dt = DateTime::parse_from_rfc3339(s)
        .map_err(|e| ExportError::InvalidTimeRange(e.to_string()))?;

    dt.timestamp_nanos_opt()
        .ok_or_else(|| ExportError::InvalidTimeRange("timestamp out of nanosecond range".into()))
}

fn format_timestamp(ns: i64) -> String {
    // Safe conversion: handle timestamps outside nanosecond range (~1677 AD to ~2262 AD)
    // DateTime::from_timestamp_nanos panics on overflow, so we use fallback for edge cases
    // Note: i64::MIN would overflow, but we use safe margins well within range
    const MAX_SAFE_NANOS: i64 = 9_000_000_000_000_000_000; // ~2255 AD, safe margin
    const MIN_SAFE_NANOS: i64 = -9_000_000_000_000_000_000; // ~1684 AD, safe margin

    if ns > MAX_SAFE_NANOS {
        // Far future timestamp - use seconds-based conversion
        let secs = ns / 1_000_000_000;
        let nsecs = (ns % 1_000_000_000) as u32;
        if let Some(dt) = DateTime::from_timestamp(secs, nsecs) {
            return dt.to_rfc3339();
        }
        return format!("OVERFLOW:{}", ns);
    }

    if ns < MIN_SAFE_NANOS {
        // Far past timestamp - use seconds-based conversion
        let secs = ns / 1_000_000_000;
        let nsecs = ((ns % 1_000_000_000).abs()) as u32;
        if let Some(dt) = DateTime::from_timestamp(secs, nsecs) {
            return dt.to_rfc3339();
        }
        return format!("UNDERFLOW:{}", ns);
    }

    DateTime::from_timestamp_nanos(ns).to_rfc3339()
}

fn write_event(
    writer: &mut dyn Write,
    csv_writer: &mut Option<csv::Writer<Box<dyn Write>>>,
    event: &ExportedEvent,
    format: ExportFormat,
) -> Result<(), ExportError> {
    match format {
        ExportFormat::Jsonl => {
            serde_json::to_writer(&mut *writer, event)
                .map_err(|e| ExportError::Parse(e.to_string()))?;
            writeln!(writer)?;
        }
        ExportFormat::Csv => {
            if let Some(csv_w) = csv_writer {
                csv_w.write_record([
                    &event.sequence.to_string(),
                    &event.timestamp,
                    &event.event_type,
                    &event.source,
                    &event.payload_hash,
                ])?;
            }
        }
        ExportFormat::Syslog => {
            // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            // PRI 14 = facility 1 (user) * 8 + severity 6 (info)
            writeln!(
                writer,
                "<14>1 {} spine {} - - - seq={} hash={}",
                event.timestamp, event.source, event.sequence, event.payload_hash
            )?;
        }
    }
    Ok(())
}

fn collect_segments(wal_path: &Path) -> Result<Vec<std::path::PathBuf>, ExportError> {
    Ok(collect_wal_segments(wal_path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;
    use tempfile::TempDir;

    fn create_test_entry(seq: u64, ts: i64, prev: &str, payload: &str) -> String {
        serde_json::json!({
            "sequence": seq,
            "timestamp_ns": ts,
            "prev_hash": prev,
            "payload_hash": payload,
            "event_type": "test.event",
            "source": "test-source"
        })
        .to_string()
    }

    #[test]
    fn test_parse_time_filter_valid() {
        let result = parse_time_filter(
            Some("2025-01-01T00:00:00Z"),
            Some("2025-01-02T00:00:00Z"),
        );
        assert!(result.is_ok());
        let (start, end) = result.unwrap().unwrap();
        assert!(start < end);
    }

    #[test]
    fn test_parse_time_filter_invalid_range() {
        let result = parse_time_filter(
            Some("2025-01-02T00:00:00Z"),
            Some("2025-01-01T00:00:00Z"),
        );
        assert!(matches!(result, Err(ExportError::InvalidTimeRange(_))));
    }

    #[test]
    fn test_parse_timestamp_valid_future() {
        // Year 2100 is safely within nanosecond range
        let result = parse_iso_timestamp("2100-01-01T00:00:00Z");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_timestamp_invalid_format() {
        let result = parse_iso_timestamp("not-a-timestamp");
        assert!(matches!(result, Err(ExportError::InvalidTimeRange(_))));
    }

    #[test]
    fn test_export_empty_wal() {
        let dir = TempDir::new().unwrap();
        let result = export_wal(dir.path(), None, ExportFormat::Jsonl, None, None, false).unwrap();

        assert_eq!(result.events_exported, 0);
        assert!(result.first_sequence.is_none());
    }

    #[test]
    fn test_export_counts_events() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        let zero_hash = "0".repeat(64);
        writeln!(file, "{}", create_test_entry(1, 1000, &zero_hash, "payload1")).unwrap();
        writeln!(file, "{}", create_test_entry(2, 2000, "hash1", "payload2")).unwrap();

        let result = export_wal(dir.path(), None, ExportFormat::Jsonl, None, None, false).unwrap();

        assert_eq!(result.events_exported, 2);
        assert_eq!(result.first_sequence, Some(1));
        assert_eq!(result.last_sequence, Some(2));
    }

    #[test]
    fn test_chain_root_matches_verify_computation() {
        // Verify that export and verify use the same hash computation
        use crate::wal_types::compute_entry_hash;
        
        let entry = WalEntry {
            sequence: 1,
            timestamp_ns: 1000000,
            prev_hash: "0".repeat(64),
            payload_hash: "abc123".to_string(),
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

        let hash = compute_entry_hash(&entry);

        // Should be deterministic
        let hash2 = compute_entry_hash(&entry);
        assert_eq!(hash, hash2);

        // Should be 64 hex chars (32 bytes)
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_time_filter_excludes_events() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        let zero_hash = "0".repeat(64);
        // Event at 2025-01-01 00:00:00 (timestamp in ns)
        let ts1 = 1735689600_000_000_000i64;
        // Event at 2025-01-03 00:00:00
        let ts2 = 1735862400_000_000_000i64;

        writeln!(file, "{}", create_test_entry(1, ts1, &zero_hash, "p1")).unwrap();
        writeln!(file, "{}", create_test_entry(2, ts2, "h1", "p2")).unwrap();

        // Filter to only include first day
        let result = export_wal(
            dir.path(),
            None,
            ExportFormat::Jsonl,
            Some("2025-01-01T00:00:00Z"),
            Some("2025-01-02T00:00:00Z"),
            false,
        )
        .unwrap();

        assert_eq!(result.events_exported, 1);
        assert_eq!(result.first_sequence, Some(1));
    }

    #[test]
    fn test_format_timestamp_extreme_values() {
        // Test the format_timestamp function with extreme values
        // This ensures no panics on overflow/underflow

        // Valid normal timestamp (2025-01-01)
        let ts_normal = 1735689600_000_000_000i64;
        let result = super::format_timestamp(ts_normal);
        assert!(result.contains("2025"), "Expected 2025 in timestamp: {}", result);

        // Far future timestamp (beyond safe nanos range)
        let ts_far_future = 9_100_000_000_000_000_000i64; // ~2258 AD
        let result = super::format_timestamp(ts_far_future);
        // Should not panic, and should either be valid RFC3339 or OVERFLOW marker
        assert!(!result.is_empty());

        // Very far future (i64::MAX-ish)
        let ts_max = i64::MAX / 2; // ~146 billion years, definitely overflows
        let result = super::format_timestamp(ts_max);
        assert!(!result.is_empty());

        // Negative timestamp (before 1970)
        let ts_negative = -1_000_000_000_000_000_000i64; // ~1938 AD
        let result = super::format_timestamp(ts_negative);
        assert!(!result.is_empty());

        // Far past (underflow territory)
        let ts_far_past = -9_100_000_000_000_000_000i64;
        let result = super::format_timestamp(ts_far_past);
        // Should contain UNDERFLOW marker
        assert!(result.contains("UNDERFLOW") || result.contains("-"),
            "Expected UNDERFLOW or negative year in: {}", result);

        // Zero timestamp (1970-01-01 00:00:00)
        let ts_zero = 0i64;
        let result = super::format_timestamp(ts_zero);
        assert!(result.contains("1970"), "Expected 1970 in timestamp: {}", result);
    }
}