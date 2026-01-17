// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Eul Bite

//! Human-readable WAL inspection for debugging and exploration.
//!
//! Provides quick access to WAL contents without full verification,
//! useful for debugging and understanding audit trail structure.

use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::wal_types::{collect_wal_segments, compute_entry_hash, WalEntry, GENESIS_PREV_HASH};

/// Statistics about a WAL directory
#[derive(Debug, Serialize)]
pub struct WalStats {
    pub segment_count: usize,
    pub total_events: u64,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub first_timestamp_ns: Option<i64>,
    pub last_timestamp_ns: Option<i64>,
    pub total_size_bytes: u64,
    pub has_signatures: bool,
    pub chain_intact: bool,
    // SDK-specific stats
    pub stream_ids: Vec<String>,
    pub events_with_receipt: u64,
    pub events_without_receipt: u64,
    pub is_sdk_format: bool,
}

/// Single event for display
#[derive(Debug, Serialize)]
pub struct EventDisplay {
    pub sequence: u64,
    pub timestamp: String,
    pub event_type: String,
    pub source: String,
    pub payload_hash_short: String,
    pub prev_hash_short: String,
    pub signed: bool,
    // SDK-specific fields
    pub event_id: Option<String>,
    pub has_receipt: bool,
}

pub fn run(
    wal_path: &Path,
    last_n: usize,
    sequence: Option<u64>,
    show_stats: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    if show_stats {
        let stats = compute_stats(wal_path)?;
        println!("{}", serde_json::to_string_pretty(&stats)?);
        return Ok(true);
    }

    if let Some(seq) = sequence {
        // Show specific event
        if let Some(event) = find_event(wal_path, seq)? {
            println!("{}", serde_json::to_string_pretty(&event)?);
        } else {
            eprintln!("Event with sequence {} not found", seq);
            return Ok(false);
        }
    } else {
        // Show last N events
        let events = get_last_events(wal_path, last_n)?;
        if events.is_empty() {
            eprintln!("No events found in WAL");
            return Ok(false);
        }

        print_events_table(&events);
    }

    Ok(true)
}

fn compute_stats(wal_path: &Path) -> Result<WalStats, Box<dyn std::error::Error>> {
    use std::collections::HashSet;

    let mut stats = WalStats {
        segment_count: 0,
        total_events: 0,
        first_sequence: None,
        last_sequence: None,
        first_timestamp_ns: None,
        last_timestamp_ns: None,
        total_size_bytes: 0,
        has_signatures: false,
        chain_intact: true,
        stream_ids: Vec::new(),
        events_with_receipt: 0,
        events_without_receipt: 0,
        is_sdk_format: false,
    };

    let segments = collect_segments(wal_path)?;
    stats.segment_count = segments.len();

    let mut prev_hash: Option<String> = None;
    let mut stream_set: HashSet<String> = HashSet::new();

    for segment_path in &segments {
        stats.total_size_bytes += segment_path.metadata()?.len();

        let file = File::open(segment_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: WalEntry = serde_json::from_str(&line)?;

            if stats.first_sequence.is_none() {
                stats.first_sequence = Some(entry.sequence);
                stats.first_timestamp_ns = Some(entry.timestamp_ns);
            }
            stats.last_sequence = Some(entry.sequence);
            stats.last_timestamp_ns = Some(entry.timestamp_ns);
            stats.total_events += 1;

            if entry.signature.is_some() {
                stats.has_signatures = true;
            }
            if entry.event_id.is_some() || entry.stream_id.is_some() {
                stats.is_sdk_format = true;
            }
            if let Some(ref stream_id) = entry.stream_id {
                stream_set.insert(stream_id.clone());
            }
            if entry.receipt.is_some() {
                stats.events_with_receipt += 1;
            } else {
                stats.events_without_receipt += 1;
            }

            if let Some(ref expected) = prev_hash {
                if entry.prev_hash != *expected {
                    stats.chain_intact = false;
                }
            } else if entry.prev_hash != GENESIS_PREV_HASH {
                stats.chain_intact = false;
            }

            prev_hash = Some(compute_entry_hash(&entry));
        }
    }

    stats.stream_ids = stream_set.into_iter().collect();
    stats.stream_ids.sort();

    Ok(stats)
}

fn find_event(wal_path: &Path, target_seq: u64) -> Result<Option<WalEntry>, Box<dyn std::error::Error>> {
    let segments = collect_segments(wal_path)?;

    for segment_path in &segments {
        let file = File::open(segment_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: WalEntry = serde_json::from_str(&line)?;
            if entry.sequence == target_seq {
                return Ok(Some(entry));
            }

            // Optimization: if we've passed the target, stop
            if entry.sequence > target_seq {
                return Ok(None);
            }
        }
    }

    Ok(None)
}

fn get_last_events(wal_path: &Path, n: usize) -> Result<Vec<EventDisplay>, Box<dyn std::error::Error>> {
    use std::collections::VecDeque;

    if n == 0 {
        return Ok(Vec::new());
    }

    let mut ring_buffer: VecDeque<WalEntry> = VecDeque::with_capacity(n);
    let segments = collect_segments(wal_path)?;

    for segment_path in &segments {
        let file = File::open(segment_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: WalEntry = serde_json::from_str(&line)?;
            if ring_buffer.len() >= n {
                ring_buffer.pop_front();
            }
            ring_buffer.push_back(entry);
        }
    }

    Ok(ring_buffer
        .iter()
        .map(|e| EventDisplay {
            sequence: e.sequence,
            timestamp: format_timestamp(e.timestamp_ns),
            event_type: e.event_type.clone().unwrap_or_else(|| "-".to_string()),
            source: e.source.clone().unwrap_or_else(|| "-".to_string()),
            payload_hash_short: truncate_hash(&e.payload_hash),
            prev_hash_short: truncate_hash(&e.prev_hash),
            signed: e.signature.is_some(),
            event_id: e.event_id.clone(),
            has_receipt: e.receipt.is_some(),
        })
        .collect())
}

fn print_events_table(events: &[EventDisplay]) {
    let has_sdk_events = events.iter().any(|e| e.event_id.is_some());

    if has_sdk_events {
        println!("\n{:>8} │ {:^23} │ {:^20} │ {:^10} │ {:^6} │ {:^8}",
            "SEQ", "TIMESTAMP", "EVENT TYPE", "HASH", "SIGNED", "RECEIPT");
        println!("{}", "─".repeat(90));

        for event in events {
            let receipt_status = if event.has_receipt { "✓ AUTH" } else { "- CLAIM" };
            println!("{:>8} │ {:^23} │ {:^20} │ {:^10} │ {:^6} │ {:^8}",
                event.sequence,
                &event.timestamp[..std::cmp::min(23, event.timestamp.len())],
                truncate_str(&event.event_type, 20),
                &event.payload_hash_short,
                if event.signed { "✓" } else { "-" },
                receipt_status
            );
        }
    } else {
        println!("\n{:>8} │ {:^23} │ {:^20} │ {:^15} │ {:^10} │ {:^6}",
            "SEQ", "TIMESTAMP", "EVENT TYPE", "SOURCE", "HASH", "SIGNED");
        println!("{}", "─".repeat(95));

        for event in events {
            println!("{:>8} │ {:^23} │ {:^20} │ {:^15} │ {:^10} │ {:^6}",
                event.sequence,
                &event.timestamp[..std::cmp::min(23, event.timestamp.len())],
                truncate_str(&event.event_type, 20),
                truncate_str(&event.source, 15),
                &event.payload_hash_short,
                if event.signed { "✓" } else { "-" }
            );
        }
    }

    println!();

    // Show legend for SDK format
    if has_sdk_events {
        println!("Legend: AUTH = Audit-grade proof (server receipt), CLAIM = Client integrity claim only");
    }
}

fn format_timestamp(ns: i64) -> String {
    // Safe conversion: handle timestamps outside nanosecond range (~1677 AD to ~2262 AD)
    // DateTime::from_timestamp_nanos panics on overflow, so we use fallback for edge cases
    const MAX_SAFE_NANOS: i64 = 9_000_000_000_000_000_000; // ~2255 AD, safe margin
    const MIN_SAFE_NANOS: i64 = -9_000_000_000_000_000_000; // ~1684 AD, safe margin

    if ns > MAX_SAFE_NANOS {
        // Far future timestamp - use seconds-based conversion
        let secs = ns / 1_000_000_000;
        let nsecs = (ns % 1_000_000_000) as u32;
        if let Some(dt) = chrono::DateTime::from_timestamp(secs, nsecs) {
            return dt.to_rfc3339();
        }
        return format!("OVERFLOW:{}", ns);
    }

    if ns < MIN_SAFE_NANOS {
        // Far past timestamp - use seconds-based conversion
        let secs = ns / 1_000_000_000;
        let nsecs = ((ns % 1_000_000_000).abs()) as u32;
        if let Some(dt) = chrono::DateTime::from_timestamp(secs, nsecs) {
            return dt.to_rfc3339();
        }
        return format!("UNDERFLOW:{}", ns);
    }

    chrono::DateTime::from_timestamp_nanos(ns).to_rfc3339()
}

fn truncate_hash(hash: &str) -> String {
    if hash.len() > 8 {
        format!("{}…", &hash[..8])
    } else {
        hash.to_string()
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }
    // Count characters, not bytes (safe for UTF-8)
    let char_count = s.chars().count();
    if char_count > max_len {
        // Take max_len - 1 chars and add ellipsis
        let truncated: String = s.chars().take(max_len - 1).collect();
        format!("{}…", truncated)
    } else {
        s.to_string()
    }
}

fn collect_segments(wal_path: &Path) -> Result<Vec<std::path::PathBuf>, Box<dyn std::error::Error>> {
    Ok(collect_wal_segments(wal_path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
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
    fn test_compute_stats_empty() {
        let dir = TempDir::new().unwrap();
        let stats = compute_stats(dir.path()).unwrap();

        assert_eq!(stats.total_events, 0);
        assert_eq!(stats.segment_count, 0);
        assert!(stats.chain_intact);
    }

    #[test]
    fn test_compute_stats_with_events() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        writeln!(file, "{}", create_test_entry(1, 1000, GENESIS_PREV_HASH, "p1")).unwrap();
        writeln!(file, "{}", create_test_entry(2, 2000, "hash1", "p2")).unwrap();

        let stats = compute_stats(dir.path()).unwrap();

        assert_eq!(stats.total_events, 2);
        assert_eq!(stats.segment_count, 1);
        assert_eq!(stats.first_sequence, Some(1));
        assert_eq!(stats.last_sequence, Some(2));
    }

    #[test]
    fn test_find_event() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        writeln!(file, "{}", create_test_entry(1, 1000, GENESIS_PREV_HASH, "p1")).unwrap();
        writeln!(file, "{}", create_test_entry(2, 2000, "hash1", "p2")).unwrap();

        let event = find_event(dir.path(), 2).unwrap();
        assert!(event.is_some());
        assert_eq!(event.unwrap().sequence, 2);

        let missing = find_event(dir.path(), 99).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_get_last_events() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        for i in 1..=10 {
            writeln!(file, "{}", create_test_entry(i, i as i64 * 1000, "prev", &format!("p{}", i))).unwrap();
        }

        let events = get_last_events(dir.path(), 3).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 8);
        assert_eq!(events[2].sequence, 10);
    }

    #[test]
    fn test_truncate_hash() {
        assert_eq!(truncate_hash("abcdef1234567890"), "abcdef12…");
        assert_eq!(truncate_hash("short"), "short");
    }
}
