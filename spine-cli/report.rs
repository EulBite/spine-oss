// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Eul Bite

//! Compliance report generation for regulatory requirements.
//!
//! Generates audit reports in formats suitable for:
//! - DORA (Digital Operational Resilience Act)
//! - NIS2 (Network and Information Security Directive)
//! - Generic compliance audits

use chrono::Utc;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::wal_types::{collect_wal_segments, compute_entry_hash, WalEntry, GENESIS_PREV_HASH};
use crate::ReportTemplate;

/// Compliance report structure
#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub report_metadata: ReportMetadata,
    pub verification_summary: VerificationSummary,
    pub chain_analysis: ChainAnalysis,
    pub compliance_checklist: Vec<ComplianceCheck>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ReportMetadata {
    pub report_id: String,
    pub generated_at: String,
    pub template: String,
    pub spine_cli_version: String,
    pub wal_path: String,
    pub signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerificationSummary {
    pub overall_status: String,
    pub events_verified: u64,
    pub signatures_verified: u64,
    pub chain_root: String,
    pub first_sequence: Option<u64>,
    pub last_sequence: Option<u64>,
    pub time_range_start: Option<String>,
    pub time_range_end: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChainAnalysis {
    pub chain_intact: bool,
    pub sequence_gaps: Vec<u64>,
    pub timestamp_regressions: Vec<u64>,
    pub unsigned_events: u64,
    pub segment_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ComplianceCheck {
    pub requirement: String,
    pub status: String,
    pub details: String,
}

pub fn run(
    wal_path: &Path,
    output_path: &Path,
    template: ReportTemplate,
) -> Result<bool, Box<dyn std::error::Error>> {
    let report = generate_report(wal_path, template)?;

    let mut file = File::create(output_path)?;
    let json = serde_json::to_string_pretty(&report)?;
    file.write_all(json.as_bytes())?;

    eprintln!("Report generated: {}", output_path.display());
    eprintln!("  Template: {:?}", template);
    eprintln!(
        "  Events verified: {}",
        report.verification_summary.events_verified
    );
    eprintln!("  Status: {}", report.verification_summary.overall_status);

    Ok(report.verification_summary.overall_status == "PASS")
}

fn generate_report(
    wal_path: &Path,
    template: ReportTemplate,
) -> Result<ComplianceReport, Box<dyn std::error::Error>> {
    let analysis = analyze_wal(wal_path)?;
    let template_name = match template {
        ReportTemplate::Dora => "DORA",
        ReportTemplate::Nis2 => "NIS2",
        ReportTemplate::Generic => "Generic",
    };

    let overall_status = if analysis.chain_intact
        && analysis.sequence_gaps.is_empty()
        && analysis.timestamp_regressions.is_empty()
    {
        "PASS"
    } else {
        "FAIL"
    };

    let checklist = generate_checklist(template, &analysis);
    let recommendations = generate_recommendations(&analysis);

    Ok(ComplianceReport {
        report_metadata: ReportMetadata {
            report_id: format!("RPT-{}", Utc::now().format("%Y%m%d-%H%M%S")),
            generated_at: Utc::now().to_rfc3339(),
            template: template_name.to_string(),
            spine_cli_version: env!("CARGO_PKG_VERSION").to_string(),
            wal_path: wal_path.display().to_string(),
            signature: None,
        },
        verification_summary: VerificationSummary {
            overall_status: overall_status.to_string(),
            events_verified: analysis.total_events,
            signatures_verified: analysis.signatures_found,
            chain_root: analysis.chain_root,
            first_sequence: analysis.first_sequence,
            last_sequence: analysis.last_sequence,
            time_range_start: analysis.first_timestamp.map(format_timestamp),
            time_range_end: analysis.last_timestamp.map(format_timestamp),
        },
        chain_analysis: ChainAnalysis {
            chain_intact: analysis.chain_intact,
            sequence_gaps: analysis.sequence_gaps,
            timestamp_regressions: analysis.timestamp_regressions,
            unsigned_events: analysis.total_events - analysis.signatures_found,
            segment_count: analysis.segment_count,
        },
        compliance_checklist: checklist,
        recommendations,
    })
}

struct WalAnalysis {
    total_events: u64,
    signatures_found: u64,
    chain_intact: bool,
    chain_root: String,
    first_sequence: Option<u64>,
    last_sequence: Option<u64>,
    first_timestamp: Option<i64>,
    last_timestamp: Option<i64>,
    sequence_gaps: Vec<u64>,
    timestamp_regressions: Vec<u64>,
    segment_count: usize,
}

fn analyze_wal(wal_path: &Path) -> Result<WalAnalysis, Box<dyn std::error::Error>> {
    let mut analysis = WalAnalysis {
        total_events: 0,
        signatures_found: 0,
        chain_intact: true,
        chain_root: String::new(),
        first_sequence: None,
        last_sequence: None,
        first_timestamp: None,
        last_timestamp: None,
        sequence_gaps: Vec::new(),
        timestamp_regressions: Vec::new(),
        segment_count: 0,
    };

    let segments = collect_segments(wal_path)?;
    analysis.segment_count = segments.len();

    let mut prev_hash: Option<String> = None;
    let mut prev_sequence: Option<u64> = None;
    let mut prev_timestamp: Option<i64> = None;
    let mut hasher = blake3::Hasher::new();

    for segment_path in &segments {
        let file = File::open(segment_path)?;
        let reader = BufReader::new(file);

        for line_result in reader.lines() {
            let line = line_result?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: WalEntry = serde_json::from_str(&line)?;

            if analysis.first_sequence.is_none() {
                analysis.first_sequence = Some(entry.sequence);
                analysis.first_timestamp = Some(entry.timestamp_ns);
            }
            analysis.last_sequence = Some(entry.sequence);
            analysis.last_timestamp = Some(entry.timestamp_ns);
            analysis.total_events += 1;

            if entry.signature.is_some() {
                analysis.signatures_found += 1;
            }

            let expected_prev = prev_hash.as_deref().unwrap_or(GENESIS_PREV_HASH);
            if entry.prev_hash != expected_prev {
                analysis.chain_intact = false;
            }

            if let Some(prev_seq) = prev_sequence {
                if entry.sequence != prev_seq + 1 {
                    analysis.sequence_gaps.push(prev_seq + 1);
                }
            }

            if let Some(prev_ts) = prev_timestamp {
                if entry.timestamp_ns < prev_ts {
                    analysis.timestamp_regressions.push(entry.sequence);
                }
            }

            let entry_hash = compute_entry_hash(&entry);
            hasher.update(entry_hash.as_bytes());
            prev_hash = Some(entry_hash);
            prev_sequence = Some(entry.sequence);
            prev_timestamp = Some(entry.timestamp_ns);
        }
    }

    analysis.chain_root = hex::encode(hasher.finalize().as_bytes());
    Ok(analysis)
}

fn generate_checklist(template: ReportTemplate, analysis: &WalAnalysis) -> Vec<ComplianceCheck> {
    let mut checks = vec![
        ComplianceCheck {
            requirement: "Chain Integrity".to_string(),
            status: if analysis.chain_intact {
                "PASS"
            } else {
                "FAIL"
            }
            .to_string(),
            details: if analysis.chain_intact {
                "All events are cryptographically linked".to_string()
            } else {
                "Chain breaks detected - possible tampering".to_string()
            },
        },
        ComplianceCheck {
            requirement: "Sequence Continuity".to_string(),
            status: if analysis.sequence_gaps.is_empty() {
                "PASS"
            } else {
                "FAIL"
            }
            .to_string(),
            details: if analysis.sequence_gaps.is_empty() {
                "No sequence gaps detected".to_string()
            } else {
                format!("Gaps found at sequences: {:?}", analysis.sequence_gaps)
            },
        },
        ComplianceCheck {
            requirement: "Timestamp Monotonicity".to_string(),
            status: if analysis.timestamp_regressions.is_empty() {
                "PASS"
            } else {
                "WARN"
            }
            .to_string(),
            details: if analysis.timestamp_regressions.is_empty() {
                "All timestamps are monotonically increasing".to_string()
            } else {
                format!(
                    "Regressions at sequences: {:?}",
                    analysis.timestamp_regressions
                )
            },
        },
    ];

    // Add template-specific checks
    match template {
        ReportTemplate::Dora => {
            checks.push(ComplianceCheck {
                requirement: "DORA Art. 12 - ICT Logging".to_string(),
                status: if analysis.total_events > 0 {
                    "PASS"
                } else {
                    "FAIL"
                }
                .to_string(),
                details: format!("{} events recorded for audit trail", analysis.total_events),
            });
            checks.push(ComplianceCheck {
                requirement: "DORA Art. 12 - Integrity Protection".to_string(),
                status: if analysis.chain_intact {
                    "PASS"
                } else {
                    "FAIL"
                }
                .to_string(),
                details: "Cryptographic hash chain protects log integrity".to_string(),
            });
        }
        ReportTemplate::Nis2 => {
            checks.push(ComplianceCheck {
                requirement: "NIS2 Art. 21 - Security Measures".to_string(),
                status: if analysis.chain_intact {
                    "PASS"
                } else {
                    "FAIL"
                }
                .to_string(),
                details: "Audit logs are cryptographically protected".to_string(),
            });
            checks.push(ComplianceCheck {
                requirement: "NIS2 Art. 23 - Incident Reporting".to_string(),
                status: "INFO".to_string(),
                details: format!(
                    "Audit trail contains {} events for incident analysis",
                    analysis.total_events
                ),
            });
        }
        ReportTemplate::Generic => {
            checks.push(ComplianceCheck {
                requirement: "Digital Signatures".to_string(),
                status: if analysis.signatures_found > 0 {
                    "PASS"
                } else {
                    "WARN"
                }
                .to_string(),
                details: format!(
                    "{}/{} events have digital signatures",
                    analysis.signatures_found, analysis.total_events
                ),
            });
        }
    }

    checks
}

fn generate_recommendations(analysis: &WalAnalysis) -> Vec<String> {
    let mut recommendations = Vec::new();

    if !analysis.chain_intact {
        recommendations.push(
            "CRITICAL: Chain integrity compromised. Investigate potential tampering.".to_string(),
        );
    }

    if !analysis.sequence_gaps.is_empty() {
        recommendations.push(format!(
            "WARNING: {} sequence gaps detected. Review log collection infrastructure.",
            analysis.sequence_gaps.len()
        ));
    }

    if analysis.signatures_found == 0 && analysis.total_events > 0 {
        recommendations.push(
            "NOTICE: No digital signatures found. Consider enabling WAL signing for enhanced non-repudiation.".to_string()
        );
    }

    if analysis.total_events == 0 {
        recommendations
            .push("WARNING: No events found. Verify WAL path and log collection.".to_string());
    }

    if recommendations.is_empty() {
        recommendations.push("No issues detected. Audit trail is compliant.".to_string());
    }

    recommendations
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

fn collect_segments(wal_path: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
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
    fn test_analyze_empty_wal() {
        let dir = TempDir::new().unwrap();
        let analysis = analyze_wal(dir.path()).unwrap();

        assert_eq!(analysis.total_events, 0);
        assert!(analysis.chain_intact);
    }

    #[test]
    fn test_analyze_with_events() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        writeln!(
            file,
            "{}",
            create_test_entry(1, 1000, GENESIS_PREV_HASH, "p1")
        )
        .unwrap();

        let analysis = analyze_wal(dir.path()).unwrap();

        assert_eq!(analysis.total_events, 1);
        assert!(analysis.chain_intact);
        assert_eq!(analysis.first_sequence, Some(1));
    }

    #[test]
    fn test_generate_report_dora() {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("00000001.wal");
        let mut file = File::create(&wal_file).unwrap();

        writeln!(
            file,
            "{}",
            create_test_entry(1, 1000, GENESIS_PREV_HASH, "p1")
        )
        .unwrap();

        let report = generate_report(dir.path(), ReportTemplate::Dora).unwrap();

        assert_eq!(report.verification_summary.overall_status, "PASS");
        assert!(report
            .compliance_checklist
            .iter()
            .any(|c| c.requirement.contains("DORA")));
    }

    #[test]
    fn test_recommendations_for_broken_chain() {
        let analysis = WalAnalysis {
            total_events: 10,
            signatures_found: 0,
            chain_intact: false,
            chain_root: String::new(),
            first_sequence: Some(1),
            last_sequence: Some(10),
            first_timestamp: Some(1000),
            last_timestamp: Some(10000),
            sequence_gaps: vec![5],
            timestamp_regressions: Vec::new(),
            segment_count: 1,
        };

        let recommendations = generate_recommendations(&analysis);

        assert!(recommendations.iter().any(|r| r.contains("CRITICAL")));
        assert!(recommendations.iter().any(|r| r.contains("sequence gaps")));
    }
}
