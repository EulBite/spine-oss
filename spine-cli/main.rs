// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2025 Eul Bite

//! Spine CLI - Independent Audit Trail Verification
//!
//! Standalone tool for verifying WAL integrity without trusting the Spine server.
//! Designed for auditors and compliance officers who need independent verification.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

mod verify;
mod export;
mod inspect;
mod report;
mod wal_types;

/// Spine CLI - Cryptographic Audit Trail Tools
///
/// Standalone tools for verifying, exporting, and inspecting WAL files
/// without trusting the Spine server.
#[derive(Parser)]
#[command(name = "spine-cli")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format (json, text, or quiet)
    #[arg(short, long, default_value = "text", global = true)]
    format: OutputFormat,

    /// Verbose output for debugging
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Verify integrity of a WAL directory
    Verify {
        /// Path to WAL directory
        #[arg(short, long)]
        wal: PathBuf,

        /// Optional: verify against known root hash
        #[arg(long)]
        expected_root: Option<String>,

        /// Output verification report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Fail on first error (default: continue and report all)
        #[arg(long)]
        fail_fast: bool,
    },

    /// Export audit trail for external tools
    Export {
        /// Path to WAL directory
        #[arg(short, long)]
        wal: PathBuf,

        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Export format (jsonl, csv, or syslog)
        #[arg(long, default_value = "jsonl")]
        export_format: ExportFormat,

        /// Time range start (ISO 8601)
        #[arg(long)]
        from: Option<String>,

        /// Time range end (ISO 8601)
        #[arg(long)]
        to: Option<String>,

        /// Include cryptographic proofs in export
        #[arg(long)]
        include_proofs: bool,
    },

    /// Human-readable inspection of WAL contents
    Inspect {
        /// Path to WAL directory
        #[arg(short, long)]
        wal: PathBuf,

        /// Show last N events (default: 10)
        #[arg(short = 'n', long, default_value = "10")]
        last: usize,

        /// Show specific event by sequence number
        #[arg(long)]
        sequence: Option<u64>,

        /// Show chain statistics
        #[arg(long)]
        stats: bool,
    },

    /// Generate verification report for compliance
    Report {
        /// Path to WAL directory
        #[arg(short, long)]
        wal: PathBuf,

        /// Output report file
        #[arg(short, long)]
        output: PathBuf,

        /// Report template (dora, nis2, generic)
        #[arg(long, default_value = "generic")]
        template: ReportTemplate,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
    Quiet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    Jsonl,
    Csv,
    Syslog,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ReportTemplate {
    Dora,
    Nis2,
    Generic,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Allow RUST_LOG to override --verbose flag
    let default_level = if cli.verbose { "debug" } else { "info" };
    let env_filter = std::env::var("RUST_LOG").unwrap_or_else(|_| default_level.to_string());

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();

    let result = match &cli.command {
        Commands::Verify {
            wal,
            expected_root,
            output,
            fail_fast,
        } => verify::run(
            wal,
            expected_root.as_deref(),
            output.as_deref(),
            *fail_fast,
            cli.format,
        ),

        Commands::Export {
            wal,
            output,
            export_format,
            from,
            to,
            include_proofs,
        } => export::run(
            wal,
            output.as_deref(),
            *export_format,
            from.as_deref(),
            to.as_deref(),
            *include_proofs,
            cli.format,
        ),

        Commands::Inspect {
            wal,
            last,
            sequence,
            stats,
        } => inspect::run(wal, *last, *sequence, *stats),

        Commands::Report {
            wal,
            output,
            template,
        } => generate_report(wal, output, *template),
    };

    match result {
        Ok(success) => {
            if success {
                if cli.format != OutputFormat::Quiet {
                    eprintln!("✓ Operation completed successfully");
                }
                ExitCode::SUCCESS
            } else {
                if cli.format != OutputFormat::Quiet {
                    eprintln!("✗ Operation completed with issues - see output for details");
                }
                ExitCode::from(1)
            }
        }
        Err(e) => {
            if cli.format != OutputFormat::Quiet {
                eprintln!("Error: {e}");
            }
            ExitCode::from(2)
        }
    }
}

fn generate_report(
    wal: &PathBuf,
    output: &PathBuf,
    template: ReportTemplate,
) -> Result<bool, Box<dyn std::error::Error>> {
    report::run(wal, output, template)
}