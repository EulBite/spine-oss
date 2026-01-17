# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-17

### Added

- Initial public release
- `verify` command - Full cryptographic verification (hash chain + Ed25519 signatures)
- `inspect` command - View WAL contents with `--stats` for summary
- `export` command - Export to CSV/JSON formats
- `report` command - Generate verification reports
- JSON output mode (`--json`) for all commands
- Colored terminal output with verification status

### Compatibility

- Compatible with `spine-sdk-python` v0.2.0+
- Requires BLAKE3 hash algorithm for entry hash verification
- Ed25519 signature verification using `ed25519-dalek`

### Technical

- Entry hash: `BLAKE3(seq || timestamp_ns || prev_hash || payload_hash)` (little-endian)
- Signature over entry hash (not payload) - binds position, time, and chain state
