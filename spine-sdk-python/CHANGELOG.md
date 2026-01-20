# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-01-20

### Added

- **Unicode NFC normalization** in `canonical_json()` - Ensures equivalent Unicode sequences (e.g., `é` vs `e+combining accent`) produce identical hashes
- **`format_version` field** in WAL records - Enables forward compatibility for future format changes
- **`WAL_FORMAT_VERSION` constant** - Exported for version checking
- **Test vectors** (`test-vectors/vectors.json`) - Public test cases for cross-implementation verification
- **Documentation**:
  - `docs/KEY_MANAGEMENT.md` - Key generation, rotation, and revocation procedures
  - `docs/WAL_FORMAT.md` - Complete WAL format specification

### Changed

- Records now include `format_version: 1` field (defaults to 1 for backwards compatibility)
- `canonical_json()` now applies NFC normalization before serialization

## [0.2.0] - 2026-01-17

### Breaking Changes

- **`unsynced_records(limit)` now requires `limit` parameter** - No default value to prevent silent truncation of results. Call `unsynced_count()` to get the total count.
- **BLAKE3 is now required** - The SDK will raise `RuntimeError` when computing hashes if `blake3` is not installed. Install with: `pip install blake3`
- **Python 3.10+ required** - Uses `X | None` union syntax

### Added

- `WAL.unsynced_count()` - Memory-efficient count of unsynced records
- `LocalRecord.public_key` field - Full public key (64 hex chars) for CLI signature verification
- `compute_entry_hash()` - Compute entry hash for chain linking (CLI-compatible)
- `timestamp_to_nanos()` - Convert ISO timestamp to nanoseconds with integer precision

### Changed

- **`SpineClient` fallback now uses signed `WAL`** - Offline events are now CLI-verifiable with Ed25519 signatures and BLAKE3 hash chains (was: plain `LocalWAL` without crypto)
- `SpineClient` parameters renamed: `enable_local_wal` → `enable_wal_fallback`, `local_wal_dir` → `wal_dir`
- `SpineClient` accepts optional `signing_key` parameter (auto-generates if not provided)
- Chain linking now uses **entry hash** (not payload hash) for `prev_hash`
- Signature is now over **entry hash** (binds seq, timestamp, chain position)
- Entry hash always uses BLAKE3 for CLI compatibility
- Timestamp conversion uses integer arithmetic to avoid float precision loss

### Deprecated

- **`LocalWAL` is deprecated** - Use `WAL` with `SigningKey` instead. `LocalWAL` does not provide cryptographic signatures and cannot be verified with `spine-cli`. Emits `DeprecationWarning` on instantiation.

### Fixed

- CLI compatibility: SDK-generated WALs now pass `spine-cli verify`
- Memory usage: `_load_receipts()` now supports filtering by event IDs
- `get_stats()` now uses `unsynced_count()` instead of truncated list

## [0.1.0] - 2025-01-01

### Added

- Initial release
- WAL with Ed25519 signing and hash chain
- SpineClient for server integration
- Circuit breaker for resilience
- Local verification (verify_wal, verify_chain, verify_record)
