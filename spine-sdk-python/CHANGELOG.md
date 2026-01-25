# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-01-25

### Fixed

- **AuditSidecar: Semaphore leak on cancellation** - Fixed permit leak when `_add_to_buffer()` was cancelled during `block` policy. Added `acquired/enqueued` flags with proper cleanup in `finally` block
- **AuditSidecar: Double exponential backoff** - Removed redundant external backoff in `_sender_loop()`, keeping only internal retry backoff
- **AuditSidecar: stop() race condition** - Buffer reads during flush now protected by `_buffer_lock`
- **AuditSidecar: try_emit() infinite buffer growth** - Fixed `drop_oldest` policy to actually evict oldest events (was missing after removing `maxlen`)
- **AuditSidecar: try_emit() + block policy** - Now returns `False` immediately instead of breaking semaphore accounting
- **AuditSidecar: max_backoff_ms ignored** - Retry backoff now capped at `max_backoff_ms`
- **AuditSidecar: enable_local_wal contradiction** - Set `enable_local_wal=False` to match "in-memory only" documentation
- **SpineClient: urljoin path eating** - Added `_build_url()` method to handle base URLs with paths correctly (e.g., `http://host/spine/api`)
- **SpineClient: WAL sync infinite loop** - Records now marked as synced with synthetic receipt when server doesn't return one
- **SpineClient: Task leak on shutdown** - `__aexit__` now awaits cancelled tasks with `asyncio.gather(..., return_exceptions=True)`
- **SpineClient: max_retries unused** - Now implements exponential backoff retry in `_send_request()`
- **canonical_json: Float values** - Now rejects floats with `TypeError` (RFC8785 canonicalization not guaranteed by Python)
- **SigningKey.from_env: Fragile base64 detection** - Removed length heuristics, uses `base64.b64decode(validate=True)` with try/except

### Added

- **AuditSidecar: try_emit()** - Truly non-blocking synchronous emit for latency-critical paths
- **AuditSidecar: overflow_policy validation** - Invalid policies now raise `ValueError` immediately
- **AuditSidecar: Enhanced is_healthy** - Detects stale sends (>60s) and failed startup (>30s grace period)
- **AuditSidecar: Client None guard** - `_sender_loop()` handles edge case where `_client` is None
- **SpineClient: connect_timeout_ms** - Separate connection establishment timeout in `ClientConfig`
- **SpineClient: Key persistence warning** - Logs warning with guidance when auto-generating signing key
- **SpineClient: log_async() error** - Clear error message when called without running event loop
- **AuditEvent: Payload validation** - Uses `canonical_json()` for consistent validation (rejects floats, NFC normalization)
- **AuditEvent: Idempotency key guidance** - Docstring explains deterministic keys for dedup across retries

### Changed

- **AuditSidecar documentation** - Clarified timing guarantees (best-effort), block policy caveats, thread safety notes
- **SigningKey.from_bytes → from_seed_bytes** - Renamed for BYOK clarity (accepts 32-byte seed, not expanded key)
- **AuditEvent.to_json()** - Now uses deterministic settings (`sort_keys=True`, `separators`, `ensure_ascii=False`)
- **crypto.py architecture note** - Documented future refactor for Receipt verification with server key

## [0.4.0] - 2026-01-24

### Security

- **Chain of trust signature verification** - Rotation records are now verified BEFORE trusting the new key. Previously, `extract_key_chain()` could be tricked with forged rotation records. Now signatures must be valid under the current trusted key before adding new keys to the trust chain.

### Fixed

- **Critical: stream_id persistence after key rotation** - `stream_id` is now persisted independently in `stream.meta.json`. Previously, `stream_id` was derived from the initial `key_id`, causing WAL recovery to fail after key rotation + restart (old records appeared to belong to a different stream).
- **`verify_chain_with_root()` ignored `strict_file_order` flag** - Was always using forensic mode internally, now correctly honors the user's choice
- **Explicit BLAKE3 in `_rebuild_state_from_segments()`** - Hardening: explicitly specifies `algorithm=HashAlgorithm.BLAKE3` to prevent divergence if default changes
- **`compute_entry_hash()` now enforces BLAKE3** - Raises `ValueError` if called with non-BLAKE3 algorithm. Previously the "BLAKE3 required" contract was documented but not enforced at runtime

### Changed

- **Verification mode in results** - `verify_chain()` and `verify_wal()` now include `mode` in `result.details` (`"forensic"` or `"resilient"`) for audit interpretation
- **CLI shows verification mode** - `spine-sdk verify` now displays the mode used
- **Removed unused `max_segments`** - Removed from `WALConfig` (was defined but never used)

### Added

- **Corrupted lines diagnostic** - `_rebuild_state_from_segments()` now counts and logs corrupted lines skipped during recovery
- **Test: `test_key_rotation_survives_restart`** - Verifies stream_id stability across key rotation and WAL restart
- **Test: `test_forged_rotation_record_rejected`** - Verifies forged rotation records with invalid signatures are rejected

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

## [0.1.0] - 2026-01-01

### Added

- Initial release
- WAL with Ed25519 signing and hash chain
- SpineClient for server integration
- Circuit breaker for resilience
- Local verification (verify_wal, verify_chain, verify_record)
