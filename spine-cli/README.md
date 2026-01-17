# Spine CLI - Independent WAL Verification Tools

**Cryptographically verify audit trails without trusting the Spine server.**

These tools read WAL (Write-Ahead Log) files directly from disk and verify integrity using BLAKE3 hashing and Ed25519 signatures. Works with both Spine server WAL files and SDK-generated local WALs.

> This CLI verifies WAL integrity and structure.
> It does not generate legal attestations or replace certified audit processes.

## Features

- **Chain Integrity**: Verify hash chain links between entries
- **Signature Validation**: Ed25519 signature verification
- **Sequence Continuity**: Detect gaps in sequence numbers
- **Timestamp Monotonicity**: Ensure timestamps never regress
- **SDK Support**: Verify client-generated WALs (LocalRecord format)
- **Receipt Tracking**: Show which events have server attestation
- **Compliance Reports**: Generate DORA/NIS2-aligned audit summaries
- **Zero Server Trust**: Works offline, no network required

## Installation

```bash
cargo build --release
```

Binary will be at `target/release/spine-cli` (or `spine-cli.exe` on Windows).

### Requirements

- Rust 1.75.0 or later
- No runtime dependencies

## Usage

### Verify WAL Integrity

```bash
# Basic verification (internal consistency only)
spine-cli verify --wal /path/to/wal

# Full verification with external anchor
spine-cli verify --wal /path/to/wal --expected-root 0xabc123...

# Stop on first error
spine-cli verify --wal /path/to/wal --fail-fast

# JSON output
spine-cli verify --wal /path/to/wal -f json
```

### Inspect WAL Contents

```bash
# Show statistics
spine-cli inspect --wal /path/to/wal --stats

# Show last N events
spine-cli inspect --wal /path/to/wal -n 10

# Find specific event by sequence
spine-cli inspect --wal /path/to/wal --sequence 42
```

Output shows receipt status for SDK WALs:

```
     SEQ │        TIMESTAMP        │     EVENT TYPE     │    HASH    │ SIGNED │  RECEIPT
───────────────────────────────────────────────────────────────────────────────────────────
       1 │ 2025-01-15T10:30:00+00… │    user.login      │  7f8a9b0c… │   ✓    │ - CLAIM
       2 │ 2025-01-15T10:30:01+00… │    data.access     │  1a2b3c4d… │   ✓    │ ✓ AUTH

Legend: AUTH = Audit-grade proof (server receipt), CLAIM = Client integrity claim only
```

### Export Events

```bash
# Export all events
spine-cli export --wal /path/to/wal -o events.jsonl

# Export with time range
spine-cli export --wal /path/to/wal --from 2025-01-01 --to 2025-01-31 -o january.jsonl

# Include proofs in export
spine-cli export --wal /path/to/wal --include-proofs -o export.jsonl
```

### Generate Compliance Reports

```bash
# DORA compliance report
spine-cli report --wal /path/to/wal --template dora -o dora_report.json

# NIS2 compliance report
spine-cli report --wal /path/to/wal --template nis2 -o nis2_report.json

# Generic audit report
spine-cli report --wal /path/to/wal --template generic -o audit.json
```

## WAL Formats

### Spine Server Format

Traditional server-generated WAL with nanosecond timestamps:

```json
{
  "sequence": 1,
  "timestamp_ns": 1735000000000000000,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "payload_hash": "abc123def456...",
  "event_type": "auth.login",
  "source": "auth-service",
  "signature": "...",
  "public_key": "..."
}
```

### SDK LocalRecord Format

Client-generated WAL with ISO timestamps and receipt support:

```json
{
  "event_id": "evt_550e8400-e29b-41d4-a716-446655440000",
  "stream_id": "stream_a1b2c3d4e5f6g7h8",
  "seq": 1,
  "ts_client": "2025-01-15T10:30:00.123456+00:00",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "payload_hash": "544e479825ce9894e19dab2b7aa19a0416f4a28a68190bf884cc3525cab9df51",
  "hash_alg": "blake3",
  "payload": {"event_type": "user.login", "user_id": "alice"},
  "sig_client": "8b11e1ce0f7f23ab858b971fed8d76a325e48b9f3708d477...",
  "key_id": "kid_49f0b77a302a8ed4",
  "public_key": "862f70392e55bae96914b758a8959fa644df532bb82af9984ebe0a42c12237d8",
  "receipt": null
}
```

**Key differences from server format:**
- `seq` instead of `sequence`
- `ts_client` (ISO string) instead of `timestamp_ns` (nanoseconds)
- `sig_client` instead of `signature`
- `key_id` (short identifier) + `public_key` (full 64-char hex for verification)
- `prev_hash` is the **entry hash** of the previous record (not payload hash)

### Supported File Extensions

- `.wal` - WAL segment files (JSONL)
- `.jsonl` - JSON Lines format

Files are processed in lexicographic order by filename. Use zero-padded naming:
- `00000001.wal`, `00000002.wal`, ...

## Verification Checks

### Genesis Validation
- First entry must have `sequence = 1`
- First entry must have `prev_hash` = 64 zeros (null hash)

### Chain Integrity
- Each entry's `prev_hash` must equal hash of previous entry
- Hash computation: `BLAKE3(sequence || timestamp_ns || prev_hash || payload_hash)`
- BLAKE3 is required (no SHA-256 fallback for entry hash)

### Sequence Continuity
- Sequences must be consecutive: 1, 2, 3, ...
- Gaps indicate missing or deleted events

### Timestamp Monotonicity
- Timestamps must never decrease
- Regression indicates tampering or clock issues

### Signature Verification (Optional)
- Ed25519 signature over entry hash
- Signature is over UTF-8 bytes of hex-encoded hash string

## Understanding Verification Results

### Client Integrity Claim (No Receipt)

When events have no server receipt (`- CLAIM`):
- Chain is intact locally
- Signatures are valid
- But: no independent timestamp witness
- Proves: client didn't tamper after recording
- Cannot prove: when events actually occurred

### Audit-grade Proof (With Receipt)

When events have server receipt (`✓ AUTH`):
- Server witnessed and counter-signed
- Independent timestamp attestation
- Third-party verifiable

## Statistics Output

```bash
spine-cli inspect --wal ./audit_log --stats
```

```json
{
  "segment_count": 3,
  "total_events": 1247,
  "first_sequence": 1,
  "last_sequence": 1247,
  "total_size_bytes": 524288,
  "has_signatures": true,
  "chain_intact": true,
  "is_sdk_format": true,
  "stream_ids": ["sdk_a1b2c3/my-app"],
  "events_with_receipt": 1200,
  "events_without_receipt": 47
}
```

## Output Formats

### Text (default)
```
╔══════════════════════════════════════════════════════════════╗
║              SPINE WAL VERIFICATION REPORT                   ║
╠══════════════════════════════════════════════════════════════╣
║  Status: VALID                                               ║
║  Events verified: 1000                                       ║
║  Signatures verified: 1000                                   ║
║  Sequence range: 1 - 1000                                    ║
║  Chain root: abc123def456...                                 ║
╚══════════════════════════════════════════════════════════════╝
```

### JSON
```json
{
  "valid": true,
  "events_verified": 1000,
  "signatures_verified": 1000,
  "chain_root": "abc123def456...",
  "first_sequence": 1,
  "last_sequence": 1000,
  "errors": [],
  "warnings": []
}
```

## Error Types

| Error Type | Description |
|-----------|-------------|
| `invalid_genesis` | Genesis entry has wrong sequence or prev_hash |
| `chain_break` | Entry's prev_hash doesn't match predecessor |
| `sequence_gap` | Missing sequence number(s) |
| `timestamp_regression` | Timestamp decreased from previous entry |
| `invalid_signature` | Ed25519 signature verification failed |
| `invalid_hash_format` | Hash field not valid hex |
| `parse_error` | JSON parsing failed |
| `io_error` | File read error |

## Security Considerations

### External Anchor
Without `--expected-root`, verification only confirms internal consistency. An attacker who controls all WAL files could create a valid-looking but fake chain.

For full tamper-detection, compare `chain_root` against an external anchor (e.g., published hash, blockchain, trusted third party, or Spine server receipt).

### Signature Trust
Signature verification proves the entry was signed by the holder of the private key. It does not prove:
- The signer is authorized
- The event data is accurate
- The timestamp is correct (unless server receipt present)

### Receipt Verification
Server receipts provide independent attestation but require trusting the Spine server's timestamp. For maximum assurance, cross-reference with multiple anchors.

## Development

```bash
# Run tests
cargo test

# Run with debug output
RUST_LOG=debug cargo run -- verify --wal /path/to/wal

# Build release
cargo build --release
```

## Philosophy

Spine follows an open-core model:
- **Open Source**: CLI, verification tools, file formats, SDK
- **Proprietary**: Spine server (receipts, sealing, time attestation)

The CLI is designed to verify audit trails independently of the Spine server, providing trust-but-verify capability for auditors.

## License

Apache-2.0

## Related

- [Python SDK](../spine-sdk-python/) - Client library with hash chain and local WAL
- Spine Server - Proprietary audit trail engine with receipts
