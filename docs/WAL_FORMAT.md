# WAL Format Specification

**Version**: 1
**Status**: Stable
**Last Updated**: 2025-01-20

## Overview

The Write-Ahead Log (WAL) is the core data structure for Spine audit logging.
Each record is cryptographically linked to form a tamper-evident chain.

## Format Version

Current version: **1**

The `format_version` field enables forward compatibility. Implementations MUST:
- Include `format_version` in all new records
- Default to version 1 when reading records without this field
- Reject records with unsupported version numbers

## Record Structure

Each WAL record is a JSON object stored as a single line (JSONL format).

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `format_version` | int | Format version (currently 1) |
| `event_id` | string | Unique event identifier (e.g., `evt_<uuid>`) |
| `stream_id` | string | Stream identifier (e.g., `stream_<hash>`) |
| `seq` | int | Monotonic sequence number (1-indexed) |
| `prev_hash` | string | Previous entry hash (64 hex chars) |
| `ts_client` | string | Client timestamp (RFC 3339) |
| `payload` | object | Event data |
| `payload_hash` | string | BLAKE3 hash of canonical payload (64 hex chars) |
| `hash_alg` | string | Hash algorithm (`blake3` or `sha256`) |
| `sig_client` | string | Ed25519 signature (128 hex chars) |
| `key_id` | string | Signing key identifier |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | string | Full public key hex (64 chars) for offline verification |
| `receipt` | object | Server receipt (when synced) |

### Example Record

```json
{
  "format_version": 1,
  "event_id": "evt_01HQ8XYZABC123",
  "stream_id": "stream_a1b2c3d4e5f6",
  "seq": 1,
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "ts_client": "2025-01-15T12:00:00.000000+00:00",
  "payload": {
    "event_type": "user.login",
    "user_id": "alice",
    "ip_address": "192.168.1.1"
  },
  "payload_hash": "ff4ae8aaf47e8bea7408a02304573acf9dcd21d103a8126b355430ba38d7156d",
  "hash_alg": "blake3",
  "sig_client": "a1b2c3d4...128_hex_chars...",
  "key_id": "kid_prod_2025_01",
  "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
}
```

## Canonical JSON

Payloads are serialized to canonical JSON before hashing:

1. **Unicode NFC normalization** applied to all strings
2. **Keys sorted** lexicographically (Unicode code points)
3. **No whitespace** between elements
4. **UTF-8 encoding**

### Rules

```
canonical_json({"b": 1, "a": 2}) = '{"a":2,"b":1}'
canonical_json({"café": 1})     = '{"café":1}'  (NFC normalized)
```

## Hash Computation

### Payload Hash

```
payload_hash = BLAKE3(canonical_json(payload))
```

Output: 64-character lowercase hex string.

### Entry Hash

The entry hash links records and is signed:

```
entry_hash = BLAKE3(
    seq.to_le_bytes(8) ||           // u64 little-endian
    timestamp_ns.to_le_bytes(8) ||  // i64 little-endian
    prev_hash.as_utf8_bytes() ||    // hex string as UTF-8
    payload_hash.as_utf8_bytes()    // hex string as UTF-8
)
```

### Binary Format Details

| Component | Size | Format | Example |
|-----------|------|--------|---------|
| seq | 8 bytes | u64 LE | `0100000000000000` (seq=1) |
| timestamp_ns | 8 bytes | i64 LE | nanoseconds since epoch |
| prev_hash | 64 bytes | UTF-8 | hex string as bytes |
| payload_hash | 64 bytes | UTF-8 | hex string as bytes |

## Signature

```
signature = Ed25519_Sign(private_key, entry_hash.as_utf8_bytes())
```

The signature covers the hex-encoded entry hash as UTF-8 bytes (64 ASCII chars).

## Chain Rules

### Genesis Record

The first record in a chain MUST have:
- `seq = 1`
- `prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"` (64 zeros)

### Chain Linking

For record N (where N > 1):
- `seq = N`
- `prev_hash = entry_hash(record N-1)`

### Timestamp Monotonicity

Timestamps MUST be monotonically increasing within a chain:
- `record[N].timestamp_ns >= record[N-1].timestamp_ns`

## File Format

### Segment Files

WAL records are stored in segment files:

```
data_dir/
  segment_20250115_120000.jsonl
  segment_20250115_130000.jsonl
  chain_state.json
  receipts.jsonl
```

**Naming Convention**: `segment_YYYYMMDD_HHMMSS.jsonl`

### JSONL Format

Each line is a complete JSON record:

```jsonl
{"format_version":1,"event_id":"evt_001","seq":1,...}
{"format_version":1,"event_id":"evt_002","seq":2,...}
{"format_version":1,"event_id":"evt_003","seq":3,...}
```

- One record per line
- No trailing commas
- UTF-8 encoded
- LF line endings (Unix-style)

## Verification

### Chain Integrity

1. Parse all records in sequence order
2. For each record:
   - Verify `payload_hash = BLAKE3(canonical_json(payload))`
   - Compute `entry_hash`
   - Verify `Ed25519_Verify(public_key, entry_hash, sig_client)`
   - If not genesis: verify `prev_hash = entry_hash(previous_record)`
3. Check sequence continuity (no gaps)
4. Check timestamp monotonicity

### Error Types

| Error | Description |
|-------|-------------|
| `invalid_genesis` | Genesis has wrong seq or prev_hash |
| `chain_break` | prev_hash doesn't match previous entry_hash |
| `sequence_gap` | Missing sequence number |
| `timestamp_regression` | Timestamp went backwards |
| `invalid_signature` | Signature verification failed |
| `invalid_hash` | payload_hash doesn't match payload |

## Receipt Structure (Optional)

When synced to Spine server:

```json
{
  "event_id": "evt_001",
  "payload_hash": "ff4ae8aa...",
  "server_time": "2025-01-15T12:00:01.000Z",
  "server_seq": 12345,
  "receipt_sig": "server_signature...",
  "server_key_id": "server_prod_2025",
  "sig_alg": "ed25519",
  "batch_id": "batch_2025011512"
}
```

## Compatibility

### Field Aliases

For interoperability, implementations SHOULD accept these aliases:

| Canonical | Aliases |
|-----------|---------|
| `seq` | `sequence` |
| `ts_client` | `ts`, `timestamp`, `ts_ns`, `timestamp_ns` |
| `prev_hash` | `previous_hash`, `prev` |
| `payload_hash` | `hash`, `event_hash` |
| `sig_client` | `sig`, `signature` |
| `public_key` | `pubkey`, `pk` |

### Version Compatibility

| Reader Version | Writer Version 1 |
|----------------|------------------|
| 1 | Full support |
| Future | Read v1, warn if unknown fields |

## Security Considerations

1. **Private keys**: Never include in WAL records
2. **Payload data**: May contain sensitive data, encrypt at rest
3. **Timestamps**: Client timestamps are claims, not proofs
4. **Signatures**: Prove authorship, not time or server acceptance

## References

- [Test Vectors](../test-vectors/README.md)
- [Key Management](./KEY_MANAGEMENT.md)
- RFC 8785: JSON Canonicalization Scheme (JCS)
- RFC 8032: Ed25519 Signatures
