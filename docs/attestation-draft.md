# Spine Attestation Format v0.3 (Draft)

## Structure

```json
{
  "version": "1.0",
  "type": "spine.attestation.v1",
  "attestation_id": "a1b2c3d4e5f6a1b2",

  "period": {
    "start": "2026-01-26T00:00:00Z",
    "end": "2026-01-26T23:59:59Z"
  },

  "ledger": {
    "stream_id": "app-prod-main",
    "first_seq": 1,
    "last_seq": 1234
  },

  "count": 1234,

  "root_hash": {
    "algo": "blake3",
    "value": "a1b2c3d4e5f6789..."
  },

  "pubkey": {
    "id": "spine_k1_abc123",
    "algo": "ed25519",
    "format": "raw32",
    "value": "base64..."
  },

  "verification": {
    "status": "VERIFIED",
    "checked_at": "2026-01-26T14:30:00Z",
    "tool": "spine-cli/0.4.0"
  },

  "generated_at": "2026-01-26T14:30:05Z",
  "generator": "spine-node/0.1.0"
}
```

## Field Semantics

### attestation_id

Deterministic. Computed as:

```
attestation_id = blake3(stream_id | period.start | period.end | root_hash.value).hex[0:16]
```

Enables deduplication on GRC platforms.

### generator vs verification.tool

| Field | Meaning |
|-------|---------|
| `generator` | Tool that created this attestation |
| `verification.tool` | Tool that performed the cryptographic verification |

These may differ (e.g., `spine-vanta-connector` generates, `spine-cli` verifies).

### count

```
count == last_seq - first_seq + 1  (when VERIFIED)
count <= last_seq - first_seq + 1  (when INCOMPLETE)
count == 0                          (when EMPTY)
```

### pubkey.format

| Value | Meaning |
|-------|---------|
| `raw32` | Ed25519 raw 32-byte public key, base64 encoded |

Using raw32 for cross-language compatibility.

## Optional Fields

Omit (don't set to null) when not applicable:

| Field | Include when |
|-------|--------------|
| `ledger.first_seq`, `ledger.last_seq` | status != EMPTY |
| `verification.missing_ranges` | status == INCOMPLETE |
| `batch` | batching enabled |
| `signature` | signing enabled (v1.0) |

## Status

| Value | Meaning |
|-------|---------|
| `VERIFIED` | Chain intact, signatures valid |
| `TAMPERED` | Hash or signature mismatch |
| `INCOMPLETE` | Gaps detected |
| `EMPTY` | No events in period |

## Example: INCOMPLETE

```json
{
  "verification": {
    "status": "INCOMPLETE",
    "checked_at": "2026-01-26T14:30:00Z",
    "tool": "spine-cli/0.4.0",
    "missing_ranges": [
      { "from": 120, "to": 140 }
    ]
  }
}
```

## Example: EMPTY

```json
{
  "ledger": {
    "stream_id": "app-prod-main"
  },
  "count": 0,
  "verification": {
    "status": "EMPTY",
    "checked_at": "2026-01-26T14:30:00Z",
    "tool": "spine-cli/0.4.0"
  }
}
```

## Signature (v1.0)

```json
"signature": {
  "algo": "ed25519",
  "format": "base64",
  "value": "...",
  "signed_fields": ["version", "type", "attestation_id", "period", "ledger", "count", "root_hash", "pubkey", "verification"]
}
```

### Signing procedure

1. Extract `signed_fields` from attestation
2. Serialize as canonical JSON (RFC 8785)
3. Sign UTF-8 bytes with Ed25519
4. Encode signature as base64 (standard, with padding)

Excludes: `signature`, `generated_at`, `generator`.
