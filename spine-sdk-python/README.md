# Spine Python SDK

**Cryptographic audit logging with local integrity and optional server attestation.**

Build tamper-evident audit trails with Ed25519 signatures and hash chains. **No server required** - verify locally with `spine-cli`.

## What This SDK Does

1. **Creates signed audit logs** - Ed25519 signatures + BLAKE3 hash chains
2. **Stores locally** - Append-only WAL files on your filesystem
3. **Verifies independently** - Use `spine-cli` to verify without trusting anyone

> **Optional**: Connect to Spine server for third-party timestamping and audit-grade proof.

## Trust Model

| Mode | What You Get | Use Case |
|------|--------------|----------|
| **Standalone** | Hash chain + Ed25519 signatures + CLI verification | Internal audits, compliance evidence, forensics |
| **With Spine Server** | + Independent timestamps + Server receipts | Regulatory requirements, third-party audits |

**Standalone is production-ready**: detect tampering, prove sequence, verify signatures with `spine-cli`.

## Features

- **Hash Chain**: Every record links to previous via BLAKE3
- **Ed25519 Signing**: Cryptographic signatures bind payload to chain position
- **CLI Verification**: Verify with `spine-cli` - no server, no trust required
- **WAL Storage**: Append-only segments with configurable retention
- **Async/Await**: Built on `aiohttp` and `aiofiles`
- **Optional Server**: Connect to Spine for receipts (not required)

## Installation

```bash
pip install -e .
```

### Requirements

- Python 3.10+
- aiohttp, aiofiles
- **blake3** (required for CLI compatibility)
- cryptography (Ed25519)

> **Important**: BLAKE3 is required for `spine-cli` verification compatibility.

## Quick Start

```python
import asyncio
from spine_client import WAL, WALConfig, SigningKey, verify_wal

async def main():
    # Generate signing key
    key = SigningKey.generate()
    print(f"Key ID: {key.key_id}")

    # Create WAL
    config = WALConfig(data_dir="./audit_log", retention_hours=72)
    wal = WAL(key, config, namespace="my-app")
    await wal.initialize()

    # Log events
    record = await wal.append({
        "event_type": "user.login",
        "user_id": "alice",
        "ip": "192.168.1.1"
    })
    print(f"Logged: seq={record.seq}, hash={record.payload_hash[:16]}...")

    # Verify chain integrity
    result = await verify_wal(wal)
    print(f"Verification: {result.status.value}")
    print(f"Authoritative: {result.is_authoritative}")  # False without receipts

asyncio.run(main())
```

Then verify with CLI (no server needed):

```bash
spine-cli verify --wal ./audit_log
```

```
SPINE WAL VERIFICATION REPORT
=============================
Status:              VALID
Events verified:     1
Signatures verified: 1
Sequence range:      1 - 1
Chain root:          7f8a9b0c1d2e3f4a...
```

## CLI Verification

Use `spine-cli` to independently verify WAL files without trusting the SDK:

```bash
# Show WAL statistics
spine-cli inspect --wal ./audit_log --stats

# Show last 10 events
spine-cli inspect --wal ./audit_log -n 10

# Full cryptographic verification
spine-cli verify --wal ./audit_log

# Export for analysis
spine-cli export --wal ./audit_log --format csv -o events.csv
```

## Verification Levels

### Local Verification (Default)

```python
result = await verify_wal(wal)

if result.valid:
    # Chain is intact, signatures valid
    # But: only proves client didn't tamper AFTER recording
    print(f"Status: {result.status.value}")  # "valid" or "no_receipt"
    print(f"Authoritative: {result.is_authoritative}")  # False
```

**What you can prove**:
- Events are in sequence (no gaps, no reordering)
- Hashes chain correctly (no tampering after write)
- Signatures are valid (came from this key)

**What you cannot prove**:
- When events actually occurred (client clock)
- That events weren't deleted before recording
- Independent third-party verification

### Server Attestation (Optional)

If you need third-party timestamping, connect to Spine server:

```python
from spine_client import SpineClient, AuditEvent

async with SpineClient("http://spine:3000") as client:
    response = await client.log(AuditEvent(event_type="data.export"))
    # WAL fallback is automatic if server unreachable
```

**Additional guarantees with server**:
- Independent timestamp (server clock, not client)
- Counter-signature (server vouches for receipt)
- Third-party verifiable

## Core API

### SigningKey

```python
from spine_client import SigningKey

# Generate new key
key = SigningKey.generate(key_id="my-service-01")

# From existing seed (32 bytes)
key = SigningKey.from_seed(seed_bytes, key_id="restored")

# Export for backup
seed = key.to_seed()
public_hex = key.public_key().to_hex()
```

### WAL (Write-Ahead Log)

```python
from spine_client import WAL, WALConfig

config = WALConfig(
    data_dir="./audit_log",
    retention_hours=72,        # Auto-cleanup old segments
    max_segment_size=10_000,   # Records per segment file
)

wal = WAL(signing_key, config, namespace="service-name")
await wal.initialize()

# Append event
record = await wal.append({"event_type": "action", "data": "value"})

# Get unsynced records (no receipt yet)
unsynced = await wal.unsynced_records(limit=100)

# Attach receipt from server
await wal.attach_receipt(event_id, receipt)

# Statistics
stats = await wal.get_stats()
print(f"Total records: {stats['total_records']}")
print(f"Unsynced: {stats['unsynced_records']}")
```

### LocalRecord Structure

```python
@dataclass
class LocalRecord:
    event_id: str          # Unique ID (UUID)
    stream_id: str         # key_id + namespace hash
    seq: int               # Sequence number in stream
    ts_client: str         # Client timestamp (ISO 8601)
    prev_hash: str         # Entry hash of previous record (BLAKE3)
    payload_hash: str      # Hash of canonical payload
    hash_alg: str          # "blake3" or "sha256"
    payload: Dict          # Original event data
    sig_client: str        # Ed25519 signature over entry_hash (hex)
    key_id: str            # Short key identifier (kid_xxx)
    public_key: str        # Full public key (64 hex chars, for CLI verification)
    receipt: Optional[Receipt]  # Server receipt if synced
```

**Note**: The signature (`sig_client`) is computed over the **entry hash**, not just the payload.
The entry hash binds together: `seq`, `timestamp`, `prev_hash`, and `payload_hash`.

### Verification

```python
from spine_client import verify_wal, verify_record, verify_chain, verify_receipt

# Verify entire WAL
result = await verify_wal(wal)

# Verify single record
result = verify_record(record, client_public_key)

# Verify chain of records
result = verify_chain(records, client_public_key)

# Verify server receipt (makes it authoritative)
result = verify_receipt(record, server_public_key)
```

### VerifyResult

```python
@dataclass
class VerifyResult:
    valid: bool              # Overall validity
    status: VerifyStatus     # Detailed status
    message: str             # Human-readable
    is_authoritative: bool   # Has valid server receipt?
    details: Dict            # Additional info
```

Status values:
- `valid` - Chain intact, signatures valid
- `invalid_hash` - Hash chain broken
- `invalid_signature` - Signature verification failed
- `invalid_chain` - Sequence/ordering issue
- `no_receipt` - Valid locally, but no server attestation

## WAL File Format

```
audit_log/
├── segment_20250115_103000.jsonl   # Segment (timestamped JSONL)
├── segment_20250115_120000.jsonl   # Next segment
├── chain_state.json                # Chain state (seq, prev_hash)
└── receipts.jsonl                  # Server receipts
```

Each segment file contains newline-delimited JSON:

```json
{
  "event_id": "evt_abc-123",
  "stream_id": "stream_x1y2z3w4a5b6c7d8",
  "seq": 1,
  "ts_client": "2025-01-15T10:30:00.123456+00:00",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "payload_hash": "544e479825ce9894e19dab2b7aa19a0416f4a28a68190bf884cc3525cab9df51",
  "hash_alg": "blake3",
  "payload": {"event_type": "user.login", "user_id": "alice"},
  "sig_client": "8b11e1ce0f7f23ab858b971fed8d76a325e48b9f3708d477c024a7dc2f6ceea8...",
  "key_id": "kid_49f0b77a302a8ed4",
  "public_key": "862f70392e55bae96914b758a8959fa644df532bb82af9984ebe0a42c12237d8"
}
```

### Chain Linking

Each record's `prev_hash` contains the **entry hash** of the previous record (not just the payload hash).
The entry hash is computed as:

```
entry_hash = BLAKE3(seq_le_bytes || timestamp_ns_le_bytes || prev_hash_utf8 || payload_hash_utf8)
```

This ensures the signature binds not just the payload, but also the sequence position and timing.

## SpineClient (Optional Server Integration)

```python
from spine_client import SpineClient, AuditEvent

async with SpineClient(
    base_url="http://spine:3000",
    api_key="your-api-key",
    # WAL fallback is automatic (signed, CLI-verifiable)
) as client:

    # Log with full event structure
    response = await client.log(AuditEvent(
        event_type="data.export",
        severity=Severity.HIGH,
        actor=Actor(id="user_42", email="user@example.com"),
        resource=Resource(type="report", id="report_123"),
        payload={"format": "xlsx", "rows": 15000},
    ))
```

### Circuit Breaker

```python
from spine_client.circuit_breaker import CircuitState

async with SpineClient(
    base_url="http://spine:3000",
    circuit_failure_threshold=3,    # Open after 3 failures
    circuit_recovery_timeout=30.0,  # Try again after 30s
) as client:

    state = await client.get_circuit_state()
    # CLOSED    - Normal operation
    # OPEN      - Using signed WAL fallback
    # HALF_OPEN - Testing recovery
```

## Configuration Reference

### WALConfig

| Option | Default | Description |
|--------|---------|-------------|
| `data_dir` | "./spine_wal" | Directory for WAL files |
| `retention_hours` | 72 | Auto-delete segments older than this |
| `max_segment_size` | 10MB | Max size per segment file |
| `max_segments` | 100 | Max segment files to keep |

> **Note**: Hash algorithm is always BLAKE3 (required for CLI compatibility).

### SpineClient

| Option | Default | Description |
|--------|---------|-------------|
| `base_url` | required | Spine server URL |
| `api_key` | None | Bearer token authentication |
| `timeout_ms` | 5000 | Request timeout |
| `enable_circuit_breaker` | True | Enable circuit breaker |
| `enable_wal_fallback` | True | Enable signed WAL fallback when offline |
| `wal_dir` | "./spine_fallback_wal" | Directory for fallback WAL |
| `signing_key` | None | Ed25519 key (auto-generated if not provided) |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Spine SDK                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ SigningKey  │  │    WAL      │  │  SpineClient (optional) │  │
│  │  Ed25519    │  │ Hash Chain  │  │  for server receipts    │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │  Local WAL      │◄────── spine-cli verify
                  │  (JSONL files)  │        (no server needed)
                  └─────────────────┘
```

## Design Philosophy & Threat Model

**The SDK is intentionally powerful but non-authoritative.**

This means: the SDK gives you full cryptographic capabilities (signing, hashing, chain linking), but it cannot *prove* anything to a third party on its own. A client can always lie about timestamps, omit events, or regenerate the entire WAL. The cryptography guarantees *internal consistency*, not *external truth*.

**What the SDK protects against**:
- Post-hoc tampering (modifying events after they're written)
- Reordering attacks (changing event sequence)
- Silent deletion (removing events breaks the chain)
- Payload modification (signature verification fails)

**What the SDK does NOT protect against** (without server):
- Omission at write time (never logging an event)
- Clock manipulation (client controls timestamps)
- Full WAL replacement (regenerating from scratch)
- Key compromise (attacker with private key can forge)

**Why this design?** Compliance teams need to understand the trust boundary. Client-side signing is *evidence*, not *proof*. For audit-grade proof, you need an independent witness (Spine server) that timestamps and counter-signs.

**Standalone-first**: Use `spine-cli` to verify - it's cryptographic proof of consistency, not trust in the client.

## License

Apache-2.0

## Related

- [spine-cli](../spine-cli/) - Independent WAL verification tool
- Spine Server - Proprietary audit trail engine with receipts
