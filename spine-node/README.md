# Spine Node SDK

**Spine is an open-source integrity layer for compliance platforms (Vanta, Drata), providing cryptographically verifiable audit trails and signed compliance attestations.**

> Spine exists to provide cryptographic integrity guarantees that most compliance platforms currently assume but do not verify.

Tamper-proof, hash-chained audit logs with Ed25519 signatures for Node.js.

## Features

- **Hash-chained WAL** - Each event links to previous via BLAKE3 hash
- **Ed25519 signatures** - Every event is cryptographically signed
- **Verification** - Detect tampering, gaps, or missing events
- **Attestations** - Generate signed proof documents for compliance

```
+----------+     +-----------+     +--------+     +-------------+     +-----------+
|   Your   | --> |   Spine   | --> | Verify | --> |   Signed    | --> | Compliance|
|   App    |     |    WAL    |     |        |     | Attestation |     |  (Vanta/  |
|          |     |           |     |        |     |             |     |   Drata)  |
+----------+     +-----------+     +--------+     +-------------+     +-----------+
   events         hash-chain       integrity        JSON proof         compliance
                  + signatures     check            document           evidence
```

## What Spine Is / Is Not

**Spine is:**
- An integrity layer for audit logs
- A cryptographic proof generator
- A verification tool for compliance evidence

**Spine is not:**
- A SIEM
- A log aggregation platform
- A replacement for your compliance platform

## Installation

```bash
npm install spine-sdk-node
```

## Quick Start

```typescript
import { SigningKey, WAL, verify, exportAttestation } from 'spine-sdk-node';

// Generate signing key
const signingKey = await SigningKey.generate('my-key');

// Create WAL
const wal = new WAL(signingKey, { dataDir: './audit-logs' });

// Append events
await wal.append({ event: 'user.login', user: 'alice' });
await wal.append({ event: 'document.sign', doc_id: 'doc-123' });

// Verify chain integrity
const result = await verify(wal);
console.log(result.status); // 'VERIFIED'

// Export attestation
const attestation = await exportAttestation(wal, signingKey);
console.log(JSON.stringify(attestation, null, 2));
```

The generated attestation can be uploaded to compliance platforms (e.g. Vanta) as evidence.

## API Reference

### SigningKey

```typescript
// Generate new key
const key = await SigningKey.generate('key-id');

// Load from hex seed
const key = await SigningKey.fromHex(hexSeed, 'key-id');

// Get public key
key.publicKeyHex();    // hex string
key.publicKeyBase64(); // base64 string
```

### WAL (Write-Ahead Log)

```typescript
const wal = new WAL(signingKey, {
  dataDir: './data',  // Storage directory
});

// Append event (returns LocalRecord)
const record = await wal.append({
  event_type: 'user.login',
  user_id: 'alice',
  // ... any JSON-serializable data (no floats)
});

// Read all records
for await (const record of wal.readRecords()) {
  console.log(record);
}

// Get stream ID
wal.getStreamId();
```

### verify()

```typescript
const result = await verify(wal, {
  startTime: '2026-01-01T00:00:00Z',  // optional
  endTime: '2026-01-31T23:59:59Z',    // optional
});

// result.status: 'VERIFIED' | 'TAMPERED' | 'INCOMPLETE' | 'EMPTY'
// result.count: number of events
// result.first_seq, result.last_seq: sequence range
// result.root_hash: final chain hash
// result.missing_ranges: [{from, to}] if INCOMPLETE
```

### exportAttestation()

```typescript
const attestation = await exportAttestation(wal, signingKey, {
  period: {
    start: '2026-01-01T00:00:00Z',
    end: '2026-01-31T23:59:59Z',
  },
  sign: true,  // default: true
});
```

## Attestation Format

```json
{
  "version": "1.0",
  "type": "spine.attestation.v1",
  "attestation_id": "39921f1ee8ff9f5a",
  "period": {
    "start": "2026-01-01T00:00:00Z",
    "end": "2026-01-31T23:59:59Z"
  },
  "ledger": {
    "stream_id": "stream_my-key",
    "first_seq": 1,
    "last_seq": 1523
  },
  "count": 1523,
  "root_hash": {
    "algo": "blake3",
    "value": "c30c91aeb54e7b2d..."
  },
  "verification": {
    "status": "VERIFIED",
    "tool": "spine-node/0.1.0"
  },
  "signature": {
    "algo": "ed25519",
    "format": "base64",
    "value": "tMUL46WTHObrEQ...",
    "signed_fields": ["version", "type", "attestation_id", ...]
  }
}
```

## Performance

Benchmarked on AMD Ryzen 7 7800X3D, Node.js v24, Windows 11:

| Operation | Throughput | Latency | Notes |
|-----------|-----------|---------|-------|
| **Append** | 1,330 events/sec | 0.75 ms | Write + sign + hash |
| **Verify** | 742 events/sec | 1.35 ms | Read + verify sig + check hash |
| **Attestation** | ~1 sec / 1K events | - | Full verify + sign |

> **Note:** Benchmarks include BLAKE3 hashing + Ed25519 signing per event (not raw I/O). Do not compare with raw message brokers like Kafka.

### Capacity Estimates

| Events/day | Append time | Storage |
|------------|-------------|---------|
| 100K | ~75 sec | ~50 MB |
| 1M | ~12 min | ~500 MB |
| 10M | ~2 hours | ~5 GB |

Run benchmark yourself:
```bash
npm run build
node dist/benchmark/throughput.js
```

## Cryptographic Details

- **Hashing**: BLAKE3 (faster than SHA-256, cryptographically secure)
- **Signatures**: Ed25519 (compact 64-byte signatures)
- **Entry hash**: `BLAKE3(seq_le_u64 || ts_ns_le_i64 || prev_hash || payload_hash)`
- **Genesis hash**: 64 zeros (`0000...0000`)
- **Canonical JSON**: Sorted keys, no whitespace, NFC normalized, no floats

## Payload Constraints

Payloads must be JSON-serializable with these restrictions:
- No floating-point numbers (use integers or strings)
- No undefined values
- No circular references

```typescript
// Good
await wal.append({ count: 42, price: "19.99", active: true });

// Bad - will throw
await wal.append({ ratio: 0.5 });  // Float not allowed
```

## Production Deployments

For long-running audit pipelines requiring:
- Crash recovery
- Key rotation
- Dead letter queues
- Retention policies

Use the [Python SDK](../spine-sdk-python/).

The Node SDK is designed as a **thin integration layer** for SaaS and compliance platform connectors.

## Roadmap

- [x] Node.js SDK
- [x] Python SDK ([spine-sdk-python](../spine-sdk-python/))
- [x] CLI verifier ([spine-cli](../spine-cli/) - Rust)
- [x] Vanta connector (open-source)
- [ ] Drata connector (planned)
- [ ] Go SDK
- [ ] Enterprise engine (closed-source)

## License

Apache-2.0

---

Part of the [Spine](https://github.com/EulBite/spine-oss) open-core project.
