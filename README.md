# Spine Open Source

**Open-source SDK and CLI for verifiable audit logging in compliance-critical systems.**

Build tamper-evident audit trails with Ed25519 signatures and BLAKE3 hash chains.
**No server required** - the SDK creates signed logs locally, and `spine-cli` verifies them independently.

These tools allow you to:

- **Create** cryptographically signed audit logs (works standalone, no server needed)
- **Verify** audit trail integrity with `spine-cli` (independent verification)
- **Optionally** connect to Spine server for third-party timestamping

## Components

| Component | Language | Purpose |
|-----------|----------|---------|
| [spine-sdk-python](./spine-sdk-python/) | Python | Create signed audit logs (WAL files) |
| [spine-cli](./spine-cli/) | Rust | Verify WAL integrity independently |

## Quick Start

### 1. Create Signed Audit Logs (Python SDK)

```python
import asyncio
from spine_client import WAL, WALConfig, SigningKey

async def main():
    key = SigningKey.generate()
    wal = WAL(key, WALConfig(data_dir="./audit_log"))
    await wal.initialize()

    await wal.append({"event_type": "user.login", "user_id": "alice"})
    await wal.append({"event_type": "data.access", "resource": "report_123"})

    print(f"Logged {wal._seq} events to ./audit_log/")

asyncio.run(main())
```

### 2. Verify with CLI (No Server Needed)

**Prerequisite**: [Rust toolchain](https://rustup.rs/) (1.75.0+)

```bash
cd spine-cli
cargo build --release
./target/release/spine-cli verify --wal ../audit_log
```

Output:
```
SPINE WAL VERIFICATION REPORT
=============================
Status:              VALID
Events verified:     2
Signatures verified: 2
```

The CLI verifies:
- Hash chain integrity (BLAKE3)
- Digital signatures (Ed25519)
- Sequence continuity
- Timestamp monotonicity

## Architecture

```
+-------------------------------------------------------------+
|                     Your Application                         |
+-------------------------------------------------------------+
                            |
                            v
+-------------------------------------------------------------+
|  spine-sdk-python                                            |
|  (Ed25519 signing + BLAKE3 hash chain)                       |
+-------------------------------------------------------------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
+---------------------+       +-------------------------------+
|  Local WAL Files    |       |  Spine Server (optional,      |
|  (JSONL, signed)    |       |  on-premise deployment)       |
+---------------------+       +-------------------------------+
              |
              v
+---------------------+
|  spine-cli verify   |  <-- Independent verification
+---------------------+      (no server, no trust required)
```

**Standalone mode**: SDK creates signed WAL files, CLI verifies them. No server needed.

**With Spine server (on-premise)**: Deploy Spine in your infrastructure for independent timestamps and third-party attestation. Your data never leaves your network.

## Why Open Source?

Audit systems require trust. By open-sourcing verification tools and client SDKs:

1. **Verifiable claims**: Anyone can verify our integrity guarantees
2. **No vendor lock-in**: Your audit data is readable without our server
3. **Security audits**: The verification logic can be independently reviewed
4. **Client flexibility**: Integrate with any language, modify as needed

The core Spine engine remains proprietary, but the contract (WAL format, hash algorithms, signature schemes) is fully documented and verifiable.

## WAL Format

Spine uses append-only JSON Lines files with hash chaining:

```json
{"sequence":1,"timestamp_ns":1735000000000000000,"prev_hash":"0000...","payload_hash":"abc1..."}
{"sequence":2,"timestamp_ns":1735000000000000001,"prev_hash":"abc1...","payload_hash":"def2..."}
```

Each entry links to the previous via `prev_hash`, forming a verifiable chain.
See [spine-cli/README.md](./spine-cli/README.md#wal-format) for full specification.

## Requirements

### spine-cli
- Rust 1.75.0+
- No runtime dependencies

### spine-sdk-python
- Python 3.10+
- blake3 (required for CLI compatibility)
- aiohttp, aiofiles, cryptography

## Documentation

- [CLI Documentation](./spine-cli/README.md) - Verification commands, output formats, error types
- [Python SDK Documentation](./spine-sdk-python/README.md) - Client API, circuit breaker, sidecar mode

## License

Apache License 2.0

You may use, modify, and distribute these components freely.
See [LICENSE](./LICENSE) for details.

## Contributing

Issues and pull requests are welcome.

Before contributing:
1. Check existing issues for duplicates
2. For large changes, open an issue first to discuss
3. Follow the existing code style
4. Add tests for new functionality

## Security

If you discover a security vulnerability, please email security@eulbite.com instead of opening a public issue.

## Links

- [Eul Bite](https://eulbite.com) - Company website
- [Spine Product Page](https://eulbite.com/spine) - Product information
