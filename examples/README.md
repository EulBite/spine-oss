# Spine Examples

Ready-to-run examples for integrating Spine into your applications.

## Quick Start

```bash
# 1. Install the SDK (from repo root)
cd spine-sdk-python
pip install -e ".[dev]"

# 2. Run an example
cd ../examples/python
python basic_wal_async.py

# 3. Verify the audit log
cd ../../spine-cli
cargo run --release -- verify --wal ../examples/python/audit_log
```

## Python Examples

| Example | Description |
|---------|-------------|
| [basic_wal_async.py](python/basic_wal_async.py) | Minimal WAL usage with key management |
| [sidecar_nonblocking.py](python/sidecar_nonblocking.py) | High-throughput, non-blocking logging |
| [fastapi_middleware.py](python/fastapi_middleware.py) | Request/response audit middleware |
| [logging_handler.py](python/logging_handler.py) | Bridge Python `logging` to Spine |
| [wal_verify_report.py](python/wal_verify_report.py) | Generate logs + verification report |

## Key Management

Examples support keys from multiple sources (in priority order):

1. **Environment variable**: `SPINE_KEY` (hex, base64, or PEM)
2. **File**: `./signing.key` in the example directory
3. **Auto-generate**: Creates `./signing.key` on first run

For production, always use a persistent key. See [docs/KEY_MANAGEMENT.md](../docs/KEY_MANAGEMENT.md).

## Requirements

- Python 3.10+
- `spine-client` package (installed from `spine-sdk-python/`)
- `blake3` package (for BLAKE3 hashing)
- `cryptography` package (for Ed25519 signing)

Optional:
- `fastapi` + `uvicorn` (for FastAPI example)
- Rust toolchain (for `spine-cli` verification)
