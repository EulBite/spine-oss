# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Spine Python SDK - Tamper-Evident Audit Logging

Two modes of operation:
1. Standalone (local WAL with crypto) - "Client Integrity Claim"
2. With Spine server - "Audit-grade Proof" via server receipts

Features:
- Canonical JSON + cryptographic hashing (BLAKE3/SHA-256)
- Ed25519 client-side signing
- Local hash chain for integrity
- Server receipts for authoritative proof
- Circuit breaker and retry for resilience

Usage (standalone):
    from spine_client import WAL, SigningKey

    key = SigningKey.generate()
    wal = WAL(key)
    await wal.initialize()

    record = await wal.append({"event_type": "auth.login", "user_id": "123"})
    # record has: payload_hash, sig_client, prev_hash chain

    # Verify local chain
    from spine_client import verify_wal
    result = await verify_wal(wal)
    print(result.message)  # "Client integrity claim: local chain valid"

Usage (with Spine server):
    from spine_client import SpineClient, AuditEvent

    async with SpineClient("http://spine:3000") as client:
        response = await client.log(AuditEvent(
            event_type="auth.login",
            payload={"user_id": "123"}
        ))
        # response includes server receipt = authoritative proof
"""

# Core types
from .circuit_breaker import CircuitBreaker, CircuitState

# Client (for Spine server integration)
from .client import SpineClient

# Crypto
from .crypto import (
    HashAlgorithm,
    SigningKey,
    VerifyingKey,
    canonical_json,
    compute_entry_hash,
    compute_hash,
    hash_payload,
    sign_payload,
    timestamp_to_nanos,
    verify_payload_signature,
)
from .events import AuditEvent

# Legacy (deprecated, use WAL instead)
# LocalWAL emits DeprecationWarning in __init__
from .local_wal import LocalWAL
from .sidecar import AuditSidecar
from .types import (
    WAL_FORMAT_VERSION,
    Actor,
    LocalRecord,
    Receipt,
    Resource,
    Severity,
    VerifyResult,
    VerifyStatus,
    generate_event_id,
    generate_stream_id,
)

# Verification
from .verify import (
    verify_chain,
    verify_receipt,
    verify_record,
    verify_record_hash,
    verify_record_signature,
    verify_wal,
)

# WAL (standalone mode)
from .wal import WAL, WALConfig

__version__ = "0.3.0"
__all__ = [
    # Types
    "LocalRecord",
    "Receipt",
    "VerifyResult",
    "VerifyStatus",
    "Severity",
    "Actor",
    "Resource",
    "generate_event_id",
    "generate_stream_id",
    "WAL_FORMAT_VERSION",
    # Crypto
    "SigningKey",
    "VerifyingKey",
    "canonical_json",
    "hash_payload",
    "compute_hash",
    "compute_entry_hash",
    "timestamp_to_nanos",
    "sign_payload",
    "verify_payload_signature",
    "HashAlgorithm",
    # WAL
    "WAL",
    "WALConfig",
    # Verification
    "verify_record",
    "verify_chain",
    "verify_wal",
    "verify_record_hash",
    "verify_record_signature",
    "verify_receipt",
    # Client
    "SpineClient",
    "AuditEvent",
    "CircuitBreaker",
    "CircuitState",
    "AuditSidecar",
    # Legacy
    "LocalWAL",
]
