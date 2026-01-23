# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Verification module for Spine SDK.

Two levels of verification:
1. verify_local() - Checks chain integrity and client signatures
   Result: "Client Integrity Claim" (useful, but not authoritative)

2. verify_record() with receipt - Checks server receipt signature
   Result: "Audit-grade Proof" (server-attested, verifiable)

Usage:
    from spine_client.verify import verify_local, verify_record

    # Local verification (chain + signature)
    result = await verify_local(wal)
    if result.valid:
        print("Local chain is valid")
    if result.is_authoritative:
        print("Has server receipts - audit-grade")

    # Single record verification
    result = verify_record(record, client_public_key, server_public_key)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Union

from .crypto import (
    HashAlgorithm,
    VerifyingKey,
    canonical_json,
    compute_entry_hash,
    compute_hash,
    timestamp_to_nanos,
)
from .types import (
    LocalRecord,
    VerifyResult,
    VerifyStatus,
)

if TYPE_CHECKING:
    from .wal import WAL

logger = logging.getLogger(__name__)

# Genesis hash for first record in a stream
GENESIS_HASH = "0" * 64

# Type for key provider: single key, list of keys, or dict mapping key_id to key
# Supports key rotation scenarios where different records may be signed by different keys
KeyProvider = Union[VerifyingKey, list[VerifyingKey], dict[str, VerifyingKey]]


def _resolve_client_key(
    provider: KeyProvider,
    key_id: str,
) -> VerifyingKey | None:
    """
    Resolve a client key from a provider by key_id.

    Args:
        provider: Single key, list of keys, or dict of key_id -> key
        key_id: The key_id to look up

    Returns:
        VerifyingKey if found, None otherwise
    """
    if isinstance(provider, dict):
        return provider.get(key_id)
    elif isinstance(provider, list):
        for key in provider:
            if key.key_id == key_id:
                return key
        return None
    else:
        # Single key - return it if key_id matches, None otherwise
        return provider if provider.key_id == key_id else None


def verify_record_hash(record: LocalRecord) -> VerifyResult:
    """
    Verify that a record's payload_hash matches its payload.

    Args:
        record: LocalRecord to verify

    Returns:
        VerifyResult
    """
    # Recompute hash
    canonical = canonical_json(record.payload)
    supported_algs = (HashAlgorithm.BLAKE3, HashAlgorithm.SHA256)
    alg = record.hash_alg if record.hash_alg in supported_algs else HashAlgorithm.SHA256
    computed_hash, _ = compute_hash(canonical, alg)

    if computed_hash != record.payload_hash:
        computed_preview = computed_hash[:16]
        stored_preview = record.payload_hash[:16]
        return VerifyResult.failure(
            VerifyStatus.INVALID_HASH,
            f"Hash mismatch: computed {computed_preview}... != stored {stored_preview}...",
            details={
                "event_id": record.event_id,
                "computed": computed_hash,
                "stored": record.payload_hash,
            }
        )

    return VerifyResult.success(details={"event_id": record.event_id, "hash": computed_hash})


def verify_record_signature(
    record: LocalRecord,
    client_key: KeyProvider,
) -> VerifyResult:
    """
    Verify a record's client signature.

    The signature is over the entry_hash (not just the payload), which binds
    seq, timestamp, chain position, and payload together.

    Args:
        record: LocalRecord to verify
        client_key: Client's public key(s) for verification.
                   Can be a single key, list of keys, or dict mapping key_id to key.
                   Supports key rotation - each record is verified with the key
                   matching its key_id.

    Returns:
        VerifyResult
    """
    # Resolve the key for this record's key_id
    resolved_key = _resolve_client_key(client_key, record.key_id)
    if resolved_key is None:
        if isinstance(client_key, dict):
            available = list(client_key.keys())
        elif isinstance(client_key, list):
            available = [k.key_id for k in client_key]
        else:
            available = [client_key.key_id]
        return VerifyResult.failure(
            VerifyStatus.INVALID_SIGNATURE,
            f"No key found for key_id '{record.key_id}'. Available: {available}",
            details={"event_id": record.event_id, "key_id": record.key_id}
        )

    # Compute entry hash (signature is over this, not just payload)
    # Entry hash always uses BLAKE3 for CLI compatibility
    ts_ns = timestamp_to_nanos(record.ts_client)
    entry_hash, _ = compute_entry_hash(
        seq=record.seq,
        timestamp_ns=ts_ns,
        prev_hash=record.prev_hash,
        payload_hash=record.payload_hash,
        algorithm=HashAlgorithm.BLAKE3,  # Always BLAKE3 for chain linking
    )

    if not resolved_key.verify_hex(record.sig_client, entry_hash.encode('utf-8')):
        return VerifyResult.failure(
            VerifyStatus.INVALID_SIGNATURE,
            "Client signature verification failed",
            details={"event_id": record.event_id, "key_id": record.key_id}
        )

    return VerifyResult.success(details={"event_id": record.event_id, "signed_by": record.key_id})


def verify_receipt(
    record: LocalRecord,
    server_key: VerifyingKey,
) -> VerifyResult:
    """
    Verify a record's server receipt.

    This is what makes a record "authoritative" vs just a "client claim".

    Args:
        record: LocalRecord with receipt
        server_key: Server's public key for receipt verification

    Returns:
        VerifyResult with is_authoritative=True if valid
    """
    if not record.receipt:
        return VerifyResult.failure(
            VerifyStatus.MISSING_RECEIPT,
            "No server receipt - this is a client integrity claim only, not authoritative",
            details={"event_id": record.event_id}
        )

    receipt = record.receipt

    if receipt.server_key_id != server_key.key_id:
        return VerifyResult.failure(
            VerifyStatus.INVALID_RECEIPT,
            f"Server key ID mismatch: receipt has {receipt.server_key_id}, "
            f"verifying with {server_key.key_id}",
            details={"event_id": record.event_id}
        )

    # Check event_id match (defense in depth - also checked via signature)
    if receipt.event_id != record.event_id:
        return VerifyResult.failure(
            VerifyStatus.INVALID_RECEIPT,
            "Receipt event_id doesn't match record - possible receipt substitution attack",
            details={
                "record_event_id": record.event_id,
                "receipt_event_id": receipt.event_id,
            }
        )

    if receipt.payload_hash != record.payload_hash:
        return VerifyResult.failure(
            VerifyStatus.INVALID_RECEIPT,
            "Receipt payload_hash doesn't match record",
            details={
                "event_id": record.event_id,
                "receipt_hash": receipt.payload_hash,
                "record_hash": record.payload_hash,
            }
        )

    receipt_data = receipt.receipt_data_for_signing().encode('utf-8')
    if not server_key.verify_hex(receipt.receipt_sig, receipt_data):
        return VerifyResult.failure(
            VerifyStatus.INVALID_RECEIPT,
            "Server receipt signature verification failed",
            details={"event_id": record.event_id, "server_key_id": receipt.server_key_id}
        )

    return VerifyResult.success(
        is_authoritative=True,
        details={
            "event_id": record.event_id,
            "server_seq": receipt.server_seq,
            "server_time": receipt.server_time,
            "batch_id": receipt.batch_id,
        }
    )


def verify_record(
    record: LocalRecord,
    client_key: KeyProvider,
    server_key: VerifyingKey | None = None,
) -> VerifyResult:
    """
    Full verification of a single record.

    Checks:
    1. Payload hash matches
    2. Client signature is valid
    3. Server receipt (if present and server_key provided)

    Args:
        record: LocalRecord to verify
        client_key: Client's public key(s) - single key, list, or dict.
                   Supports key rotation scenarios.
        server_key: Server's public key (optional, for receipt verification)

    Returns:
        VerifyResult - is_authoritative=True only if receipt is valid
    """
    # 1. Verify hash
    result = verify_record_hash(record)
    if not result.valid:
        return result

    # 2. Verify client signature
    result = verify_record_signature(record, client_key)
    if not result.valid:
        return result

    # 3. Verify receipt if server key provided
    if server_key and record.receipt:
        result = verify_receipt(record, server_key)
        return result
    elif record.receipt and not server_key:
        # Has receipt but no key to verify
        return VerifyResult.success(
            is_authoritative=False,
            details={
                "event_id": record.event_id,
                "note": "Receipt present but no server key provided for verification"
            }
        )
    else:
        # No receipt
        return VerifyResult.success(
            is_authoritative=False,
            details={"event_id": record.event_id}
        )


def verify_chain(
    records: list[LocalRecord],
    client_key: KeyProvider,
    server_key: VerifyingKey | None = None,
    strict_timestamps: bool = True,
    strict_file_order: bool = False,
) -> VerifyResult:
    """
    Verify a chain of records.

    Checks:
    1. Each record individually (hash, signature, receipt)
    2. Chain integrity (prev_hash links via entry_hash)
    3. Sequence monotonicity (no duplicates, no decreasing)
    4. Sequence continuity (no gaps - seq 1,2,3 not 1,3)
    5. Timestamp monotonicity (optional, enabled by default)
    6. File order integrity (optional, for forensic use)

    Args:
        records: List of LocalRecord in sequence order
        client_key: Client's public key(s) for signature verification.
                   Supports key rotation:
                   - Single VerifyingKey: all records must use this key
                   - List[VerifyingKey]: looks up key by key_id
                   - Dict[str, VerifyingKey]: maps key_id to key
        server_key: Server's public key (optional)
        strict_timestamps: If True, require timestamps to be monotonically increasing
        strict_file_order: If True, records must be in correct order as read from file
                          (no sorting by seq - fails immediately if out of order).
                          Use this for forensic verification where physical file order
                          is evidence. Default False for resilience to async writes.

    Returns:
        VerifyResult with aggregate status
    """
    if not records:
        return VerifyResult.success(details={"count": 0})

    # In strict mode, don't sort - verify in file order
    # In resilient mode, sort by seq to handle async/out-of-order writes
    if strict_file_order:
        ordered_records = records  # Preserve file order
    else:
        ordered_records = sorted(records, key=lambda r: r.seq)

    prev_entry_hash = GENESIS_HASH
    prev_seq = 0
    prev_timestamp: str | None = None
    all_authoritative = True
    errors = []

    for record in ordered_records:
        # Verify individual record
        result = verify_record(record, client_key, server_key)
        if not result.valid:
            errors.append({
                "event_id": record.event_id,
                "seq": record.seq,
                "error": result.message,
            })
            continue

        if not result.is_authoritative:
            all_authoritative = False

        # Verify chain link (prev_hash = previous entry's entry_hash)
        if record.seq == 1:
            # First record should have genesis prev_hash
            if record.prev_hash != GENESIS_HASH:
                errors.append({
                    "event_id": record.event_id,
                    "seq": record.seq,
                    "error": "First record has invalid prev_hash (expected genesis)",
                })
        elif record.prev_hash != prev_entry_hash:
            errors.append({
                "event_id": record.event_id,
                "seq": record.seq,
                "error": "Chain break: prev_hash doesn't match previous entry hash",
                "expected": prev_entry_hash[:16] + "...",
                "got": record.prev_hash[:16] + "...",
            })

        # Verify sequence monotonicity (no duplicates or going backward)
        if record.seq <= prev_seq and prev_seq > 0:
            error_msg = f"Sequence not monotonic: {record.seq} <= {prev_seq}"
            if strict_file_order:
                error_msg += " (strict file order: records out of order in file)"
            errors.append({
                "event_id": record.event_id,
                "seq": record.seq,
                "error": error_msg,
            })

        # Verify sequence continuity (no gaps)
        if prev_seq > 0 and record.seq != prev_seq + 1:
            errors.append({
                "event_id": record.event_id,
                "seq": record.seq,
                "error": f"Sequence gap: expected {prev_seq + 1}, got {record.seq}",
                "missing_range": f"{prev_seq + 1} to {record.seq - 1}",
            })

        # Verify timestamp monotonicity
        if strict_timestamps and prev_timestamp is not None:
            if record.ts_client < prev_timestamp:
                errors.append({
                    "event_id": record.event_id,
                    "seq": record.seq,
                    "error": "Timestamp not monotonic: current < previous",
                    "current_ts": record.ts_client,
                    "previous_ts": prev_timestamp,
                })

        # Compute this record's entry_hash for next iteration's chain check
        # Entry hash always uses BLAKE3 for CLI compatibility
        ts_ns = timestamp_to_nanos(record.ts_client)
        prev_entry_hash, _ = compute_entry_hash(
            seq=record.seq,
            timestamp_ns=ts_ns,
            prev_hash=record.prev_hash,
            payload_hash=record.payload_hash,
            algorithm=HashAlgorithm.BLAKE3,  # Always BLAKE3 for chain linking
        )
        prev_seq = record.seq
        prev_timestamp = record.ts_client

    if errors:
        return VerifyResult.failure(
            VerifyStatus.INVALID_CHAIN,
            f"Chain verification failed: {len(errors)} error(s)",
            details={"errors": errors, "total_records": len(records)}
        )

    return VerifyResult.success(
        is_authoritative=all_authoritative,
        details={
            "count": len(records),
            "first_seq": ordered_records[0].seq,
            "last_seq": ordered_records[-1].seq,
            "all_have_receipts": all_authoritative,
        }
    )


async def verify_wal(
    wal: WAL,
    server_key: VerifyingKey | None = None,
    strict_timestamps: bool = True,
    strict_file_order: bool = False,
    additional_client_keys: list[VerifyingKey] | None = None,
) -> VerifyResult:
    """
    Verify all records in a WAL.

    Args:
        wal: WAL instance to verify
        server_key: Server's public key (optional, for receipt verification)
        strict_timestamps: If True, require timestamps to be monotonically increasing
        strict_file_order: If True, verify records in file order (forensic mode).
                          If False, sort by seq first (resilient mode, default).
        additional_client_keys: Additional client keys for key rotation scenarios.
                               The WAL's current signing key is always included.
                               Pass previous keys here when verifying logs that
                               span a key rotation.

    Returns:
        VerifyResult for entire WAL
    """
    # Build key provider with current key + any additional rotated keys
    current_key = wal.signing_key.public_key()
    if additional_client_keys:
        client_keys: KeyProvider = {current_key.key_id: current_key}
        for key in additional_client_keys:
            client_keys[key.key_id] = key
    else:
        client_keys = current_key

    records = []
    async for record in wal.iter_records():
        records.append(record)

    return verify_chain(
        records,
        client_keys,
        server_key,
        strict_timestamps=strict_timestamps,
        strict_file_order=strict_file_order,
    )
