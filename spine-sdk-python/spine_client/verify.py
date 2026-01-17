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

import logging
from typing import Optional, List, Dict, Any

from .types import (
    LocalRecord,
    Receipt,
    VerifyResult,
    VerifyStatus,
)
from .crypto import (
    canonical_json,
    compute_hash,
    compute_entry_hash,
    timestamp_to_nanos,
    verify_payload_signature,
    VerifyingKey,
    HashAlgorithm,
)

logger = logging.getLogger(__name__)

# Genesis hash for first record in a stream
GENESIS_HASH = "0" * 64


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
    alg = record.hash_alg if record.hash_alg in (HashAlgorithm.BLAKE3, HashAlgorithm.SHA256) else HashAlgorithm.SHA256
    computed_hash, _ = compute_hash(canonical, alg)

    if computed_hash != record.payload_hash:
        return VerifyResult.failure(
            VerifyStatus.INVALID_HASH,
            f"Hash mismatch: computed {computed_hash[:16]}... != stored {record.payload_hash[:16]}...",
            details={
                "event_id": record.event_id,
                "computed": computed_hash,
                "stored": record.payload_hash,
            }
        )

    return VerifyResult.success(details={"event_id": record.event_id, "hash": computed_hash})


def verify_record_signature(
    record: LocalRecord,
    client_key: VerifyingKey,
) -> VerifyResult:
    """
    Verify a record's client signature.

    The signature is over the entry_hash (not just the payload), which binds
    seq, timestamp, chain position, and payload together.

    Args:
        record: LocalRecord to verify
        client_key: Client's public key for verification

    Returns:
        VerifyResult
    """
    if record.key_id != client_key.key_id:
        return VerifyResult.failure(
            VerifyStatus.INVALID_SIGNATURE,
            f"Key ID mismatch: record has {record.key_id}, verifying with {client_key.key_id}",
            details={"event_id": record.event_id}
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

    if not client_key.verify_hex(record.sig_client, entry_hash.encode('utf-8')):
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
            f"Server key ID mismatch: receipt has {receipt.server_key_id}, verifying with {server_key.key_id}",
            details={"event_id": record.event_id}
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
    client_key: VerifyingKey,
    server_key: Optional[VerifyingKey] = None,
) -> VerifyResult:
    """
    Full verification of a single record.

    Checks:
    1. Payload hash matches
    2. Client signature is valid
    3. Server receipt (if present and server_key provided)

    Args:
        record: LocalRecord to verify
        client_key: Client's public key
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
    records: List[LocalRecord],
    client_key: VerifyingKey,
    server_key: Optional[VerifyingKey] = None,
) -> VerifyResult:
    """
    Verify a chain of records.

    Checks:
    1. Each record individually (hash, signature, receipt)
    2. Chain integrity (prev_hash links via entry_hash)
    3. Sequence monotonicity

    Args:
        records: List of LocalRecord in sequence order
        client_key: Client's public key
        server_key: Server's public key (optional)

    Returns:
        VerifyResult with aggregate status
    """
    if not records:
        return VerifyResult.success(details={"count": 0})

    # Sort by sequence
    sorted_records = sorted(records, key=lambda r: r.seq)

    prev_entry_hash = GENESIS_HASH
    prev_seq = 0
    all_authoritative = True
    errors = []

    for record in sorted_records:
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
                    "error": f"First record has invalid prev_hash (expected genesis)",
                })
        elif record.prev_hash != prev_entry_hash:
            errors.append({
                "event_id": record.event_id,
                "seq": record.seq,
                "error": f"Chain break: prev_hash doesn't match previous entry hash",
                "expected": prev_entry_hash[:16] + "...",
                "got": record.prev_hash[:16] + "...",
            })

        # Verify sequence monotonicity
        if record.seq <= prev_seq and prev_seq > 0:
            errors.append({
                "event_id": record.event_id,
                "seq": record.seq,
                "error": f"Sequence not monotonic: {record.seq} <= {prev_seq}",
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
            "first_seq": sorted_records[0].seq,
            "last_seq": sorted_records[-1].seq,
            "all_have_receipts": all_authoritative,
        }
    )


async def verify_wal(
    wal: "WAL",  # type: ignore
    server_key: Optional[VerifyingKey] = None,
) -> VerifyResult:
    """
    Verify all records in a WAL.

    Args:
        wal: WAL instance to verify
        server_key: Server's public key (optional, for receipt verification)

    Returns:
        VerifyResult for entire WAL
    """
    from .wal import WAL

    client_key = wal.signing_key.public_key()
    records = []
    async for record in wal.iter_records():
        records.append(record)

    return verify_chain(records, client_key, server_key)
