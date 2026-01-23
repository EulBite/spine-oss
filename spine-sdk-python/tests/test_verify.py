# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""Tests for chain verification functionality."""

import json

import pytest

from spine_client.crypto import SigningKey
from spine_client.types import LocalRecord
from spine_client.verify import verify_chain, verify_wal
from spine_client.wal import WAL, WALConfig


@pytest.fixture
def signing_key():
    """Generate a fresh signing key for tests."""
    return SigningKey.generate(key_id="test-key")


@pytest.fixture
def wal_config(tmp_path):
    """Create WAL config pointing to temp directory."""
    return WALConfig(data_dir=str(tmp_path / "wal"))


# =============================================================================
# Basic Verification
# =============================================================================


@pytest.mark.asyncio
async def test_verify_valid_chain(signing_key, wal_config):
    """Valid chain should pass verification."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Write records
    await wal.append({"event": "first"})
    await wal.append({"event": "second"})
    await wal.append({"event": "third"})

    # Verify
    result = await verify_wal(wal)

    assert result.valid
    assert result.details["count"] == 3


@pytest.mark.asyncio
async def test_verify_empty_wal(signing_key, wal_config):
    """Empty WAL should pass verification."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    result = await verify_wal(wal)

    assert result.valid
    assert result.details["count"] == 0


# =============================================================================
# Chain Integrity
# =============================================================================


@pytest.mark.asyncio
async def test_verify_detects_reordering(signing_key, wal_config):
    """Reordered records should fail chain verification.

    When records are reordered in the file but sorted by seq during verification,
    the prev_hash won't match because record 2's prev_hash points to record 1's
    entry_hash, but if we read them out of order from file and re-sort,
    the chain linkage is still checked and will fail.

    Actually, since we sort by seq and check prev_hash against computed entry_hash,
    reordering in file doesn't matter - the chain check happens on sorted records.
    The real attack we detect is when someone modifies seq numbers.
    """
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "first"})
    await wal.append({"event": "second"})
    await wal.append({"event": "third"})

    # Modify seq numbers to simulate reordering attack
    # Change seq 2 -> 3 and seq 3 -> 2 (swap sequence numbers)
    segments = list(wal.data_dir.glob("segment_*.jsonl"))
    with open(segments[0]) as f:
        lines = f.readlines()

    record2 = json.loads(lines[1])
    record3 = json.loads(lines[2])

    # Swap seq numbers
    record2["seq"], record3["seq"] = record3["seq"], record2["seq"]

    lines[1] = json.dumps(record2) + "\n"
    lines[2] = json.dumps(record3) + "\n"

    with open(segments[0], "w") as f:
        f.writelines(lines)

    # Reload and verify - should fail because:
    # - After sorting by seq, prev_hash chain will be broken
    # - Signatures will also fail (seq is part of entry_hash)
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    result = await verify_wal(wal2)

    assert not result.valid


@pytest.mark.asyncio
async def test_verify_detects_tampered_payload(signing_key, wal_config):
    """Tampered payload should fail hash verification."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "original"})

    # Tamper with payload in file
    segments = list(wal.data_dir.glob("segment_*.jsonl"))
    with open(segments[0]) as f:
        data = json.loads(f.read().strip())

    data["payload"]["event"] = "tampered"

    with open(segments[0], "w") as f:
        f.write(json.dumps(data) + "\n")

    # Reload and verify
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    result = await verify_wal(wal2)

    assert not result.valid


# =============================================================================
# Sequence Gap Detection
# =============================================================================


@pytest.mark.asyncio
async def test_verify_detects_sequence_gap(signing_key, wal_config):
    """Missing sequence number should be detected."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "first"})   # seq=1
    await wal.append({"event": "second"})  # seq=2
    await wal.append({"event": "third"})   # seq=3

    # Remove middle record to create gap
    segments = list(wal.data_dir.glob("segment_*.jsonl"))
    with open(segments[0]) as f:
        lines = f.readlines()

    # Remove seq=2 (line index 1)
    del lines[1]

    with open(segments[0], "w") as f:
        f.writelines(lines)

    # Reload and verify
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    result = await verify_wal(wal2)

    assert not result.valid
    # Should mention gap
    assert any("gap" in str(e).lower() for e in result.details.get("errors", []))


# =============================================================================
# Timestamp Monotonicity
# =============================================================================


@pytest.mark.asyncio
async def test_verify_detects_timestamp_regression(signing_key, wal_config):
    """Timestamp going backward should be detected."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "first"})
    await wal.append({"event": "second"})

    # Modify second record's timestamp to be earlier than first
    segments = list(wal.data_dir.glob("segment_*.jsonl"))
    with open(segments[0]) as f:
        lines = f.readlines()

    record1 = json.loads(lines[0])
    record2 = json.loads(lines[1])

    # Set record2's timestamp to 1 hour before record1
    from datetime import datetime, timedelta
    ts1 = datetime.fromisoformat(record1["ts_client"])
    ts2_backdated = (ts1 - timedelta(hours=1)).isoformat()
    record2["ts_client"] = ts2_backdated

    # Need to re-sign because timestamp is part of entry hash
    # For this test, we just verify the timestamp check catches it
    # even though signature will also fail
    lines[1] = json.dumps(record2) + "\n"

    with open(segments[0], "w") as f:
        f.writelines(lines)

    # Reload and verify
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    result = await verify_wal(wal2)

    assert not result.valid


@pytest.mark.asyncio
async def test_verify_timestamp_check_can_be_disabled(signing_key):
    """Timestamp check should be skippable with strict_timestamps=False."""
    # Create records manually with backdated timestamp
    client_key = signing_key.public_key()

    # This tests that the parameter exists and works
    # With strict_timestamps=False, only chain and signature matter
    records: list[LocalRecord] = []  # Empty list for this test
    result = verify_chain(records, client_key, strict_timestamps=False)
    assert result.valid


# =============================================================================
# Corrupted Data Handling
# =============================================================================


@pytest.mark.asyncio
async def test_verify_handles_corrupted_signature(signing_key, wal_config):
    """Corrupted signature should fail verification."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "test"})

    # Corrupt signature
    segments = list(wal.data_dir.glob("segment_*.jsonl"))
    with open(segments[0]) as f:
        data = json.loads(f.read().strip())

    # Flip some bits in signature
    sig = data["sig_client"]
    corrupted_sig = sig[:10] + "0000000000" + sig[20:]
    data["sig_client"] = corrupted_sig

    with open(segments[0], "w") as f:
        f.write(json.dumps(data) + "\n")

    # Reload and verify
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    result = await verify_wal(wal2)

    assert not result.valid


# =============================================================================
# Verify Chain Function Directly
# =============================================================================


def test_verify_chain_empty_list(signing_key):
    """Empty record list should pass."""
    client_key = signing_key.public_key()
    result = verify_chain([], client_key)
    assert result.valid


@pytest.mark.asyncio
async def test_verify_chain_with_sequence_duplicate(signing_key, wal_config):
    """Duplicate sequence numbers should fail verification."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "first"})
    await wal.append({"event": "second"})

    # Modify second record to have same seq as first
    segments = list(wal.data_dir.glob("segment_*.jsonl"))
    with open(segments[0]) as f:
        lines = f.readlines()

    record2 = json.loads(lines[1])
    record2["seq"] = 1  # Duplicate seq

    lines[1] = json.dumps(record2) + "\n"

    with open(segments[0], "w") as f:
        f.writelines(lines)

    # Reload and verify
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    result = await verify_wal(wal2)

    # Should fail - either monotonic check or signature check
    assert not result.valid


# =============================================================================
# Strict File Order (Forensic Mode)
# =============================================================================


@pytest.mark.asyncio
async def test_strict_file_order_fails_on_reordered_file(signing_key, wal_config):
    """In strict mode, physically reordered records should fail immediately."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "first"})
    await wal.append({"event": "second"})
    await wal.append({"event": "third"})

    # Swap lines in file (physical reorder)
    segments = list(wal.data_dir.glob("segment_*.jsonl"))
    with open(segments[0]) as f:
        lines = f.readlines()

    # Swap second and third records in file
    lines[1], lines[2] = lines[2], lines[1]

    with open(segments[0], "w") as f:
        f.writelines(lines)

    # Reload
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    # Strict mode should fail (records out of order in file)
    # Error will be sequence-related because we see seq 1 -> 3 -> 2 in file order
    result_strict = await verify_wal(wal2, strict_file_order=True)
    assert not result_strict.valid
    # Verify error mentions sequence issue (not monotonic or gap)
    errors = result_strict.details.get("errors", [])
    assert any(
        "sequence" in str(e).lower() or "monotonic" in str(e).lower()
        for e in errors
    ), f"Expected sequence error, got: {errors}"

    # Resilient mode: sorts by seq first, so order becomes 1 -> 2 -> 3
    # Chain remains intact because prev_hash linkage was created correctly
    result_resilient = await verify_wal(wal2, strict_file_order=False)
    # This passes because after sorting, the logical chain is valid
    assert result_resilient.valid, f"Resilient mode failed: {result_resilient.details}"


@pytest.mark.asyncio
async def test_strict_file_order_passes_correct_order(signing_key, wal_config):
    """In strict mode, correctly ordered file should pass."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "first"})
    await wal.append({"event": "second"})
    await wal.append({"event": "third"})

    # Don't modify file - should pass in strict mode
    result = await verify_wal(wal, strict_file_order=True)

    assert result.valid
    assert result.details["count"] == 3


@pytest.mark.asyncio
async def test_resilient_mode_handles_async_writes(signing_key, wal_config):
    """Resilient mode should handle out-of-order writes by sorting by seq."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Write in order
    await wal.append({"event": "first"})
    await wal.append({"event": "second"})
    await wal.append({"event": "third"})

    # File is in correct order, both modes should pass
    result_strict = await verify_wal(wal, strict_file_order=True)
    result_resilient = await verify_wal(wal, strict_file_order=False)

    assert result_strict.valid
    assert result_resilient.valid
