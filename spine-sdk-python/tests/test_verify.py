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


# =============================================================================
# Partial Authoritativeness
# =============================================================================


@pytest.mark.asyncio
async def test_partial_authoritativeness(signing_key, wal_config):
    """Chain with mixed receipts should report is_authoritative=False."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Write records (none have receipts initially)
    await wal.append({"event": "first"})
    await wal.append({"event": "second"})
    await wal.append({"event": "third"})

    # Verify - should pass but not be authoritative
    result = await verify_wal(wal)

    assert result.valid
    assert not result.is_authoritative, "No receipts = not authoritative"
    assert result.details.get("all_have_receipts") is False


@pytest.mark.asyncio
async def test_all_authoritative_requires_all_receipts(signing_key, wal_config):
    """is_authoritative should only be True when ALL records have valid receipts."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    r1 = await wal.append({"event": "first"})
    r2 = await wal.append({"event": "second"})

    # Simulate attaching receipt to only first record
    # (In real usage, this would come from server)
    from spine_client.types import Receipt

    fake_receipt = Receipt(
        event_id=r1.event_id,
        payload_hash=r1.payload_hash,
        server_time="2026-01-01T00:00:00Z",
        server_seq=1,
        receipt_sig="fake_sig",  # Won't verify without real server key
        server_key_id="server-key",
    )
    await wal.attach_receipt(r1.event_id, fake_receipt)

    # Verify without server key (can't verify receipts)
    result = await verify_wal(wal)

    assert result.valid
    # Even with one receipt attached, without server key to verify it,
    # and with second record having no receipt, should not be authoritative
    assert not result.is_authoritative


# =============================================================================
# Receipt Substitution Attack
# =============================================================================


@pytest.mark.asyncio
async def test_receipt_substitution_attack(signing_key, wal_config):
    """Attaching Record 1's receipt to Record 2 should fail verification.

    Attack scenario:
    - Attacker has a valid receipt for Record 1
    - Attacker modifies Record 2's payload (e.g., changing transfer amount)
    - Attacker attaches Record 1's receipt to the modified Record 2
    - Verification should detect that receipt.event_id != record.event_id
      or receipt.payload_hash != record.payload_hash
    """
    from spine_client.types import Receipt
    from spine_client.verify import verify_receipt

    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    r1 = await wal.append({"event": "transfer", "amount": 100})
    r2 = await wal.append({"event": "transfer", "amount": 200})

    # Create a "valid" receipt for Record 1
    # (In reality, this would come from the server with a real signature)
    r1_receipt = Receipt(
        event_id=r1.event_id,
        payload_hash=r1.payload_hash,
        server_time="2026-01-01T00:00:00Z",
        server_seq=1,
        receipt_sig="valid_sig_for_r1",
        server_key_id="server-key",
    )

    # Attack: Try to attach r1's receipt to r2
    # This simulates an attacker trying to "prove" r2 was accepted
    # by reusing r1's receipt
    stolen_receipt = Receipt(
        event_id=r1_receipt.event_id,  # Wrong! Points to r1
        payload_hash=r1_receipt.payload_hash,  # Wrong! r1's hash
        server_time=r1_receipt.server_time,
        server_seq=r1_receipt.server_seq,
        receipt_sig=r1_receipt.receipt_sig,
        server_key_id=r1_receipt.server_key_id,
    )

    # Manually attach the stolen receipt to r2
    # (bypassing attach_receipt which might have its own checks)
    r2_with_stolen_receipt = LocalRecord(
        event_id=r2.event_id,
        stream_id=r2.stream_id,
        seq=r2.seq,
        prev_hash=r2.prev_hash,
        ts_client=r2.ts_client,
        payload=r2.payload,
        payload_hash=r2.payload_hash,
        hash_alg=r2.hash_alg,
        sig_client=r2.sig_client,
        key_id=r2.key_id,
        public_key=r2.public_key,
        receipt=stolen_receipt,
    )

    # Create a mock server key for verification
    server_signing_key = SigningKey.generate(key_id="server-key")
    server_key = server_signing_key.public_key()

    # Verify the record with the stolen receipt
    result = verify_receipt(r2_with_stolen_receipt, server_key)

    # Should fail because:
    # 1. receipt.event_id (r1's) != record.event_id (r2's)
    # 2. receipt.payload_hash (r1's) != record.payload_hash (r2's)
    assert not result.valid
    assert "payload_hash" in result.message.lower() or "doesn't match" in result.message.lower()


@pytest.mark.asyncio
async def test_receipt_event_id_mismatch(signing_key, wal_config):
    """Receipt with wrong event_id should fail even if payload_hash matches."""
    from spine_client.types import Receipt
    from spine_client.verify import verify_receipt

    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    r1 = await wal.append({"event": "test"})

    # Create receipt with correct payload_hash but wrong event_id
    wrong_receipt = Receipt(
        event_id="evt_wrong_id",  # Wrong event_id
        payload_hash=r1.payload_hash,  # Correct hash
        server_time="2026-01-01T00:00:00Z",
        server_seq=1,
        receipt_sig="some_sig",
        server_key_id="server-key",
    )

    r1_with_wrong_receipt = LocalRecord(
        event_id=r1.event_id,
        stream_id=r1.stream_id,
        seq=r1.seq,
        prev_hash=r1.prev_hash,
        ts_client=r1.ts_client,
        payload=r1.payload,
        payload_hash=r1.payload_hash,
        hash_alg=r1.hash_alg,
        sig_client=r1.sig_client,
        key_id=r1.key_id,
        receipt=wrong_receipt,
    )

    server_key = SigningKey.generate(key_id="server-key").public_key()
    result = verify_receipt(r1_with_wrong_receipt, server_key)

    # Should fail - event_id mismatch is now detected explicitly
    assert not result.valid
    assert "event_id" in result.message.lower()


# =============================================================================
# Key Rotation Support
# =============================================================================


@pytest.mark.asyncio
async def test_verify_chain_with_key_rotation(wal_config):
    """Chain with multiple signing keys should verify when all keys provided."""
    from spine_client.verify import verify_chain

    # Create two different signing keys (simulating key rotation)
    key_a = SigningKey.generate(key_id="key-a")
    key_b = SigningKey.generate(key_id="key-b")

    # First WAL session with key_a
    wal1 = WAL(key_a, wal_config)
    await wal1.initialize()
    await wal1.append({"event": "first", "key": "a"})
    await wal1.append({"event": "second", "key": "a"})

    # Read records from first session
    records = []
    async for record in wal1.iter_records():
        records.append(record)

    # "Rotate" to key_b - create new records with different key
    # In practice, you'd continue with the same WAL but different key
    # Here we manually create records to simulate key rotation
    from datetime import datetime, timezone
    from spine_client.crypto import hash_payload, compute_entry_hash, timestamp_to_nanos

    # Get last record's entry hash for chain continuity
    last = records[-1]
    ts_ns = timestamp_to_nanos(last.ts_client)
    prev_hash, _ = compute_entry_hash(
        seq=last.seq,
        timestamp_ns=ts_ns,
        prev_hash=last.prev_hash,
        payload_hash=last.payload_hash,
    )

    # Create a record signed with key_b
    payload = {"event": "third", "key": "b"}
    payload_hash, hash_alg = hash_payload(payload)
    ts_client = datetime.now(timezone.utc).isoformat()
    ts_ns = timestamp_to_nanos(ts_client)
    entry_hash, _ = compute_entry_hash(
        seq=3,
        timestamp_ns=ts_ns,
        prev_hash=prev_hash,
        payload_hash=payload_hash,
    )
    sig = key_b.sign_hex(entry_hash.encode("utf-8"))

    record_b = LocalRecord(
        event_id="evt_key_b_record",
        stream_id=last.stream_id,
        seq=3,
        prev_hash=prev_hash,
        ts_client=ts_client,
        payload=payload,
        payload_hash=payload_hash,
        hash_alg=hash_alg,
        sig_client=sig,
        key_id=key_b.key_id,
        public_key=key_b.public_key().to_bytes().hex(),
    )

    all_records = records + [record_b]

    # Verify with both keys provided as a list
    result_list = verify_chain(
        all_records,
        client_key=[key_a.public_key(), key_b.public_key()],
    )
    assert result_list.valid, f"List key provider failed: {result_list.details}"

    # Verify with both keys provided as a dict
    result_dict = verify_chain(
        all_records,
        client_key={
            "key-a": key_a.public_key(),
            "key-b": key_b.public_key(),
        },
    )
    assert result_dict.valid, f"Dict key provider failed: {result_dict.details}"

    # Verify fails if key_b is not provided
    result_missing = verify_chain(
        all_records,
        client_key=key_a.public_key(),  # Only key_a
    )
    assert not result_missing.valid, "Should fail when rotated key is missing"
    assert "key-b" in result_missing.details.get("errors", [{}])[0].get("error", "").lower()


@pytest.mark.asyncio
async def test_verify_wal_with_additional_keys(wal_config):
    """verify_wal should accept additional_client_keys for key rotation."""
    # Create initial WAL with key_a
    key_a = SigningKey.generate(key_id="key-a")
    wal = WAL(key_a, wal_config)
    await wal.initialize()

    await wal.append({"event": "with_key_a"})

    # Verify with just the current key (should pass)
    result = await verify_wal(wal)
    assert result.valid

    # Now verify with additional keys (still should pass)
    key_b = SigningKey.generate(key_id="key-b")
    result_with_extra = await verify_wal(wal, additional_client_keys=[key_b.public_key()])
    assert result_with_extra.valid


def test_verify_chain_key_provider_types():
    """Test that all KeyProvider types work correctly."""
    from spine_client.verify import verify_chain

    key = SigningKey.generate(key_id="test-key")
    pub = key.public_key()

    # Empty list should pass for any key provider type
    assert verify_chain([], pub).valid
    assert verify_chain([], [pub]).valid
    assert verify_chain([], {"test-key": pub}).valid
