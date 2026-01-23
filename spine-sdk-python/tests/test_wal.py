# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""Tests for Write-Ahead Log (WAL) functionality."""

import asyncio

import pytest

from spine_client.crypto import SigningKey, compute_entry_hash, hash_payload, timestamp_to_nanos
from spine_client.wal import GENESIS_HASH, WAL, WALConfig


@pytest.fixture
def signing_key():
    """Generate a fresh signing key for tests."""
    return SigningKey.generate(key_id="test-key")


@pytest.fixture
def wal_config(tmp_path):
    """Create WAL config pointing to temp directory."""
    return WALConfig(data_dir=str(tmp_path / "wal"))


# =============================================================================
# Basic Operations
# =============================================================================


@pytest.mark.asyncio
async def test_wal_initialize(signing_key, wal_config):
    """WAL should initialize and create data directory."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    assert wal._initialized
    assert wal.data_dir.exists()


@pytest.mark.asyncio
async def test_wal_append_single(signing_key, wal_config):
    """Should append a single event to WAL."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    payload = {"event_type": "user.login", "user_id": "alice"}
    record = await wal.append(payload)

    assert record.seq == 1
    assert record.payload == payload
    assert record.prev_hash == GENESIS_HASH
    assert record.key_id == "test-key"
    assert record.sig_client is not None
    assert len(record.sig_client) == 128  # 64 bytes hex


@pytest.mark.asyncio
async def test_wal_append_multiple(signing_key, wal_config):
    """Should append multiple events with incrementing sequence."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    records = []
    for i in range(5):
        record = await wal.append({"event": f"test_{i}"})
        records.append(record)

    # Check sequence numbers
    assert [r.seq for r in records] == [1, 2, 3, 4, 5]

    # Check each record links to previous
    assert records[0].prev_hash == GENESIS_HASH
    for i in range(1, 5):
        assert records[i].prev_hash != GENESIS_HASH
        assert records[i].prev_hash != records[i - 1].prev_hash


# =============================================================================
# Hash Chain Integrity
# =============================================================================


@pytest.mark.asyncio
async def test_hash_chain_linkage(signing_key, wal_config):
    """Each record's prev_hash should be the entry_hash of the previous record."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Append records
    r1 = await wal.append({"event": "first"})
    r2 = await wal.append({"event": "second"})
    r3 = await wal.append({"event": "third"})

    # Manually compute entry hashes and verify chain
    def compute_record_entry_hash(record):
        ts_ns = timestamp_to_nanos(record.ts_client)
        entry_hash, _ = compute_entry_hash(
            seq=record.seq,
            timestamp_ns=ts_ns,
            prev_hash=record.prev_hash,
            payload_hash=record.payload_hash,
        )
        return entry_hash

    # r1's entry_hash should be r2's prev_hash
    r1_hash = compute_record_entry_hash(r1)
    assert r2.prev_hash == r1_hash

    # r2's entry_hash should be r3's prev_hash
    r2_hash = compute_record_entry_hash(r2)
    assert r3.prev_hash == r2_hash


@pytest.mark.asyncio
async def test_signature_verification(signing_key, wal_config):
    """Client signature should be verifiable."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    record = await wal.append({"event": "signed_event"})

    # Recompute entry hash
    ts_ns = timestamp_to_nanos(record.ts_client)
    entry_hash, _ = compute_entry_hash(
        seq=record.seq,
        timestamp_ns=ts_ns,
        prev_hash=record.prev_hash,
        payload_hash=record.payload_hash,
    )

    # Verify signature
    pub_key = signing_key.public_key()
    is_valid = pub_key.verify_hex(record.sig_client, entry_hash.encode("utf-8"))
    assert is_valid


# =============================================================================
# Persistence and Recovery
# =============================================================================


@pytest.mark.asyncio
async def test_wal_recovery(signing_key, wal_config):
    """WAL should recover state after restart."""
    # First session: write some records
    wal1 = WAL(signing_key, wal_config)
    await wal1.initialize()
    await wal1.append({"event": "first"})
    await wal1.append({"event": "second"})
    await wal1.append({"event": "third"})

    # Simulate restart with new WAL instance
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()

    # Should continue from seq 3
    assert wal2._seq == 3

    # New append should be seq 4
    new_record = await wal2.append({"event": "fourth"})
    assert new_record.seq == 4


@pytest.mark.asyncio
async def test_wal_recovery_chain_continuity(signing_key, wal_config):
    """Recovered WAL should maintain chain continuity."""
    # First session
    wal1 = WAL(signing_key, wal_config)
    await wal1.initialize()
    await wal1.append({"event": "first"})
    r2 = await wal1.append({"event": "second"})

    # Get r2's entry hash (will be prev_hash for next record)
    ts_ns = timestamp_to_nanos(r2.ts_client)
    r2_entry_hash, _ = compute_entry_hash(
        seq=r2.seq,
        timestamp_ns=ts_ns,
        prev_hash=r2.prev_hash,
        payload_hash=r2.payload_hash,
    )

    # Restart
    wal2 = WAL(signing_key, wal_config)
    await wal2.initialize()
    r3 = await wal2.append({"event": "third"})

    # r3 should link to r2
    assert r3.prev_hash == r2_entry_hash


# =============================================================================
# Special Payloads
# =============================================================================


@pytest.mark.asyncio
async def test_payload_with_newlines(signing_key, wal_config):
    """Payloads with newlines should be handled correctly."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    payload = {
        "message": "Line 1\nLine 2\nLine 3",
        "multiline": "First\n\nThird",
    }
    record = await wal.append(payload)

    # Verify payload round-trips correctly
    assert record.payload == payload
    assert record.payload["message"] == "Line 1\nLine 2\nLine 3"


@pytest.mark.asyncio
async def test_payload_with_unicode(signing_key, wal_config):
    """Payloads with unicode should be handled correctly."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    payload = {
        "emoji": "Hello 👋 World 🌍",
        "accents": "café résumé naïve",
        "cjk": "日本語 中文 한국어",
        "rtl": "مرحبا שלום",
    }
    record = await wal.append(payload)

    assert record.payload == payload


@pytest.mark.asyncio
async def test_payload_with_special_chars(signing_key, wal_config):
    """Payloads with special characters should be handled correctly."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    payload = {
        "quotes": 'He said "hello"',
        "backslash": "path\\to\\file",
        "tabs": "col1\tcol2\tcol3",
        "null_char": "before\x00after",  # null byte
    }
    record = await wal.append(payload)

    # Null byte might be escaped, but others should round-trip
    assert record.payload["quotes"] == 'He said "hello"'
    assert record.payload["backslash"] == "path\\to\\file"
    assert record.payload["tabs"] == "col1\tcol2\tcol3"


# =============================================================================
# Iteration and Retrieval
# =============================================================================


@pytest.mark.asyncio
async def test_iter_records(signing_key, wal_config):
    """Should iterate over all records in order."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Append records
    for i in range(10):
        await wal.append({"index": i})

    # Iterate and collect
    records = []
    async for record in wal.iter_records():
        records.append(record)

    assert len(records) == 10
    assert [r.payload["index"] for r in records] == list(range(10))


@pytest.mark.asyncio
async def test_get_record_by_id(signing_key, wal_config):
    """Should retrieve specific record by event_id."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "first"})
    r2 = await wal.append({"event": "second"})
    await wal.append({"event": "third"})

    # Retrieve by ID
    found = await wal.get_record(r2.event_id)
    assert found is not None
    assert found.event_id == r2.event_id
    assert found.payload == {"event": "second"}


@pytest.mark.asyncio
async def test_get_record_not_found(signing_key, wal_config):
    """Should return None for non-existent event_id."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    await wal.append({"event": "test"})

    found = await wal.get_record("evt_nonexistent")
    assert found is None


# =============================================================================
# Statistics
# =============================================================================


@pytest.mark.asyncio
async def test_wal_stats(signing_key, wal_config):
    """Should return accurate statistics."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Append some records
    for i in range(5):
        await wal.append({"index": i})

    stats = await wal.get_stats()

    assert stats["seq"] == 5
    assert stats["key_id"] == "test-key"
    assert stats["segment_count"] >= 1
    assert stats["total_size_bytes"] > 0


# =============================================================================
# Concurrent Access
# =============================================================================


@pytest.mark.asyncio
async def test_concurrent_appends(signing_key, wal_config):
    """Concurrent appends should maintain sequence integrity."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Launch concurrent appends
    async def append_event(index):
        return await wal.append({"index": index})

    tasks = [append_event(i) for i in range(20)]
    records = await asyncio.gather(*tasks)

    # All sequence numbers should be unique
    seqs = [r.seq for r in records]
    assert len(seqs) == len(set(seqs)), "Duplicate sequence numbers detected"

    # Should cover 1-20
    assert sorted(seqs) == list(range(1, 21))


# =============================================================================
# Edge Cases
# =============================================================================


@pytest.mark.asyncio
async def test_empty_payload(signing_key, wal_config):
    """Should handle empty payload."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    record = await wal.append({})
    assert record.payload == {}
    assert record.payload_hash is not None


@pytest.mark.asyncio
async def test_large_payload(signing_key, wal_config):
    """Should handle large payloads."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # 100KB payload
    large_data = "x" * 100_000
    record = await wal.append({"data": large_data})

    assert len(record.payload["data"]) == 100_000


@pytest.mark.asyncio
async def test_nested_payload(signing_key, wal_config):
    """Should handle deeply nested payloads."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    payload = {
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "value": "deep"
                    }
                }
            }
        }
    }
    record = await wal.append(payload)

    assert record.payload["level1"]["level2"]["level3"]["level4"]["value"] == "deep"


@pytest.mark.asyncio
async def test_payload_hash_deterministic(signing_key, wal_config):
    """Same payload should produce same hash regardless of key order."""
    wal = WAL(signing_key, wal_config)
    await wal.initialize()

    # Two payloads with same content, different key order
    payload1 = {"b": 2, "a": 1}
    payload2 = {"a": 1, "b": 2}

    hash1, _ = hash_payload(payload1)
    hash2, _ = hash_payload(payload2)

    assert hash1 == hash2, "Canonical JSON should normalize key order"
