"""
Test script for Spine SDK standalone mode.

This demonstrates the SDK working WITHOUT a Spine server:
- Local hash chain
- Client-side signing
- Verification (client integrity claim)
"""

import asyncio
import shutil
from pathlib import Path

from spine_client import (
    WAL,
    WALConfig,
    SigningKey,
    verify_wal,
)


async def main():
    print("=" * 60)
    print("Spine SDK - Standalone Mode Test")
    print("=" * 60)

    # Clean up test directory
    test_dir = Path("./test_wal_standalone")
    if test_dir.exists():
        shutil.rmtree(test_dir)

    # 1. Generate signing key
    print("\n[1] Generating Ed25519 signing key...")
    key = SigningKey.generate()
    print(f"    Key ID: {key.key_id}")
    print(f"    Public key: {key.public_key().to_hex()[:32]}...")

    # 2. Create WAL
    print("\n[2] Creating WAL...")
    config = WALConfig(
        data_dir=str(test_dir),
        retention_hours=24,
    )
    wal = WAL(key, config, namespace="test")
    await wal.initialize()
    print(f"    Stream ID: {wal.stream_id}")
    print(f"    Data dir: {wal.data_dir}")

    # 3. Append events
    print("\n[3] Appending events...")
    events = [
        {"event_type": "user.login", "user_id": "alice", "ip": "192.168.1.1"},
        {"event_type": "data.access", "user_id": "alice", "resource": "secrets.db"},
        {"event_type": "data.export", "user_id": "alice", "records": 150},
        {"event_type": "user.logout", "user_id": "alice"},
    ]

    records = []
    for event in events:
        record = await wal.append(event)
        records.append(record)
        print(f"    seq={record.seq}: {event['event_type']}")
        print(f"        event_id: {record.event_id}")
        print(f"        payload_hash: {record.payload_hash[:32]}...")
        print(f"        prev_hash: {record.prev_hash[:32]}...")

    # 4. Verify chain
    print("\n[4] Verifying chain (local)...")
    result = await verify_wal(wal)
    print(f"    Valid: {result.valid}")
    print(f"    Status: {result.status.value}")
    print(f"    Message: {result.message}")
    print(f"    Authoritative: {result.is_authoritative}")
    print(f"    Details: {result.details}")

    # 5. Get stats
    print("\n[5] WAL statistics...")
    stats = await wal.get_stats()
    for k, v in stats.items():
        print(f"    {k}: {v}")

    # 6. Show that records have no receipt (client claim only)
    print("\n[6] Receipt status (server sync)...")
    unsynced_count = await wal.unsynced_count()
    print(f"    Records without receipt: {unsynced_count}")
    print(f"    These are 'client integrity claims' until synced to Spine")

    print("\n" + "=" * 60)
    print("Test complete!")
    print("Without Spine server: SDK provides 'Client Integrity Claim'")
    print("With Spine server: SDK provides 'Audit-grade Proof' via receipts")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
