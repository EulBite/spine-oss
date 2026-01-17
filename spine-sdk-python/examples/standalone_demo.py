#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Standalone Demo - No server required!

Run this to see the SDK in action:
    python examples/standalone_demo.py

Then verify with CLI:
    spine-cli verify --wal ./demo_audit_log
"""

import asyncio
import json
from pathlib import Path
from spine_client import WAL, WALConfig, SigningKey, verify_wal


async def main():
    print("=" * 60)
    print("  SPINE SDK - Standalone Demo")
    print("  No server required!")
    print("=" * 60)
    print()

    # 1. Generate signing key
    print("[1/5] Generating Ed25519 signing key...")
    key = SigningKey.generate()
    print(f"      Key ID: {key.key_id}")
    print(f"      Public Key: {key.public_key().to_hex()[:32]}...")
    print()

    # 2. Create WAL
    wal_dir = "./demo_audit_log"
    print(f"[2/5] Creating WAL in {wal_dir}/")
    config = WALConfig(data_dir=wal_dir, retention_hours=24)
    wal = WAL(key, config, namespace="demo")
    await wal.initialize()
    print(f"      Stream ID: {wal.stream_id}")
    print()

    # 3. Log some events
    print("[3/5] Logging audit events...")
    events = [
        {"event_type": "user.login", "user_id": "alice", "ip": "192.168.1.1"},
        {"event_type": "data.access", "resource": "financial_report_q4", "action": "read"},
        {"event_type": "data.export", "format": "xlsx", "rows": 1500},
        {"event_type": "admin.config_change", "setting": "max_users", "old": 100, "new": 200},
        {"event_type": "user.logout", "user_id": "alice", "session_duration_sec": 3600},
    ]

    for event in events:
        record = await wal.append(event)
        print(f"      seq={record.seq}: {event['event_type']}")
    print()

    # 4. Verify chain integrity
    print("[4/5] Verifying chain integrity...")
    result = await verify_wal(wal)
    print(f"      Status: {result.status.value}")
    print(f"      Valid: {result.valid}")
    print(f"      Authoritative: {result.is_authoritative} (no server receipts)")
    print()

    # 5. Show stats and file location
    print("[5/5] WAL Statistics:")
    stats = await wal.get_stats()
    print(f"      Total events: {stats['seq']}")
    print(f"      Segments: {stats['segment_count']}")
    print(f"      Size: {stats['total_size_bytes']} bytes")
    print(f"      Data dir: {stats['data_dir']}")
    print()

    # Show how to verify with CLI
    print("=" * 60)
    print("  Next: Verify with spine-cli (independent verification)")
    print("=" * 60)
    print()
    print("  # Build CLI (if not already done)")
    print("  cd ../spine-cli && cargo build --release")
    print()
    print("  # Inspect WAL")
    print(f"  ./target/release/spine-cli inspect --wal {wal_dir} --stats")
    print()
    print("  # Full verification")
    print(f"  ./target/release/spine-cli verify --wal {wal_dir}")
    print()
    print("  # View events")
    print(f"  ./target/release/spine-cli inspect --wal {wal_dir} -n 5")
    print()

    # Show a sample record
    print("=" * 60)
    print("  Sample WAL record (JSONL format):")
    print("=" * 60)
    segments = sorted(Path(wal_dir).glob("segment_*.jsonl"))
    if segments:
        with open(segments[0]) as f:
            first_line = f.readline()
            record_dict = json.loads(first_line)
            # Pretty print with key fields highlighted
            print(json.dumps(record_dict, indent=2)[:500] + "...")


if __name__ == "__main__":
    asyncio.run(main())
