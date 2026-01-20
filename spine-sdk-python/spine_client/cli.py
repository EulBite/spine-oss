# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Spine SDK CLI - Quick demo and testing utility.

Usage:
    python -m spine_client demo              # Run interactive demo
    python -m spine_client log <event_json>  # Log a single event
    python -m spine_client stats             # Show WAL statistics
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .crypto import SigningKey
from .verify import verify_wal
from .wal import WAL, WALConfig


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spine-sdk",
        description="Spine SDK - Cryptographic audit logging",
    )
    parser.add_argument(
        "--wal-dir",
        default="./spine_wal",
        help="WAL directory (default: ./spine_wal)",
    )
    parser.add_argument(
        "--key-file",
        help="Path to key file (generates new if not exists)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # demo command
    demo_parser = subparsers.add_parser("demo", help="Run interactive demo")
    demo_parser.add_argument(
        "-n", "--events",
        type=int,
        default=5,
        help="Number of demo events to log (default: 5)",
    )

    # log command
    log_parser = subparsers.add_parser("log", help="Log an event")
    log_parser.add_argument(
        "event",
        help='Event JSON, e.g. \'{"event_type": "user.login", "user_id": "alice"}\'',
    )

    # stats command
    subparsers.add_parser("stats", help="Show WAL statistics")

    # verify command
    subparsers.add_parser("verify", help="Verify WAL chain integrity")

    return parser


async def get_or_create_key(key_file: str | None, wal_dir: str) -> SigningKey:
    """Load key from file or generate new one."""
    key_path = Path(key_file) if key_file else Path(wal_dir) / ".spine_key"
    key_id_path = key_path.with_suffix(".key_id")

    if key_path.exists():
        with open(key_path, "rb") as f:
            seed = f.read()
        # Load key_id if saved, otherwise generate one
        if key_id_path.exists():
            key_id = key_id_path.read_text().strip()
        else:
            key_id = f"kid_{seed[:8].hex()}"
        key = SigningKey.from_bytes(seed, key_id)
        print(f"Loaded key: {key.key_id}")
    else:
        key = SigningKey.generate()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(key.to_bytes())
        # Save key_id separately for reload
        key_id_path.write_text(key.key_id)
        print(f"Generated new key: {key.key_id}")
        print(f"Saved to: {key_path}")

    return key


async def cmd_demo(args: argparse.Namespace) -> int:
    """Run interactive demo."""
    print("=" * 50)
    print("  Spine SDK Demo")
    print("=" * 50)
    print()

    key = await get_or_create_key(args.key_file, args.wal_dir)

    config = WALConfig(data_dir=args.wal_dir)
    wal = WAL(key, config)
    await wal.initialize()

    print(f"WAL directory: {args.wal_dir}")
    print()

    demo_events = [
        {"event_type": "user.login", "user_id": "alice", "ip": "192.168.1.1"},
        {"event_type": "data.access", "resource": "report_q4", "action": "read"},
        {"event_type": "data.export", "format": "csv", "rows": 1000},
        {"event_type": "config.change", "setting": "timeout", "value": 30},
        {"event_type": "user.logout", "user_id": "alice"},
    ]

    print(f"Logging {args.events} events...")
    for event in demo_events[: args.events]:
        record = await wal.append(event)
        print(f"  [{record.seq}] {event['event_type']}")

    print()
    print("Verifying chain...")
    result = await verify_wal(wal)
    print(f"  Status: {'VALID' if result.valid else 'INVALID'}")
    print()

    stats = await wal.get_stats()
    print(f"Total events: {stats['seq']}")
    print()
    print("Next steps:")
    print(f"  spine-cli verify --wal {args.wal_dir}")
    print(f"  spine-cli inspect --wal {args.wal_dir} -n 10")

    return 0


async def cmd_log(args: argparse.Namespace) -> int:
    """Log a single event."""
    try:
        event = json.loads(args.event)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON: {e}", file=sys.stderr)
        return 1

    key = await get_or_create_key(args.key_file, args.wal_dir)

    config = WALConfig(data_dir=args.wal_dir)
    wal = WAL(key, config)
    await wal.initialize()

    record = await wal.append(event)
    print(f"Logged: seq={record.seq} event_id={record.event_id}")
    print(f"  hash: {record.payload_hash[:32]}...")

    return 0


async def cmd_stats(args: argparse.Namespace) -> int:
    """Show WAL statistics."""
    key = await get_or_create_key(args.key_file, args.wal_dir)

    config = WALConfig(data_dir=args.wal_dir)
    wal = WAL(key, config)
    await wal.initialize()

    stats = await wal.get_stats()
    print(f"WAL Statistics ({args.wal_dir})")
    print("-" * 40)
    print(f"  Key ID:         {stats['key_id']}")
    print(f"  Total events:   {stats['seq']}")
    print(f"  Segments:       {stats['segment_count']}")
    print(f"  Size:           {stats['total_size_bytes']} bytes")
    print(f"  Unsynced:       {stats['unsynced_count']}")
    print(f"  Retention:      {stats['retention_hours']}h")

    return 0


async def cmd_verify(args: argparse.Namespace) -> int:
    """Verify WAL chain integrity."""
    key = await get_or_create_key(args.key_file, args.wal_dir)

    config = WALConfig(data_dir=args.wal_dir)
    wal = WAL(key, config)
    await wal.initialize()

    result = await verify_wal(wal)

    if result.valid:
        print("Status: VALID")
    else:
        print("Status: INVALID")
        print(f"  {result.message}")

    print(f"Authoritative: {result.is_authoritative}")

    return 0 if result.valid else 1


async def main_async(args: argparse.Namespace) -> int:
    """Async main entry point."""
    if args.command == "demo":
        return await cmd_demo(args)
    elif args.command == "log":
        return await cmd_log(args)
    elif args.command == "stats":
        return await cmd_stats(args)
    elif args.command == "verify":
        return await cmd_verify(args)
    else:
        parser = create_parser()
        parser.print_help()
        return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
