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
from .verify import verify_wal, verify_wal_with_root
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
    verify_parser = subparsers.add_parser("verify", help="Verify WAL chain integrity")
    verify_parser.add_argument(
        "--root-key",
        help="Path to root key file for chain of trust verification",
    )
    verify_parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict file order verification (forensic mode)",
    )

    # rotate-key command
    rotate_parser = subparsers.add_parser("rotate-key", help="Rotate to a new signing key")
    rotate_parser.add_argument(
        "--new-key-file",
        help="Path to new key file (generates new if not exists)",
    )
    rotate_parser.add_argument(
        "--new-key-id",
        help="ID for the new key (auto-generated if not specified)",
    )
    rotate_parser.add_argument(
        "--reason",
        default="cli rotation",
        help="Reason for rotation (default: 'cli rotation')",
    )

    # keys command (show key history)
    subparsers.add_parser("keys", help="Show key rotation history from WAL")

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
        key = SigningKey.from_seed_bytes(seed, key_id)
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

    # Use chain of trust verification if root key specified
    if args.root_key:
        root_key_path = Path(args.root_key)
        if not root_key_path.exists():
            print(f"Root key file not found: {args.root_key}", file=sys.stderr)
            return 1
        # Load key_id from .key_id file if exists (matches get_or_create_key pattern)
        key_id_path = root_key_path.with_suffix(".key_id")
        if key_id_path.exists():
            root_key_id = key_id_path.read_text().strip()
        else:
            # Fallback: generate from seed bytes
            seed = root_key_path.read_bytes()
            root_key_id = f"kid_{seed[:8].hex()}"
        root_key = SigningKey.from_file(root_key_path, key_id=root_key_id)
        print(f"Verifying with root key: {root_key.key_id}")
        result = await verify_wal_with_root(
            wal,
            root_key.public_key(),
            strict_file_order=args.strict,
        )
    else:
        result = await verify_wal(wal, strict_file_order=args.strict)

    # Show verification mode (affects audit interpretation)
    mode = result.details.get("mode", "resilient")
    print(f"Mode: {mode}")

    if result.valid:
        print("Status: VALID")
        print(f"  Records: {result.details.get('count', 'N/A')}")
        if "key_rotations" in result.details:
            print(f"  Key rotations: {result.details['key_rotations']}")
            print(f"  Trusted keys: {', '.join(result.details.get('trusted_keys', []))}")
    else:
        print("Status: INVALID")
        print(f"  {result.message}")
        if "errors" in result.details:
            for err in result.details["errors"][:5]:  # Show first 5 errors
                print(f"  - seq {err.get('seq')}: {err.get('error')}")

    print(f"Authoritative: {result.is_authoritative}")

    return 0 if result.valid else 1


async def cmd_rotate_key(args: argparse.Namespace) -> int:
    """Rotate to a new signing key."""
    # Load current key
    key = await get_or_create_key(args.key_file, args.wal_dir)
    print(f"Current key: {key.key_id}")

    config = WALConfig(data_dir=args.wal_dir)
    wal = WAL(key, config)
    await wal.initialize()

    # Generate or load new key
    if args.new_key_file:
        new_key_path = Path(args.new_key_file)
        if new_key_path.exists():
            new_key = SigningKey.from_file(new_key_path, key_id=args.new_key_id)
            print(f"Loaded new key from: {new_key_path}")
        else:
            new_key = SigningKey.generate(key_id=args.new_key_id)
            new_key.save_to_file(new_key_path)
            print(f"Generated new key: {new_key.key_id}")
            print(f"Saved to: {new_key_path}")
    else:
        new_key = SigningKey.generate(key_id=args.new_key_id)
        # Save to default location
        default_path = Path(args.wal_dir) / f".spine_key_{new_key.key_id}"
        new_key.save_to_file(default_path, key_format="raw")
        default_path.with_suffix(".key_id").write_text(new_key.key_id)
        print(f"Generated new key: {new_key.key_id}")
        print(f"Saved to: {default_path}")

    # Perform rotation
    rotation_record = await wal.rotate_key(new_key, reason=args.reason)

    print()
    print("Key rotation complete!")
    print(f"  Old key:         {key.key_id}")
    print(f"  New key:         {new_key.key_id}")
    print(f"  Rotation record: seq={rotation_record.seq}")
    print(f"  Reason:          {args.reason}")
    print()
    print("Future events will be signed with the new key.")
    print("The rotation is cryptographically linked to the old key (chain of trust).")

    return 0


async def cmd_keys(args: argparse.Namespace) -> int:
    """Show key rotation history from WAL."""
    from .types import KeyRotationPayload

    key = await get_or_create_key(args.key_file, args.wal_dir)

    config = WALConfig(data_dir=args.wal_dir)
    wal = WAL(key, config)
    await wal.initialize()

    print(f"Key History ({args.wal_dir})")
    print("-" * 50)
    print(f"  Current key: {key.key_id}")
    print()

    rotations = []
    async for record in wal.iter_records():
        if KeyRotationPayload.is_rotation_payload(record.payload):
            rotation = KeyRotationPayload.from_dict(record.payload)
            rotations.append({
                "seq": record.seq,
                "old_key": record.key_id,
                "new_key": rotation.new_key_id,
                "reason": rotation.reason,
                "timestamp": record.ts_client,
            })

    if rotations:
        print(f"Rotations ({len(rotations)}):")
        for r in rotations:
            print(f"  seq={r['seq']}: {r['old_key']} -> {r['new_key']}")
            if r["reason"]:
                print(f"    reason: {r['reason']}")
            print(f"    time: {r['timestamp']}")
    else:
        print("No key rotations found.")

    return 0


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
    elif args.command == "rotate-key":
        return await cmd_rotate_key(args)
    elif args.command == "keys":
        return await cmd_keys(args)
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
