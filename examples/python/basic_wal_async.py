#!/usr/bin/env python3
"""
Basic Spine WAL Example - Minimal signed audit logging.

This example demonstrates:
- Loading or generating a signing key
- Initializing a WAL (Write-Ahead Log)
- Appending signed audit events
- Proper cleanup with try/finally

Run:
    python basic_wal_async.py

Verify:
    spine-cli verify --wal ./audit_log
"""

import asyncio
import os
from pathlib import Path

from spine_client import WAL, WALConfig, SigningKey, AuditEvent, Severity, Actor


KEY_FILE = Path(__file__).parent / "signing.key"
WAL_DIR = Path(__file__).parent / "audit_log"


def load_or_create_key() -> SigningKey:
    """
    Load signing key from environment, file, or generate new one.

    Priority:
    1. SPINE_KEY environment variable (hex, base64, or PEM)
    2. ./signing.key file
    3. Generate new key and save to ./signing.key
    """
    # 1. Try environment variable
    if os.environ.get("SPINE_KEY"):
        print(f"Using key from SPINE_KEY environment variable")
        return SigningKey.from_env("SPINE_KEY")

    # 2. Try key file
    if KEY_FILE.exists():
        print(f"Using key from {KEY_FILE}")
        return SigningKey.from_file(KEY_FILE, key_id="example")

    # 3. Generate and save new key
    print(f"Generating new signing key...")
    key = SigningKey.generate(key_id="example")
    key.save_to_file(KEY_FILE, key_format="hex")
    print(f"  Saved to {KEY_FILE}")
    print(f"  Key ID: {key.key_id}")
    print(f"  Public key: {key.public_key().to_hex()[:16]}...")
    print()
    print("  WARNING: This key will be used for all future runs.")
    print("  For production, manage keys securely (HSM, KMS, etc.)")
    print()
    return key


async def main():
    # Load or create signing key
    key = load_or_create_key()

    # Initialize WAL
    wal = WAL(key, WALConfig(data_dir=str(WAL_DIR)))
    await wal.initialize()

    try:
        # Log some audit events
        await wal.append(AuditEvent(
            event_type="example.started",
            severity=Severity.INFO,
            payload={"message": "Example script started"}
        ).to_dict())

        await wal.append(AuditEvent(
            event_type="user.action",
            severity=Severity.INFO,
            actor=Actor(id="user_123", email="alice@example.com"),
            payload={
                "action": "viewed_dashboard",
                "session_id": "sess_abc123",
            }
        ).to_dict())

        await wal.append(AuditEvent(
            event_type="example.completed",
            severity=Severity.INFO,
            payload={"events_logged": 3}
        ).to_dict())

        # Get stats
        stats = await wal.get_stats()
        print(f"WAL stats: {stats['seq']} records, {stats['total_size_bytes']} bytes")

    except Exception as e:
        print(f"Error: {e}")
        raise

    print()
    print(f"Events logged to {WAL_DIR}/")
    print(f"Verify with: spine-cli verify --wal {WAL_DIR}")


if __name__ == "__main__":
    asyncio.run(main())
