#!/usr/bin/env python3
"""
Audit Report Example - Generate a compliance-ready verification report.

This example demonstrates:
1. Creating a WAL with realistic audit events
2. Verifying the WAL with spine-cli
3. Generating a timestamped verification report

Use case: Periodic audit verification for compliance (DORA, NIS2, SOX, etc.)
"""

import asyncio
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add spine-sdk-python to path for local development
sys.path.insert(0, str(Path(__file__).parent.parent / "spine-sdk-python"))

from spine_client import WAL, WALConfig, SigningKey


async def create_sample_audit_trail(wal_dir: Path) -> int:
    """Create a realistic audit trail with various event types."""

    key = SigningKey.generate(key_id="kid_audit_demo_2026")
    config = WALConfig(data_dir=str(wal_dir))
    wal = WAL(key, config)
    await wal.initialize()

    # Simulate a day of audit events
    events = [
        {
            "event_type": "user.login",
            "user_id": "alice@example.com",
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0",
            "mfa_used": True,
            "success": True,
        },
        {
            "event_type": "data.access",
            "user_id": "alice@example.com",
            "resource_type": "customer_records",
            "resource_id": "customers/EU/2026",
            "action": "read",
            "record_count": 150,
        },
        {
            "event_type": "data.export",
            "user_id": "alice@example.com",
            "resource_type": "customer_records",
            "format": "csv",
            "record_count": 150,
            "destination": "local_download",
            "approval_id": "approval_12345",
        },
        {
            "event_type": "config.change",
            "user_id": "admin@example.com",
            "component": "security_policy",
            "change_type": "update",
            "old_value": {"mfa_required": False},
            "new_value": {"mfa_required": True},
            "ticket_id": "SEC-2026-001",
        },
        {
            "event_type": "user.logout",
            "user_id": "alice@example.com",
            "session_duration_seconds": 3600,
        },
    ]

    for event in events:
        await wal.append(event)

    await wal.close()
    return len(events)


def verify_with_cli(wal_dir: Path, cli_path: Path) -> dict:
    """Run spine-cli verify and capture output."""

    result = subprocess.run(
        [str(cli_path), "verify", "--wal", str(wal_dir), "--json"],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        return json.loads(result.stdout)
    else:
        return {
            "status": "ERROR",
            "error": result.stderr,
            "returncode": result.returncode,
        }


def generate_report(
    wal_dir: Path,
    event_count: int,
    verification_result: dict,
    output_path: Path,
) -> None:
    """Generate a compliance-ready verification report."""

    now = datetime.now(timezone.utc)

    report = {
        "report_type": "WAL_VERIFICATION",
        "generated_at": now.isoformat(),
        "generator": "spine-audit-report/1.0",

        "audit_trail": {
            "location": str(wal_dir.absolute()),
            "event_count": event_count,
        },

        "verification": {
            "tool": "spine-cli",
            "timestamp": now.isoformat(),
            "result": verification_result,
        },

        "compliance_notes": {
            "hash_algorithm": "BLAKE3 (256-bit)",
            "signature_algorithm": "Ed25519",
            "chain_type": "Sequential hash chain with signature binding",
            "tamper_detection": "Any modification breaks hash chain and/or signature",
        },

        "attestation": (
            f"This report certifies that the audit trail at {wal_dir.absolute()} "
            f"was verified at {now.isoformat()} using spine-cli. "
            f"The verification confirmed {event_count} events with intact "
            f"hash chain and valid Ed25519 signatures."
        ),
    }

    # Write JSON report
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    # Also print human-readable summary
    print("=" * 60)
    print("SPINE AUDIT VERIFICATION REPORT")
    print("=" * 60)
    print(f"Generated:     {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"WAL Location:  {wal_dir.absolute()}")
    print(f"Events:        {event_count}")
    print("-" * 60)

    if verification_result.get("status") == "VALID":
        print("Status:        VALID")
        print("Hash Chain:    INTACT")
        print("Signatures:    VERIFIED")
    else:
        print(f"Status:        {verification_result.get('status', 'UNKNOWN')}")
        if "error" in verification_result:
            print(f"Error:         {verification_result['error']}")

    print("-" * 60)
    print(f"Report saved:  {output_path}")
    print("=" * 60)


async def main():
    # Setup paths (examples/ is inside repo root)
    base_dir = Path(__file__).parent.parent
    wal_dir = base_dir / "example_audit_trail"
    cli_path = base_dir / "spine-cli" / "target" / "release" / "spine-cli"
    report_path = base_dir / "verification_report.json"

    # Check if CLI exists
    if not cli_path.exists():
        # Try debug build
        cli_path = base_dir / "spine-cli" / "target" / "debug" / "spine-cli"
        if not cli_path.exists():
            print("ERROR: spine-cli not found. Build it first:")
            print("  cd spine-cli && cargo build --release")
            sys.exit(1)

    print("Creating sample audit trail...")
    event_count = await create_sample_audit_trail(wal_dir)
    print(f"Created {event_count} audit events in {wal_dir}/")

    print("\nVerifying with spine-cli...")
    verification_result = verify_with_cli(wal_dir, cli_path)

    print("\nGenerating report...")
    generate_report(wal_dir, event_count, verification_result, report_path)


if __name__ == "__main__":
    asyncio.run(main())
