#!/usr/bin/env python3
"""
Spine WAL Verification Report - Compliance demo in 30 seconds.

This example demonstrates:
- Creating a signed audit log with realistic events
- Running spine-cli verify to check integrity
- Generating a compliance-ready verification report

Perfect for:
- Demonstrating Spine to stakeholders
- Testing your verification pipeline
- Compliance audit rehearsals

Requirements:
    - spine-cli built (cargo build --release in spine-cli/)
    - Or spine-cli in PATH

Run:
    python wal_verify_report.py
"""

import asyncio
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from spine_client import WAL, WALConfig, SigningKey, AuditEvent, Severity, Actor, Resource


# Configuration
KEY_FILE = Path(__file__).parent / "demo_signing.key"
WAL_DIR = Path(__file__).parent / "demo_audit_log"
SPINE_CLI_PATHS = [
    Path(__file__).parent.parent.parent / "spine-cli" / "target" / "release" / "spine-cli",
    Path(__file__).parent.parent.parent / "spine-cli" / "target" / "release" / "spine-cli.exe",
    "spine-cli",  # If in PATH
]


def find_spine_cli() -> str | None:
    """Find spine-cli executable."""
    for path in SPINE_CLI_PATHS:
        if isinstance(path, Path):
            if path.exists():
                return str(path)
        else:
            # Check if in PATH
            if shutil.which(path):
                return path
    return None


def load_or_create_key() -> SigningKey:
    """Load or create a demo signing key."""
    if KEY_FILE.exists():
        return SigningKey.from_file(KEY_FILE, key_id="demo-compliance")

    key = SigningKey.generate(key_id="demo-compliance")
    key.save_to_file(KEY_FILE, key_format="hex")
    print(f"Generated demo signing key: {KEY_FILE}")
    return key


async def generate_demo_events(wal: WAL) -> int:
    """Generate realistic demo audit events."""
    events = [
        # Authentication events
        AuditEvent(
            event_type="auth.login",
            severity=Severity.INFO,
            actor=Actor(id="user_001", email="alice@example.com", role="analyst"),
            resource=Resource(type="application", id="dashboard", name="Analytics Dashboard"),
            payload={"method": "sso", "mfa_used": True, "session_duration_minutes": 480}
        ),
        AuditEvent(
            event_type="auth.login_failed",
            severity=Severity.WARNING,
            actor=Actor(id="user_002", ip_address="203.0.113.42"),
            payload={"reason": "invalid_password", "attempts": 3}
        ),

        # Data access events
        AuditEvent(
            event_type="data.query",
            severity=Severity.INFO,
            actor=Actor(id="user_001", role="analyst"),
            resource=Resource(type="database", id="customers_db", name="Customer Database"),
            payload={"query_type": "SELECT", "rows_returned": 150, "execution_time_ms": 45}
        ),
        AuditEvent(
            event_type="data.export",
            severity=Severity.HIGH,
            actor=Actor(id="user_001", role="analyst"),
            resource=Resource(type="report", id="q4_financials"),
            payload={"format": "csv", "records": 10000, "destination": "secure_share"}
        ),

        # Administrative events
        AuditEvent(
            event_type="admin.permission_change",
            severity=Severity.CRITICAL,
            actor=Actor(id="admin_001", role="superadmin"),
            resource=Resource(type="user", id="user_003"),
            payload={
                "previous_role": "viewer",
                "new_role": "admin",
                "justification": "Promotion to team lead",
                "approved_by": "manager_001"
            }
        ),
        AuditEvent(
            event_type="admin.config_change",
            severity=Severity.HIGH,
            actor=Actor(id="admin_001"),
            resource=Resource(type="system", id="auth_settings"),
            payload={
                "setting": "session_timeout_minutes",
                "old_value": 30,
                "new_value": 60,
                "change_ticket": "CHG-12345"
            }
        ),

        # System events
        AuditEvent(
            event_type="system.backup_completed",
            severity=Severity.INFO,
            source="backup_service",
            payload={"backup_id": "bkp_20260125_001", "size_mb": 2048, "duration_seconds": 120}
        ),
        AuditEvent(
            event_type="system.security_scan",
            severity=Severity.INFO,
            source="vulnerability_scanner",
            payload={"scan_type": "full", "vulnerabilities_found": 0, "last_scan_days_ago": 7}
        ),
    ]

    for event in events:
        await wal.append(event.to_dict())

    return len(events)


def run_verification(wal_dir: Path, spine_cli: str) -> tuple[bool, str]:
    """Run spine-cli verify and return result."""
    try:
        result = subprocess.run(
            [spine_cli, "verify", "--wal", str(wal_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        output = result.stdout + result.stderr
        success = result.returncode == 0
        return success, output
    except subprocess.TimeoutExpired:
        return False, "Verification timed out"
    except Exception as e:
        return False, f"Failed to run spine-cli: {e}"


def print_report(events_count: int, wal_dir: Path, key: SigningKey, verified: bool, cli_output: str):
    """Print a formatted compliance report."""
    now = datetime.now(timezone.utc)

    print()
    print("=" * 70)
    print("                    SPINE AUDIT LOG VERIFICATION REPORT")
    print("=" * 70)
    print()
    print(f"Report Generated:    {now.isoformat()}")
    print(f"WAL Location:        {wal_dir}")
    print(f"Signing Key ID:      {key.key_id}")
    print(f"Public Key:          {key.public_key().to_hex()[:32]}...")
    print()
    print("-" * 70)
    print("                           VERIFICATION RESULT")
    print("-" * 70)
    print()

    if verified:
        print("  STATUS:            VALID")
        print(f"  Events Verified:   {events_count}")
        print("  Chain Integrity:   INTACT")
        print("  Signatures:        ALL VALID")
    else:
        print("  STATUS:            FAILED")

    print()
    print("-" * 70)
    print("                           CLI OUTPUT")
    print("-" * 70)
    print()
    # Strip ANSI color codes and non-printable chars for Windows compatibility
    import re
    clean_output = re.sub(r'\x1b\[[0-9;]*m', '', cli_output)  # Remove ANSI codes
    for line in clean_output.strip().split("\n"):
        # Encode/decode to handle any remaining problematic chars
        safe_line = line.encode('ascii', errors='replace').decode('ascii')
        print(f"  {safe_line}")
    print()
    print("=" * 70)
    print()

    if verified:
        print("This audit log can be independently verified by any party with")
        print("access to the WAL files and the spine-cli tool.")
        print()
        print("For compliance purposes, archive the following:")
        print(f"  1. WAL directory: {wal_dir}/")
        print(f"  2. Public key:    {key.public_key().to_hex()}")
        print("  3. This verification report")
    else:
        print("VERIFICATION FAILED - Review the CLI output above for details.")

    print()


async def main():
    print("Spine WAL Verification Demo")
    print("=" * 40)
    print()

    # Check for spine-cli
    spine_cli = find_spine_cli()
    if not spine_cli:
        print("ERROR: spine-cli not found.")
        print()
        print("Build it with:")
        print("  cd spine-cli && cargo build --release")
        print()
        print("Or add it to your PATH.")
        sys.exit(1)

    print(f"Using spine-cli: {spine_cli}")

    # Clean up previous demo
    if WAL_DIR.exists():
        shutil.rmtree(WAL_DIR)
        print(f"Cleaned up previous demo: {WAL_DIR}")

    # Initialize
    key = load_or_create_key()
    wal = WAL(key, WALConfig(data_dir=str(WAL_DIR)))
    await wal.initialize()

    print(f"Initialized WAL: {WAL_DIR}")
    print()

    # Generate events
    print("Generating demo audit events...")
    events_count = await generate_demo_events(wal)
    print(f"  Created {events_count} signed events")

    # WAL data is persisted automatically (no close needed)
    print()

    # Run verification
    print("Running verification...")
    verified, cli_output = run_verification(WAL_DIR, spine_cli)

    # Print report
    print_report(events_count, WAL_DIR, key, verified, cli_output)


if __name__ == "__main__":
    asyncio.run(main())
