#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Shadow Mode Integration Example

Demonstrates running Spine in parallel with existing logging infrastructure.
Events are duplicated to Spine without modifying application code.

Use Case:
- POC evaluation alongside existing SIEM
- Zero-risk integration testing
- Performance comparison
"""

import asyncio
import logging
import random
from datetime import datetime, timezone

from spine_client.sidecar import ShadowModeSidecar

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


# Simulated existing log sources
def simulate_syslog_events(count: int = 100):
    """Simulate syslog-style events from existing infrastructure."""
    priorities = ["info", "warning", "error"]
    facilities = ["auth", "daemon", "kernel", "user"]

    for idx in range(count):
        yield {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "priority": random.choice(priorities),
            "facility": random.choice(facilities),
            "host": f"server-{random.randint(1, 10):02d}",
            "program": random.choice(["sshd", "cron", "systemd", "nginx"]),
            "message": f"Simulated syslog message {idx}",
            "pid": random.randint(1000, 65000),
        }


def simulate_windows_events(count: int = 100):
    """Simulate Windows Event Log entries."""
    event_ids = [4624, 4625, 4634, 4648, 4672, 4720, 4732]
    levels = ["Information", "Warning", "Error"]

    for _ in range(count):
        yield {
            "TimeCreated": datetime.now(timezone.utc).isoformat(),
            "EventID": random.choice(event_ids),
            "Level": random.choice(levels),
            "Computer": f"WORKSTATION-{random.randint(1, 50):03d}",
            "Channel": "Security",
            "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
            "EventData": {
                "TargetUserName": f"user{random.randint(1, 100)}",
                "TargetDomainName": "CORP",
                "LogonType": random.choice([2, 3, 7, 10]),
            },
        }


def simulate_application_logs(count: int = 100):
    """Simulate application JSON logs."""
    actions = ["login", "logout", "read", "write", "delete", "export"]
    resources = ["user", "document", "report", "config", "api"]

    for _ in range(count):
        yield {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": random.choice(["DEBUG", "INFO", "WARN", "ERROR"]),
            "service": f"service-{random.choice(['auth', 'api', 'worker'])}",
            "trace_id": f"trace-{random.randint(100000, 999999)}",
            "action": random.choice(actions),
            "resource_type": random.choice(resources),
            "resource_id": f"res-{random.randint(1000, 9999)}",
            "user_id": f"user-{random.randint(1, 100)}",
            "duration_ms": random.randint(1, 500),
            "success": random.random() > 0.1,
        }


def syslog_to_severity(priority: str) -> str:
    """Map syslog priority to Spine severity."""
    mapping = {
        "debug": "debug",
        "info": "info",
        "notice": "info",
        "warning": "warning",
        "err": "high",
        "error": "high",
        "crit": "critical",
        "alert": "critical",
        "emerg": "critical",
    }
    return mapping.get(priority.lower(), "info")


def windows_level_to_severity(level: str) -> str:
    """Map Windows event level to Spine severity."""
    mapping = {
        "Information": "info",
        "Warning": "warning",
        "Error": "high",
        "Critical": "critical",
    }
    return mapping.get(level, "info")


async def forward_syslog(shadow: ShadowModeSidecar, events):
    """Forward syslog events to Spine."""
    count = 0
    for event in events:
        await shadow.forward_log(
            log_data=event,
            event_type=f"syslog.{event['facility']}.{event['program']}",
            severity=syslog_to_severity(event["priority"]),
        )
        count += 1
    return count


async def forward_windows(shadow: ShadowModeSidecar, events):
    """Forward Windows events to Spine."""
    count = 0
    for event in events:
        await shadow.forward_log(
            log_data=event,
            event_type=f"windows.security.{event['EventID']}",
            severity=windows_level_to_severity(event["Level"]),
        )
        count += 1
    return count


async def forward_application(shadow: ShadowModeSidecar, events):
    """Forward application logs to Spine."""
    count = 0
    for event in events:
        severity = "info"
        if event["level"] == "ERROR":
            severity = "high"
        elif event["level"] == "WARN":
            severity = "warning"

        await shadow.forward_log(
            log_data=event,
            event_type=f"app.{event['service']}.{event['action']}",
            severity=severity,
        )
        count += 1
    return count


async def main():
    # Initialize shadow mode sidecar
    shadow = ShadowModeSidecar(
        spine_url="http://localhost:3000",
        source_name="shadow-forwarder-poc",
        buffer_size=50000,  # Large buffer for shadow mode
        emit_timeout_ms=100,
    )

    try:
        await shadow.start()
        logger.info("Shadow mode sidecar started")

        # Forward from multiple sources in parallel
        logger.info("=== Starting shadow mode forwarding ===")

        tasks = [
            forward_syslog(shadow, simulate_syslog_events(100)),
            forward_windows(shadow, simulate_windows_events(100)),
            forward_application(shadow, simulate_application_logs(100)),
        ]

        results = await asyncio.gather(*tasks)
        total = sum(results)

        logger.info(f"Forwarded {total} events to Spine in shadow mode")
        logger.info(f"  - Syslog: {results[0]}")
        logger.info(f"  - Windows: {results[1]}")
        logger.info(f"  - Application: {results[2]}")

        # Wait for buffer to flush
        await asyncio.sleep(2)

        # Show metrics
        metrics = shadow.get_metrics()
        logger.info("=== Shadow Mode Metrics ===")
        logger.info(f"Events received: {metrics['events_received']}")
        logger.info(f"Events sent: {metrics['events_sent']}")
        logger.info(f"Events in buffer: {metrics['buffer_current']}")
        logger.info(f"Events dropped: {metrics['events_dropped']}")

    finally:
        await shadow.stop(flush=True)
        logger.info("Shadow mode sidecar stopped")


if __name__ == "__main__":
    asyncio.run(main())
