#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Sidecar Integration Example

Demonstrates non-blocking audit logging for critical systems like SCADA.
Events are buffered locally and sent asynchronously - the main application
is never blocked by Spine availability.

Use Case:
- OT/SCADA systems where latency is critical
- High-throughput applications
- Systems that must not depend on external services
"""

import asyncio
import logging
import random
import time

from spine_client import Actor, AuditEvent, AuditSidecar, Resource
from spine_client.events import Severity

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


def on_event_dropped(event: AuditEvent, reason: str):
    """Callback when an event is dropped due to buffer overflow."""
    logger.warning(f"Event dropped ({reason}): {event.event_type}")
    # In production, you might want to:
    # - Write to a local file
    # - Increment a metric
    # - Alert operations


async def simulate_scada_operations(sidecar: AuditSidecar, duration_secs: int = 30):
    """
    Simulate SCADA operations generating audit events.

    This simulates a control system that:
    - Reads sensor values every 100ms
    - Sends control commands periodically
    - Generates alarms on threshold violations
    """
    logger.info(f"Starting SCADA simulation for {duration_secs}s")

    devices = ["valve_01", "pump_02", "sensor_03", "actuator_04"]
    start_time = time.time()
    event_count = 0

    while (time.time() - start_time) < duration_secs:
        device = random.choice(devices)

        # Simulate different types of SCADA events
        event_type = random.choices(
            ["scada.reading", "scada.command", "scada.alarm"],
            weights=[70, 20, 10]
        )[0]

        if event_type == "scada.reading":
            event = AuditEvent(
                event_type="scada.reading",
                severity=Severity.DEBUG,
                resource=Resource(type="sensor", id=device),
                payload={
                    "value": random.uniform(0, 100),
                    "unit": "psi",
                    "quality": "good",
                },
                source="scada-controller",
            )
        elif event_type == "scada.command":
            event = AuditEvent(
                event_type="scada.command",
                severity=Severity.INFO,
                actor=Actor(id="operator_01", role="operator"),
                resource=Resource(type="actuator", id=device),
                payload={
                    "command": random.choice(["open", "close", "set"]),
                    "target_value": random.randint(0, 100),
                },
                source="hmi-station-01",
            )
        else:  # alarm
            event = AuditEvent(
                event_type="scada.alarm",
                severity=Severity.WARNING,
                resource=Resource(type="sensor", id=device),
                payload={
                    "alarm_type": "threshold_high",
                    "current_value": random.uniform(90, 110),
                    "threshold": 90,
                    "acknowledged": False,
                },
                source="alarm-manager",
            )

        # Emit event - this should NEVER block the control loop
        emit_start = time.monotonic()
        await sidecar.emit(event)
        emit_time = (time.monotonic() - emit_start) * 1000

        if emit_time > 10:  # Log if > 10ms
            logger.warning(f"Slow emit: {emit_time:.2f}ms")

        event_count += 1

        # Simulate control loop timing (10Hz = 100ms)
        await asyncio.sleep(0.1)

    logger.info(f"Simulation complete: {event_count} events generated")
    return event_count


async def monitor_sidecar(sidecar: AuditSidecar, interval_secs: float = 5.0):
    """Monitor sidecar health and metrics."""
    while True:
        metrics = sidecar.get_metrics()
        logger.info(
            f"Sidecar metrics: "
            f"buffer={metrics['buffer_current']}/{metrics['buffer_capacity']} "
            f"sent={metrics['events_sent']} "
            f"dropped={metrics['events_dropped']} "
            f"healthy={metrics['is_healthy']}"
        )
        await asyncio.sleep(interval_secs)


async def main():
    # Initialize sidecar with aggressive timeout
    # emit_timeout_ms=50 means event emission will never take more than 50ms
    sidecar = AuditSidecar(
        spine_url="http://localhost:3000",
        buffer_size=10000,
        overflow_policy="drop_oldest",  # Prefer newer events
        batch_size=100,
        send_interval_ms=100,
        emit_timeout_ms=50,  # Max 50ms to accept event
        on_drop=on_event_dropped,
    )

    try:
        # Start sidecar
        await sidecar.start()
        logger.info("Sidecar started")

        # Run simulation with monitoring
        monitor_task = asyncio.create_task(monitor_sidecar(sidecar))

        try:
            await simulate_scada_operations(sidecar, duration_secs=30)
        finally:
            monitor_task.cancel()

        # Final metrics
        metrics = sidecar.get_metrics()
        logger.info("=== Final Metrics ===")
        logger.info(f"Events received: {metrics['events_received']}")
        logger.info(f"Events sent: {metrics['events_sent']}")
        logger.info(f"Events dropped: {metrics['events_dropped']}")
        logger.info(f"Buffer high watermark: {metrics['buffer_high_watermark']}")

    finally:
        # Graceful shutdown - flush remaining events
        logger.info("Stopping sidecar...")
        await sidecar.stop(flush=True, timeout=10.0)


if __name__ == "__main__":
    asyncio.run(main())
