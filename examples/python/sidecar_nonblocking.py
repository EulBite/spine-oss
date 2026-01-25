#!/usr/bin/env python3
"""
Spine Sidecar Example - Non-blocking audit logging for high-throughput systems.

The AuditSidecar pattern is designed for:
- Low-latency systems where audit logging must not block
- High-throughput scenarios (1000s of events/second)
- Best-effort logging where occasional drops are acceptable

IMPORTANT: The sidecar uses an IN-MEMORY buffer. Events are lost if the process
crashes before they're sent to Spine. For critical audit requirements, use the
WAL directly (see basic_wal_async.py).

Requirements:
    - A running Spine server (set SPINE_URL or modify the URL below)

Run:
    SPINE_URL=http://localhost:3000 python sidecar_nonblocking.py
"""

import asyncio
import os
import time

from spine_client import AuditSidecar, AuditEvent, Severity, Actor


# Spine server URL (set via environment or default)
SPINE_URL = os.environ.get("SPINE_URL", "http://localhost:3000")


def on_event_dropped(event: AuditEvent, reason: str) -> None:
    """Called when an event is dropped (buffer full, etc.)."""
    print(f"  DROPPED: {event.event_type} - {reason}")


async def main():
    print(f"Connecting to Spine server at {SPINE_URL}")
    print()

    # Initialize sidecar with overflow handling
    sidecar = AuditSidecar(
        spine_url=SPINE_URL,
        buffer_size=1000,           # Max events in memory
        overflow_policy="drop_oldest",  # What to do when buffer is full
        emit_timeout_ms=10,         # Max time emit() will wait
        batch_size=50,              # Events per batch to server
        send_interval_ms=100,       # How often to flush to server
        on_drop=on_event_dropped,   # Callback when events are dropped
    )

    # Start background sender
    await sidecar.start()
    print("Sidecar started. Sending events...")
    print()

    try:
        # Simulate high-throughput event logging
        for i in range(100):
            # emit() - async, bounded wait time
            accepted = await sidecar.emit(AuditEvent(
                event_type="sensor.reading",
                severity=Severity.DEBUG,
                actor=Actor(id=f"sensor_{i % 10}"),
                payload={
                    "reading_id": i,
                    "value_milliunits": i * 100,  # Use int, not float!
                    "unit": "celsius",
                }
            ))

            if not accepted:
                print(f"  Event {i} not accepted (buffer full)")

            # Small delay to simulate realistic throughput
            if i % 20 == 0:
                await asyncio.sleep(0.01)

        # You can also use try_emit() for truly synchronous, non-blocking emit
        # This is useful in sync code or when you can't await
        sync_accepted = sidecar.try_emit(AuditEvent(
            event_type="system.sync_event",
            payload={"note": "This was logged with try_emit()"}
        ))
        print(f"try_emit() returned: {sync_accepted}")

        # Wait a bit for events to be sent
        print()
        print("Waiting for events to be sent...")
        await asyncio.sleep(1)

        # Check metrics
        metrics = sidecar.get_metrics()
        print()
        print("Sidecar metrics:")
        print(f"  Events received:  {metrics['events_received']}")
        print(f"  Events sent:      {metrics['events_sent']}")
        print(f"  Events dropped:   {metrics['events_dropped']}")
        print(f"  Buffer current:   {metrics['buffer_current']}")
        print(f"  Buffer capacity:  {metrics['buffer_capacity']}")
        print(f"  Is healthy:       {metrics['is_healthy']}")

        if metrics.get("last_error"):
            print(f"  Last error:       {metrics['last_error']}")

    finally:
        # Graceful shutdown - flush remaining events
        print()
        print("Stopping sidecar (flushing remaining events)...")
        await sidecar.stop(flush=True, timeout=10.0)
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
