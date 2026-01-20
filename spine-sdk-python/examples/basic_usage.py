#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Basic Spine SDK Usage Example

Demonstrates:
- Simple event logging
- Fire-and-forget mode
- Batch logging
- Circuit breaker behavior
- API key authentication
"""

import asyncio
import logging

from spine_client import Actor, AuditEvent, Resource, SpineClient
from spine_client.events import Severity

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)


async def main():
    # Initialize client
    # For authenticated Spine servers, add api_key parameter:
    #   api_key="your-secret-api-key"
    async with SpineClient(
        base_url="http://localhost:3000",
        timeout_ms=5000,
        enable_circuit_breaker=True,
        enable_local_wal=True,
        local_wal_dir="./spine_fallback",
        # api_key="your-secret-api-key",  # Uncomment for authenticated servers
    ) as client:

        # Check if Spine is healthy
        if await client.is_healthy():
            logger.info("Spine is healthy!")
        else:
            logger.warning("Spine is not reachable - events will be buffered locally")

        # Example 1: Simple event logging
        logger.info("=== Example 1: Simple Event ===")
        response = await client.log(AuditEvent(
            event_type="auth.login.success",
            payload={
                "session_id": "sess_abc123",
                "method": "password",
            }
        ))
        logger.info(f"Event logged: sequence={response.sequence}")

        # Example 2: Full event with actor and resource
        logger.info("=== Example 2: Full Event ===")
        response = await client.log(AuditEvent(
            event_type="data.export",
            severity=Severity.HIGH,
            actor=Actor(
                id="user_42",
                email="analyst@company.com",
                role="data_analyst",
                ip_address="192.168.1.100",
            ),
            resource=Resource(
                type="report",
                id="report_2025_q1",
                name="Q1 Financial Report",
            ),
            payload={
                "format": "xlsx",
                "rows_exported": 15000,
                "filters_applied": ["date > 2025-01-01"],
            },
            source="reporting-service",
        ))
        hash_preview = response.payload_hash[:16]
        logger.info(f"Event logged: sequence={response.sequence}, hash={hash_preview}...")

        # Example 3: Critical security event
        logger.info("=== Example 3: Critical Event ===")
        response = await client.log(AuditEvent(
            event_type="auth.privilege_escalation",
            severity=Severity.CRITICAL,
            actor=Actor(id="user_99", role="user"),
            resource=Resource(type="role", id="admin"),
            payload={
                "previous_role": "user",
                "new_role": "admin",
                "escalation_method": "direct_assignment",
                "approved_by": None,  # Suspicious!
            },
        ))
        logger.info(f"Critical event logged: sequence={response.sequence}")

        # Example 4: Fire-and-forget (non-blocking)
        logger.info("=== Example 4: Fire-and-Forget ===")
        for i in range(5):
            client.log_async(AuditEvent(
                event_type="api.request",
                payload={"endpoint": f"/api/v1/resource/{i}", "status": 200},
            ))
        logger.info("5 events queued asynchronously")

        # Example 5: Batch logging
        logger.info("=== Example 5: Batch Logging ===")
        events = [
            AuditEvent(
                event_type="bulk.operation",
                payload={"item_id": f"item_{i}", "action": "update"},
            )
            for i in range(10)
        ]
        responses = await client.log_batch(events)
        logger.info(f"Batch logged: {len(responses)} events")

        # Get client statistics
        stats = await client.get_stats()
        logger.info(f"Client stats: circuit_breaker={stats['circuit_breaker']}")

        # Wait a moment for async events to complete
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
