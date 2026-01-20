#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Circuit Breaker Demonstration

Shows how the circuit breaker protects your application when Spine
becomes unavailable, and automatically recovers when it's back.

Test Scenarios:
1. Normal operation (Spine up)
2. Spine goes down - circuit opens after 3 failures
3. Requests fail fast while circuit is open
4. Circuit half-opens after recovery timeout
5. Spine recovers - circuit closes

To test:
1. Start Spine: cargo run
2. Run this script
3. Stop Spine during execution to see circuit breaker behavior
"""

import asyncio
import logging

from spine_client import AuditEvent, CircuitBreaker, SpineClient
from spine_client.circuit_breaker import CircuitState

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def log_circuit_state_change(old_state: CircuitState, new_state: CircuitState):
    """Callback for circuit breaker state changes."""
    emoji = {
        CircuitState.CLOSED: "✅",
        CircuitState.OPEN: "🔴",
        CircuitState.HALF_OPEN: "🟡",
    }
    logger.info(
        f"{emoji.get(old_state, '?')} → {emoji.get(new_state, '?')} "
        f"Circuit breaker: {old_state.value} → {new_state.value}"
    )


async def standalone_circuit_breaker_demo():
    """Demonstrate circuit breaker as standalone component."""
    logger.info("=== Standalone Circuit Breaker Demo ===")

    breaker = CircuitBreaker(
        failure_threshold=3,
        recovery_timeout=10.0,
        success_threshold=2,
        call_timeout=2.0,
        on_state_change=log_circuit_state_change,
    )

    async def unreliable_service(should_fail: bool = False):
        """Simulates an unreliable external service."""
        if should_fail:
            raise ConnectionError("Service unavailable")
        await asyncio.sleep(0.1)
        return "success"

    # Test 1: Successful calls
    logger.info("\n--- Test 1: Successful calls ---")
    for i in range(3):
        try:
            result = await breaker.execute(unreliable_service, False)
            logger.info(f"Call {i+1}: {result} (state: {breaker.state.value})")
        except Exception as e:
            logger.error(f"Call {i+1} failed: {e}")

    # Test 2: Failing calls - should trip circuit
    logger.info("\n--- Test 2: Failures (circuit should open) ---")
    for i in range(5):
        try:
            await breaker.execute(unreliable_service, True)
            logger.info(f"Call {i+1}: success")
        except Exception as e:
            logger.warning(f"Call {i+1}: {type(e).__name__} - {e} (state: {breaker.state.value})")

    # Test 3: Calls while circuit is open
    logger.info("\n--- Test 3: Calls while circuit open (should fail fast) ---")
    for i in range(3):
        try:
            await breaker.execute(unreliable_service, False)
            logger.info(f"Call {i+1}: success")
        except Exception as e:
            logger.warning(f"Call {i+1}: {type(e).__name__} (state: {breaker.state.value})")

    # Test 4: Wait for recovery timeout
    logger.info("\n--- Test 4: Waiting for recovery timeout... ---")
    await asyncio.sleep(11)

    # Test 5: Recovery test
    logger.info("\n--- Test 5: Recovery (half-open then closed) ---")
    for i in range(3):
        try:
            result = await breaker.execute(unreliable_service, False)
            logger.info(f"Call {i+1}: {result} (state: {breaker.state.value})")
        except Exception as e:
            logger.warning(f"Call {i+1}: {type(e).__name__} (state: {breaker.state.value})")

    logger.info(f"\nFinal stats: {breaker.get_stats()}")


async def client_with_circuit_breaker_demo():
    """Demonstrate circuit breaker integrated with Spine client."""
    logger.info("\n=== Client Circuit Breaker Demo ===")
    logger.info("This will send events to Spine and show circuit breaker behavior")
    logger.info("Stop/start Spine during execution to test failover\n")

    async with SpineClient(
        base_url="http://localhost:3000",
        timeout_ms=2000,
        enable_circuit_breaker=True,
        enable_local_wal=True,
        local_wal_dir="./spine_fallback",
        circuit_failure_threshold=3,
        circuit_recovery_timeout=15.0,
    ) as client:

        for i in range(30):
            try:
                state = await client.get_circuit_state()
                state_indicator = {
                    CircuitState.CLOSED: "✅",
                    CircuitState.OPEN: "🔴",
                    CircuitState.HALF_OPEN: "🟡",
                }.get(state, "?")

                response = await client.log(AuditEvent(
                    event_type="circuit_breaker.test",
                    payload={"iteration": i, "message": f"Test event {i}"}
                ))

                if response.payload_hash.startswith("pending:"):
                    logger.info(
                        f"{state_indicator} Event {i}: buffered locally (circuit: {state.value})"
                    )
                else:
                    logger.info(
                        f"{state_indicator} Event {i}: sent to Spine seq={response.sequence}"
                    )

            except Exception as e:
                logger.error(f"❌ Event {i} failed: {e}")

            await asyncio.sleep(1)

        # Show final stats
        stats = await client.get_stats()
        logger.info("\n=== Final Statistics ===")
        if stats.get("circuit_breaker"):
            cb = stats["circuit_breaker"]
            logger.info(f"Circuit Breaker State: {cb['state']}")
            logger.info(f"Failure Count: {cb['failure_count']}")
        if stats.get("local_wal"):
            wal = stats["local_wal"]
            logger.info(f"Local WAL Entries: {wal.get('total_entries', 0)}")
            logger.info(f"Unsynced Entries: {wal.get('unsynced_entries', 0)}")


async def main():
    # Run standalone demo first
    await standalone_circuit_breaker_demo()

    # Then run client demo (requires Spine to be running)
    logger.info("\n" + "="*60)
    logger.info("Press Enter to start client demo (or Ctrl+C to skip)")
    logger.info("Make sure Spine is running: cargo run")
    logger.info("="*60)

    try:
        await asyncio.sleep(2)
        await client_with_circuit_breaker_demo()
    except KeyboardInterrupt:
        logger.info("Skipped client demo")


if __name__ == "__main__":
    asyncio.run(main())
