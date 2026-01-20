# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Audit Sidecar - Non-blocking audit logging for critical systems.

The sidecar pattern allows applications to log audit events without
blocking on Spine availability. Events are buffered locally and
sent asynchronously.

Features:
- Fire-and-forget interface (never blocks caller)
- Configurable buffer with overflow handling
- Background sender with retry logic
- Metrics for monitoring buffer health

Usage:
    sidecar = AuditSidecar("http://spine:3000")
    await sidecar.start()

    # This never blocks, even if Spine is down
    await sidecar.emit(AuditEvent(
        event_type="scada.command",
        payload={"device": "valve_01", "action": "open"}
    ))

    # Graceful shutdown
    await sidecar.stop()
"""

import asyncio
import logging
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from .client import SpineClient
from .events import AuditEvent

logger = logging.getLogger(__name__)


@dataclass
class SidecarConfig:
    """Sidecar configuration."""
    # Buffer settings
    buffer_size: int = 10000
    overflow_policy: str = "drop_oldest"  # drop_oldest, drop_newest, block

    # Sender settings
    batch_size: int = 100
    send_interval_ms: int = 100
    max_retries: int = 3

    # Timeouts
    emit_timeout_ms: int = 50  # Max time to wait when emitting
    # Max time to wait for buffer slot when policy is "block" (0 = infinite)
    block_timeout_ms: int = 5000


@dataclass
class SidecarMetrics:
    """Sidecar runtime metrics."""
    events_received: int = 0
    events_sent: int = 0
    events_dropped: int = 0
    events_failed: int = 0
    buffer_high_watermark: int = 0
    last_send_time: float | None = None
    last_error: str | None = None

    def to_dict(self) -> dict:
        return {
            "events_received": self.events_received,
            "events_sent": self.events_sent,
            "events_dropped": self.events_dropped,
            "events_failed": self.events_failed,
            "buffer_high_watermark": self.buffer_high_watermark,
            "last_send_time": self.last_send_time,
            "last_error": self.last_error,
        }


class AuditSidecar:
    """
    Non-blocking audit event sidecar.

    Designed for integration with critical systems where audit logging
    must never impact application latency or availability.

    The sidecar maintains an in-memory buffer and sends events to Spine
    in the background. If the buffer fills up, the configured overflow
    policy determines behavior.

    Example:
        # Initialize
        sidecar = AuditSidecar(
            spine_url="http://spine:3000",
            buffer_size=10000,
            emit_timeout_ms=50,  # Max 50ms to accept event
        )

        # Start background sender
        await sidecar.start()

        # In your application code (never blocks)
        await sidecar.emit(event)

        # On shutdown
        await sidecar.stop(flush=True)
    """

    def __init__(
        self,
        spine_url: str,
        buffer_size: int = 10000,
        overflow_policy: str = "drop_oldest",
        batch_size: int = 100,
        send_interval_ms: int = 100,
        emit_timeout_ms: int = 50,
        on_drop: Callable[[AuditEvent, str], None] | None = None,
    ):
        self.config = SidecarConfig(
            buffer_size=buffer_size,
            overflow_policy=overflow_policy,
            batch_size=batch_size,
            send_interval_ms=send_interval_ms,
            emit_timeout_ms=emit_timeout_ms,
        )

        self._spine_url = spine_url
        self._client: SpineClient | None = None
        maxlen = buffer_size if overflow_policy == "drop_oldest" else None
        self._buffer: deque = deque(maxlen=maxlen)
        self._metrics = SidecarMetrics()
        self._running = False
        self._sender_task: asyncio.Task | None = None
        self._on_drop = on_drop

        # Lock to protect buffer operations from race conditions
        self._buffer_lock = asyncio.Lock()

        # Semaphore for bounded buffer when policy is "block"
        self._buffer_semaphore = (
            asyncio.Semaphore(buffer_size) if overflow_policy == "block" else None
        )

    async def start(self) -> None:
        """Start the sidecar background sender."""
        if self._running:
            return

        self._client = SpineClient(
            self._spine_url,
            enable_circuit_breaker=True,
            enable_local_wal=True,
        )
        await self._client.__aenter__()

        self._running = True
        self._sender_task = asyncio.create_task(self._sender_loop())
        logger.info(f"AuditSidecar started: buffer_size={self.config.buffer_size}")

    async def stop(self, flush: bool = True, timeout: float = 30.0) -> None:
        """
        Stop the sidecar.

        Args:
            flush: If True, attempt to send remaining buffered events
            timeout: Maximum time to wait for flush
        """
        self._running = False

        if flush and self._buffer:
            logger.info(f"Flushing {len(self._buffer)} buffered events...")
            start = time.monotonic()
            while self._buffer and (time.monotonic() - start) < timeout:
                await asyncio.sleep(0.1)

        if self._sender_task:
            self._sender_task.cancel()
            try:
                await self._sender_task
            except asyncio.CancelledError:
                pass

        if self._client:
            await self._client.close()

        logger.info("AuditSidecar stopped")

    async def emit(self, event: AuditEvent) -> bool:
        """
        Emit an audit event (non-blocking).

        This method is designed to return quickly regardless of Spine
        availability. Events are buffered and sent asynchronously.

        Args:
            event: AuditEvent to emit

        Returns:
            True if event was accepted, False if dropped

        Note:
            With emit_timeout_ms=50, this call will return within 50ms
            even under heavy load or buffer pressure.
        """
        if not self._running:
            logger.warning("Sidecar not running, event dropped")
            self._metrics.events_dropped += 1
            return False

        try:
            # Apply timeout to buffer operation
            accepted = await asyncio.wait_for(
                self._add_to_buffer(event),
                timeout=self.config.emit_timeout_ms / 1000
            )
            if accepted:
                self._metrics.events_received += 1
            return accepted

        except asyncio.TimeoutError:
            self._metrics.events_dropped += 1
            logger.warning("Emit timeout, event dropped")
            if self._on_drop:
                self._on_drop(event, "timeout")
            return False

    async def _add_to_buffer(self, event: AuditEvent) -> bool:
        """Add event to buffer with overflow handling.

        For "block" policy, waits for buffer slot with optional timeout.
        If block_timeout_ms > 0 and timeout occurs, event is dropped.

        Returns:
            True if event was added to buffer, False if dropped
        """
        # For "block" policy, acquire semaphore BEFORE taking lock to avoid deadlock
        if self.config.overflow_policy == "block":
            try:
                if self.config.block_timeout_ms > 0:
                    await asyncio.wait_for(
                        self._buffer_semaphore.acquire(),
                        timeout=self.config.block_timeout_ms / 1000
                    )
                else:
                    await self._buffer_semaphore.acquire()
            except asyncio.TimeoutError:
                self._metrics.events_dropped += 1
                logger.warning("Block timeout waiting for buffer slot, event dropped")
                if self._on_drop:
                    self._on_drop(event, "block_timeout")
                return False

        async with self._buffer_lock:
            if self.config.overflow_policy == "drop_newest":
                if len(self._buffer) >= self.config.buffer_size:
                    self._metrics.events_dropped += 1
                    if self._on_drop:
                        self._on_drop(event, "buffer_full")
                    return False

            # drop_oldest is handled by deque maxlen, but we track the drop
            is_drop_oldest = self.config.overflow_policy == "drop_oldest"
            if is_drop_oldest and len(self._buffer) >= self.config.buffer_size:
                dropped = self._buffer.popleft()
                self._metrics.events_dropped += 1
                if self._on_drop:
                    self._on_drop(dropped, "buffer_overflow")

            self._buffer.append(event)

            # Track high watermark
            if len(self._buffer) > self._metrics.buffer_high_watermark:
                self._metrics.buffer_high_watermark = len(self._buffer)

            return True

    async def _sender_loop(self) -> None:
        """Background loop that sends buffered events to Spine."""
        logger.info("Sender loop started")

        while self._running or self._buffer:
            try:
                # Check if buffer is empty (under lock)
                async with self._buffer_lock:
                    buffer_empty = len(self._buffer) == 0

                if buffer_empty:
                    await asyncio.sleep(self.config.send_interval_ms / 1000)
                    continue

                # Collect batch under lock
                batch = []
                semaphores_to_release = 0
                async with self._buffer_lock:
                    while self._buffer and len(batch) < self.config.batch_size:
                        batch.append(self._buffer.popleft())
                        if self._buffer_semaphore:
                            semaphores_to_release += 1

                if not batch:
                    continue

                # Send batch
                send_success = False
                try:
                    await self._client.log_batch(batch)
                    self._metrics.events_sent += len(batch)
                    self._metrics.last_send_time = time.time()
                    logger.debug(f"Sent batch of {len(batch)} events")
                    send_success = True

                except Exception as e:
                    # On failure, put events back in buffer (at front)
                    self._metrics.events_failed += len(batch)
                    self._metrics.last_error = str(e)
                    logger.warning(f"Batch send failed: {e}")

                    # Re-queue events under lock (they'll go to local WAL via client)
                    # Track how many we successfully re-queued and which were lost
                    requeued = 0
                    lost_events = []
                    async with self._buffer_lock:
                        for event in reversed(batch):
                            if len(self._buffer) < self.config.buffer_size:
                                self._buffer.appendleft(event)
                                requeued += 1
                            else:
                                # Event couldn't be re-queued, track it
                                lost_events.append(event)

                    # Handle lost events
                    events_lost = len(lost_events)
                    if events_lost > 0:
                        # Track lost events in metrics
                        self._metrics.events_dropped += events_lost
                        # Call on_drop callback for each lost event
                        if self._on_drop:
                            for event in lost_events:
                                self._on_drop(event, "requeue_buffer_full")
                        if self._buffer_semaphore:
                            for _ in range(events_lost):
                                self._buffer_semaphore.release()
                        logger.warning(f"{events_lost} events lost (buffer full on re-queue)")

                    # Back off on error
                    await asyncio.sleep(1.0)

                finally:
                    # Release semaphores for successfully sent items
                    # (they're no longer in buffer, so their slots are free)
                    if self._buffer_semaphore and send_success:
                        for _ in range(semaphores_to_release):
                            self._buffer_semaphore.release()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sender loop error: {e}")
                await asyncio.sleep(1.0)

        logger.info("Sender loop stopped")

    @property
    def buffer_size(self) -> int:
        """Current number of events in buffer."""
        return len(self._buffer)

    @property
    def is_healthy(self) -> bool:
        """True if sidecar is running and buffer is not critically full."""
        if not self._running:
            return False
        return len(self._buffer) < self.config.buffer_size * 0.9

    def get_metrics(self) -> dict:
        """Get sidecar metrics."""
        return {
            **self._metrics.to_dict(),
            "buffer_current": len(self._buffer),
            "buffer_capacity": self.config.buffer_size,
            "buffer_utilization": len(self._buffer) / self.config.buffer_size,
            "is_healthy": self.is_healthy,
            "is_running": self._running,
        }


class ShadowModeSidecar(AuditSidecar):
    """
    Shadow mode sidecar that duplicates events from existing logging.

    Use this to run Spine in parallel with your existing SIEM without
    any changes to your application code.

    Example:
        shadow = ShadowModeSidecar(
            spine_url="http://spine:3000",
            source_name="splunk-forwarder"
        )
        await shadow.start()

        # Forward events from your existing log stream
        for log_line in existing_log_stream:
            await shadow.forward_log(log_line)
    """

    def __init__(
        self,
        spine_url: str,
        source_name: str = "shadow-forwarder",
        **kwargs
    ):
        super().__init__(spine_url, **kwargs)
        self._source_name = source_name

    async def forward_log(
        self,
        log_data: dict,
        event_type: str = "shadow.forwarded",
        severity: str = "info",
    ) -> bool:
        """
        Forward a log entry from existing logging system.

        Args:
            log_data: Original log data (dict or parsed log line)
            event_type: Event type classification
            severity: Severity level

        Returns:
            True if forwarded successfully
        """
        from .events import Severity

        event = AuditEvent(
            event_type=event_type,
            source=self._source_name,
            severity=Severity(severity) if isinstance(severity, str) else severity,
            payload={
                "original_log": log_data,
                "forwarded_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        return await self.emit(event)
