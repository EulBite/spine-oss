# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Audit Sidecar - Non-blocking audit logging for critical systems.

The sidecar pattern allows applications to log audit events without
blocking on Spine availability. Events are buffered locally and
sent asynchronously.

Features:
- Fire-and-forget interface (emit() has configurable timeout, try_emit() is sync)
- Configurable buffer with overflow handling (drop_oldest, drop_newest, block)
- Background sender with retry logic and exponential backoff
- Metrics for monitoring buffer health

IMPORTANT - Durability Warning:
    The sidecar uses an IN-MEMORY buffer. Events are lost if the process
    crashes before they are sent to Spine. For critical audit requirements:

    1. Use the SpineClient directly with enable_local_wal=True for durability
    2. Or implement application-level persistence before calling emit()
    3. The "accepted" return value means "in RAM buffer", NOT "persisted"

    Future versions may add a persistent buffer option.

Usage:
    sidecar = AuditSidecar("http://spine:3000")
    await sidecar.start()

    # This returns quickly (max emit_timeout_ms), even if Spine is down
    await sidecar.emit(AuditEvent(
        event_type="scada.command",
        payload={"device": "valve_01", "action": "open"}
    ))

    # Truly non-blocking (sync, no await)
    sidecar.try_emit(event)

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
    base_backoff_ms: int = 100  # Initial backoff for exponential retry
    max_backoff_ms: int = 30000  # Maximum backoff (30 seconds)

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

    Overflow Policies:
        - "drop_oldest": Evict oldest events when buffer is full (default)
        - "drop_newest": Reject new events when buffer is full
        - "block": Wait for buffer space (with optional timeout)

    Block Policy Caveats:
        The "block" policy uses a semaphore to enforce buffer bounds. Under
        extreme contention (high event rate + slow/failing sends), semaphore
        permit counts may drift slightly. For production systems requiring
        strict bounded-buffer semantics, consider using asyncio.Queue directly
        or the "drop_oldest" policy which has simpler semantics.

    Timing Guarantees:
        - emit_timeout_ms is "best effort", not hard real-time. Actual wall
          time may exceed the timeout slightly due to asyncio scheduling,
          lock contention, or cancellation handling.
        - try_emit() is synchronous but not 100% atomic (TOCTOU possible
          under concurrent access from multiple threads).

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

    # Valid overflow policies
    VALID_POLICIES = ("drop_oldest", "drop_newest", "block")

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
        # Validate overflow_policy early to fail fast
        if overflow_policy not in self.VALID_POLICIES:
            raise ValueError(
                f"Invalid overflow_policy '{overflow_policy}'. "
                f"Must be one of: {', '.join(self.VALID_POLICIES)}"
            )

        self.config = SidecarConfig(
            buffer_size=buffer_size,
            overflow_policy=overflow_policy,
            batch_size=batch_size,
            send_interval_ms=send_interval_ms,
            emit_timeout_ms=emit_timeout_ms,
        )

        self._spine_url = spine_url
        self._client: SpineClient | None = None
        # No maxlen - we handle overflow manually for accurate drop tracking
        self._buffer: deque = deque()
        self._metrics = SidecarMetrics()
        self._running = False
        self._sender_task: asyncio.Task | None = None
        self._on_drop = on_drop
        self._start_time: float | None = None  # Track when sidecar started

        # Lock to protect buffer operations from race conditions
        self._buffer_lock = asyncio.Lock()

        # Semaphore for bounded buffer when policy is "block"
        self._buffer_semaphore = (
            asyncio.Semaphore(buffer_size) if overflow_policy == "block" else None
        )

        # Event to signal sender loop for immediate flush
        self._flush_event = asyncio.Event()

    async def start(self) -> None:
        """Start the sidecar background sender."""
        if self._running:
            return

        # Sidecar is "best-effort / low-latency" - no local WAL.
        # The in-memory buffer IS the durability trade-off for speed.
        # Users needing durability should use SpineClient directly with enable_local_wal=True.
        self._client = SpineClient(
            self._spine_url,
            enable_circuit_breaker=True,
            enable_local_wal=False,
        )
        await self._client.__aenter__()

        self._running = True
        self._start_time = time.time()
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

        # Check buffer under lock to avoid race with sender loop
        async with self._buffer_lock:
            has_events = len(self._buffer) > 0
            event_count = len(self._buffer)

        if flush and has_events:
            logger.info(f"Flushing {event_count} buffered events...")
            # Signal sender loop for immediate drain
            self._flush_event.set()

            start = time.monotonic()
            while (time.monotonic() - start) < timeout:
                async with self._buffer_lock:
                    if not self._buffer:
                        break
                self._flush_event.set()
                await asyncio.sleep(0.05)

            # Final check under lock
            async with self._buffer_lock:
                remaining = len(self._buffer)
            if remaining > 0:
                logger.warning(f"Flush timeout: {remaining} events still in buffer")

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
            Timing is best-effort: typically returns within emit_timeout_ms,
            but may exceed slightly due to asyncio scheduling, lock contention,
            or cancellation handling. Not a hard real-time guarantee.
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

    def try_emit(self, event: AuditEvent) -> bool:
        """
        Truly non-blocking emit (best-effort, no await).

        This method returns immediately without any async waiting.
        Use this when you absolutely cannot tolerate any latency,
        even the 50ms timeout of emit().

        Args:
            event: AuditEvent to emit

        Returns:
            True if event was accepted into buffer, False if dropped

        Note:
            - Works with "drop_newest" and "drop_oldest" policies
            - NOT COMPATIBLE with "block" policy (always returns False)
            - Best-effort: len check + append is not atomic (TOCTOU possible)
            - Metrics may have minor race conditions under high concurrency

        Thread Safety:
            While deque.append/popleft are thread-safe in CPython (GIL), the
            metrics counters (events_received, events_dropped, etc.) are not
            atomic. Under multi-threaded access, metric values may be slightly
            inaccurate. For accurate metrics, use emit() from async context.
        """
        if not self._running:
            self._metrics.events_dropped += 1
            return False

        # "block" policy is incompatible with sync try_emit
        # (would need semaphore acquire which is async)
        if self.config.overflow_policy == "block":
            self._metrics.events_dropped += 1
            if self._on_drop:
                self._on_drop(event, "block_policy_incompatible")
            return False

        # For "drop_newest": reject new event if buffer full
        if self.config.overflow_policy == "drop_newest":
            if len(self._buffer) >= self.config.buffer_size:
                self._metrics.events_dropped += 1
                if self._on_drop:
                    self._on_drop(event, "buffer_full")
                return False

        # For "drop_oldest": evict oldest if buffer full
        # Note: TOCTOU possible, but worst case is slightly over capacity
        if self.config.overflow_policy == "drop_oldest":
            if len(self._buffer) >= self.config.buffer_size:
                try:
                    dropped = self._buffer.popleft()
                    self._metrics.events_dropped += 1
                    if self._on_drop:
                        self._on_drop(dropped, "buffer_overflow")
                except IndexError:
                    pass  # Concurrent pop, buffer now has space

        # Append event (deque.append is thread-safe in CPython)
        self._buffer.append(event)
        self._metrics.events_received += 1

        # Update high watermark (best-effort, not atomic)
        current_len = len(self._buffer)
        if current_len > self._metrics.buffer_high_watermark:
            self._metrics.buffer_high_watermark = current_len

        return True

    async def _add_to_buffer(self, event: AuditEvent) -> bool:
        """Add event to buffer with overflow handling.

        For "block" policy, waits for buffer slot with optional timeout.
        If block_timeout_ms > 0 and timeout occurs, event is dropped.

        IMPORTANT: Properly handles cancellation to avoid semaphore leaks.

        Returns:
            True if event was added to buffer, False if dropped
        """
        acquired = False
        enqueued = False

        try:
            # For "block" policy, acquire semaphore BEFORE taking lock
            if self.config.overflow_policy == "block":
                try:
                    if self.config.block_timeout_ms > 0:
                        await asyncio.wait_for(
                            self._buffer_semaphore.acquire(),
                            timeout=self.config.block_timeout_ms / 1000
                        )
                    else:
                        await self._buffer_semaphore.acquire()
                    acquired = True
                except asyncio.TimeoutError:
                    self._metrics.events_dropped += 1
                    logger.warning("Block timeout waiting for buffer slot")
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

                # drop_oldest: manually remove oldest to track metrics
                if self.config.overflow_policy == "drop_oldest":
                    if len(self._buffer) >= self.config.buffer_size:
                        dropped = self._buffer.popleft()
                        self._metrics.events_dropped += 1
                        if self._on_drop:
                            self._on_drop(dropped, "buffer_overflow")

                self._buffer.append(event)
                enqueued = True

                # Track high watermark
                if len(self._buffer) > self._metrics.buffer_high_watermark:
                    self._metrics.buffer_high_watermark = len(self._buffer)

                return True

        except asyncio.CancelledError:
            # Propagate cancellation but ensure cleanup happens in finally
            raise
        finally:
            # Release semaphore if acquired but event was NOT enqueued
            # This prevents permit leak on cancellation or early return
            if acquired and not enqueued and self._buffer_semaphore:
                self._buffer_semaphore.release()

    async def _sender_loop(self) -> None:
        """Background loop that sends buffered events to Spine."""
        logger.info("Sender loop started")

        while self._running or self._buffer:
            # Guard against client not initialized (shouldn't happen in normal flow,
            # but protects against edge cases like start() failing mid-way)
            if self._client is None:
                logger.warning("Client not initialized, sleeping...")
                await asyncio.sleep(1.0)
                continue
            try:
                # Wait for flush signal or regular interval
                try:
                    await asyncio.wait_for(
                        self._flush_event.wait(),
                        timeout=self.config.send_interval_ms / 1000
                    )
                    self._flush_event.clear()
                except asyncio.TimeoutError:
                    pass  # Normal interval elapsed

                # Check if buffer is empty (under lock)
                async with self._buffer_lock:
                    buffer_empty = len(self._buffer) == 0

                if buffer_empty:
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

                # Send batch with retries (backoff is handled inside)
                await self._send_batch_with_retry(batch, semaphores_to_release)
                # No external backoff - _send_batch_with_retry already does
                # exponential backoff between attempts

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sender loop error: {e}")
                await asyncio.sleep(1.0)

        logger.info("Sender loop stopped")

    async def _send_batch_with_retry(
        self, batch: list, semaphores_to_release: int
    ) -> bool:
        """Send batch with retry logic. Returns True if successful."""
        last_error = None

        for attempt in range(self.config.max_retries):
            try:
                await self._client.log_batch(batch)
                self._metrics.events_sent += len(batch)
                self._metrics.last_send_time = time.time()
                logger.debug(f"Sent batch of {len(batch)} events")

                # Release semaphores for successfully sent items
                if self._buffer_semaphore:
                    for _ in range(semaphores_to_release):
                        self._buffer_semaphore.release()

                return True

            except Exception as e:
                last_error = e
                self._metrics.last_error = str(e)

                if attempt < self.config.max_retries - 1:
                    # Exponential backoff between retries, capped at max_backoff_ms
                    retry_backoff = min(
                        self.config.base_backoff_ms * (2 ** attempt),
                        self.config.max_backoff_ms
                    )
                    logger.warning(
                        f"Batch send failed (attempt {attempt + 1}/"
                        f"{self.config.max_retries}): {e}, retrying in {retry_backoff}ms"
                    )
                    await asyncio.sleep(retry_backoff / 1000)

        # All retries exhausted - re-queue events
        logger.warning(f"Batch send failed after {self.config.max_retries} attempts: {last_error}")
        self._metrics.events_failed += len(batch)

        # Re-queue events under lock
        requeued = 0
        lost_events = []
        async with self._buffer_lock:
            for event in reversed(batch):
                if len(self._buffer) < self.config.buffer_size:
                    self._buffer.appendleft(event)
                    requeued += 1
                else:
                    lost_events.append(event)

        # Handle lost events
        if lost_events:
            self._metrics.events_dropped += len(lost_events)
            if self._on_drop:
                for event in lost_events:
                    self._on_drop(event, "requeue_buffer_full")
            if self._buffer_semaphore:
                for _ in range(len(lost_events)):
                    self._buffer_semaphore.release()
            logger.warning(f"{len(lost_events)} events lost (buffer full on re-queue)")

        return False

    @property
    def buffer_size(self) -> int:
        """Current number of events in buffer."""
        return len(self._buffer)

    @property
    def is_healthy(self) -> bool:
        """
        True if sidecar is running and appears healthy.

        Health checks:
        - Sidecar is running
        - Buffer is not critically full (< 90% capacity)
        - If buffer has events: recent successful send OR recently started

        Note: This is a best-effort health signal, not a guarantee.
        """
        if not self._running:
            return False

        # Buffer critically full
        if len(self._buffer) >= self.config.buffer_size * 0.9:
            return False

        # If buffer has events, check send health
        if len(self._buffer) > 0:
            now = time.time()

            if self._metrics.last_send_time:
                # Have sent before - check if recent
                time_since_send = now - self._metrics.last_send_time
                if time_since_send > 60.0:
                    return False
            elif self._start_time:
                # Never sent successfully - check if we've been trying long enough
                # Give 30s grace period after start before marking unhealthy
                time_since_start = now - self._start_time
                if time_since_start > 30.0:
                    return False

        return True

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
