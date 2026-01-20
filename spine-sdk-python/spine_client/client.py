# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Spine Client - Main API client with circuit breaker and fallback support.
"""

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import urljoin

import aiohttp

from .circuit_breaker import CircuitBreaker, CircuitBreakerError, CircuitState
from .crypto import SigningKey
from .events import AuditEvent
from .wal import WAL, WALConfig

logger = logging.getLogger(__name__)


@dataclass
class SpineResponse:
    """Response from Spine API."""
    sequence: int
    timestamp_ns: int
    payload_hash: str
    prev_hash: str


@dataclass
class ClientConfig:
    """Spine client configuration."""
    # API settings
    base_url: str
    timeout_ms: int = 5000
    max_retries: int = 3

    # Authentication settings
    api_key: str | None = None  # API key for Bearer token auth
    api_key_header: str = "Authorization"  # Header name for API key

    # Circuit breaker settings
    circuit_failure_threshold: int = 3
    circuit_recovery_timeout: float = 30.0
    circuit_success_threshold: int = 2

    # WAL fallback settings (cryptographically signed, CLI-verifiable)
    enable_wal_fallback: bool = True
    wal_dir: str = "./spine_fallback_wal"
    signing_key: SigningKey | None = None  # Auto-generated if not provided

    # Batching settings
    batch_size: int = 100
    batch_timeout_ms: int = 1000


class SpineClient:
    """
    Async Spine client with circuit breaker and local fallback.

    Features:
    - Automatic circuit breaker for fault tolerance
    - Local WAL fallback when Spine is unreachable
    - Fire-and-forget mode for non-blocking operations
    - Batch support for high throughput
    - Connection pooling via aiohttp

    Usage:
        async with SpineClient("http://spine:3000") as client:
            # Simple logging
            await client.log(AuditEvent(
                event_type="auth.login",
                payload={"user_id": "123"}
            ))

            # Fire-and-forget (non-blocking)
            client.log_async(event)

            # Batch logging
            await client.log_batch([event1, event2, event3])

            # Check health
            if await client.is_healthy():
                print("Spine is up")
    """

    def __init__(
        self,
        base_url: str,
        timeout_ms: int = 5000,
        enable_circuit_breaker: bool = True,
        enable_wal_fallback: bool = True,
        wal_dir: str = "./spine_fallback_wal",
        signing_key: SigningKey | None = None,
        **kwargs
    ):
        self.config = ClientConfig(
            base_url=base_url.rstrip("/"),
            timeout_ms=timeout_ms,
            enable_wal_fallback=enable_wal_fallback,
            wal_dir=wal_dir,
            signing_key=signing_key,
            **{k: v for k, v in kwargs.items() if hasattr(ClientConfig, k)}
        )

        self._session: aiohttp.ClientSession | None = None
        self._circuit_breaker: CircuitBreaker | None = None
        self._wal: WAL | None = None
        self._signing_key: SigningKey | None = signing_key
        self._background_tasks: list[asyncio.Task] = []

        # Circuit breaker pattern: fail fast after N consecutive errors.
        # Why this matters for audit logging:
        # - Without it: each log() call waits for timeout (5s default) → app freezes
        # - With it: after 3 failures, immediately fall back to WAL → no latency spike
        # - HALF_OPEN state probes recovery without risking app performance
        if enable_circuit_breaker:
            self._circuit_breaker = CircuitBreaker(
                failure_threshold=self.config.circuit_failure_threshold,
                recovery_timeout=self.config.circuit_recovery_timeout,
                success_threshold=self.config.circuit_success_threshold,
                call_timeout=self.config.timeout_ms / 1000,
                on_state_change=self._on_circuit_state_change,
            )

        # WAL fallback uses the same crypto as standalone WAL (Ed25519 + BLAKE3)
        # This ensures offline events are CLI-verifiable, not just "best-effort buffer"
        self._enable_wal_fallback = enable_wal_fallback
        self._wal_dir = wal_dir

    def _on_circuit_state_change(self, old: CircuitState, new: CircuitState) -> None:
        """Handle circuit breaker state changes."""
        if new == CircuitState.OPEN:
            logger.warning("Circuit breaker OPEN - switching to WAL fallback")
        elif new == CircuitState.CLOSED:
            logger.info("Circuit breaker CLOSED - Spine connection restored")
            # Trigger background sync of buffered events
            if self._wal:
                task = asyncio.create_task(self._sync_wal())
                self._background_tasks.append(task)

                def _remove_sync_task(t: asyncio.Task) -> None:
                    try:
                        self._background_tasks.remove(t)
                    except ValueError:
                        pass

                task.add_done_callback(_remove_sync_task)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.config.timeout_ms / 1000,
                connect=2.0,
            )
            # Build headers with optional API key authentication
            headers = {"Accept": "application/json"}
            if self.config.api_key:
                # Only use "Bearer" prefix for standard Authorization header
                # Custom headers like X-API-Key should not have Bearer prefix
                if self.config.api_key_header.lower() == "authorization":
                    headers[self.config.api_key_header] = f"Bearer {self.config.api_key}"
                else:
                    headers[self.config.api_key_header] = self.config.api_key

            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
            )
        return self._session

    async def __aenter__(self):
        """Context manager entry."""
        await self._get_session()

        # Initialize WAL fallback with signing key (auto-generate if needed)
        if self._enable_wal_fallback:
            if self._signing_key is None:
                self._signing_key = SigningKey.generate()
                logger.info(f"Auto-generated signing key: {self._signing_key.key_id}")

            wal_config = WALConfig(data_dir=self._wal_dir)
            self._wal = WAL(self._signing_key, wal_config, namespace="spine-client-fallback")
            await self._wal.initialize()

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()

        # Close session
        if self._session and not self._session.closed:
            await self._session.close()

        return False

    async def close(self) -> None:
        """Explicitly close the client."""
        await self.__aexit__(None, None, None)

    async def _send_request(
        self,
        method: str,
        path: str,
        json_data: dict | None = None,
        extra_headers: dict | None = None,
    ) -> dict:
        """Send HTTP request to Spine."""
        session = await self._get_session()
        url = urljoin(self.config.base_url, path)

        async with session.request(method, url, json=json_data, headers=extra_headers) as response:
            if response.status >= 400:
                text = await response.text()
                raise aiohttp.ClientResponseError(
                    response.request_info,
                    response.history,
                    status=response.status,
                    message=text,
                )
            return await response.json()

    async def log(self, event: AuditEvent) -> SpineResponse:
        """
        Log an audit event to Spine.

        Uses circuit breaker if enabled. Falls back to cryptographically
        signed WAL if Spine is unreachable (verifiable with spine-cli).

        Args:
            event: AuditEvent to log

        Returns:
            SpineResponse with sequence number and hashes

        Raises:
            Exception: If both Spine and WAL fallback fail
        """
        event_dict = event.to_dict()
        extra_headers = {}
        if event.idempotency_key:
            extra_headers["X-Idempotency-Key"] = event.idempotency_key

        try:
            if self._circuit_breaker:
                result = await self._circuit_breaker.execute(
                    self._send_request,
                    "POST",
                    "/api/v1/events",
                    event_dict,
                    extra_headers if extra_headers else None,
                )
            else:
                result = await self._send_request(
                    "POST",
                    "/api/v1/events",
                    event_dict,
                    extra_headers if extra_headers else None,
                )

            return SpineResponse(
                sequence=result["sequence"],
                timestamp_ns=result["timestamp_ns"],
                payload_hash=result["payload_hash"],
                prev_hash=result["prev_hash"],
            )

        except (CircuitBreakerError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Spine unavailable: {e}")

            # Fallback to signed WAL - maintains cryptographic integrity even offline.
            # Unlike plain buffering, this WAL is CLI-verifiable:
            # - Ed25519 signatures prove event authenticity
            # - BLAKE3 hash chain proves ordering/completeness
            # - spine-cli verify works on these offline events
            if self._wal:
                record = await self._wal.append(event_dict)
                logger.info(f"Event buffered to signed WAL: seq={record.seq}")
                # Convert ISO timestamp to nanoseconds for SpineResponse
                from .crypto import timestamp_to_nanos
                timestamp_ns = timestamp_to_nanos(record.ts_client)
                return SpineResponse(
                    sequence=record.seq,
                    timestamp_ns=timestamp_ns,
                    payload_hash=record.payload_hash,
                    prev_hash=record.prev_hash,
                )

            raise

    def log_async(self, event: AuditEvent) -> None:
        """
        Fire-and-forget event logging.

        The event is sent asynchronously without waiting for response.
        Errors are logged but not raised.

        Args:
            event: AuditEvent to log
        """
        task = asyncio.create_task(self._log_async_impl(event))
        self._background_tasks.append(task)

        def _remove_task(t: asyncio.Task) -> None:
            """Safely remove task from tracking list."""
            try:
                self._background_tasks.remove(t)
            except ValueError:
                pass  # Task already removed (e.g., during shutdown)

        task.add_done_callback(_remove_task)

    async def _log_async_impl(self, event: AuditEvent) -> None:
        """Implementation of async logging."""
        try:
            await self.log(event)
        except Exception as e:
            logger.error(f"Async log failed: {e}")

    async def log_batch(self, events: list[AuditEvent]) -> list[SpineResponse]:
        """
        Log multiple events in a batch.

        Args:
            events: List of AuditEvents to log

        Returns:
            List of SpineResponses
        """
        events_data = [e.to_dict() for e in events]
        payload = {"events": events_data}

        try:
            if self._circuit_breaker:
                result = await self._circuit_breaker.execute(
                    self._send_request,
                    "POST",
                    "/api/v1/events/batch",
                    payload,
                )
            else:
                result = await self._send_request("POST", "/api/v1/events/batch", payload)

            return [
                SpineResponse(
                    sequence=r["sequence"],
                    timestamp_ns=r["timestamp_ns"],
                    payload_hash=r["payload_hash"],
                    prev_hash=r["prev_hash"],
                )
                for r in result.get("events", [])
            ]

        except (CircuitBreakerError, aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"Batch send failed: {e}")

            # Fallback: store each event in signed WAL (CLI-verifiable)
            if self._wal:
                from .crypto import timestamp_to_nanos
                responses = []
                for event_dict in events_data:
                    record = await self._wal.append(event_dict)
                    timestamp_ns = timestamp_to_nanos(record.ts_client)
                    responses.append(SpineResponse(
                        sequence=record.seq,
                        timestamp_ns=timestamp_ns,
                        payload_hash=record.payload_hash,
                        prev_hash=record.prev_hash,
                    ))
                return responses

            raise

    async def is_healthy(self) -> bool:
        """
        Check if Spine is healthy and reachable.

        Returns:
            True if Spine health check passes
        """
        try:
            session = await self._get_session()
            url = urljoin(self.config.base_url, "/health")
            async with session.get(url) as response:
                return response.status == 200
        except Exception:
            return False

    async def get_circuit_state(self) -> CircuitState | None:
        """Get current circuit breaker state."""
        if self._circuit_breaker:
            return self._circuit_breaker.state
        return None

    async def _sync_wal(self) -> None:
        """Background task to sync WAL to Spine."""
        if not self._wal:
            return

        logger.info("Starting WAL sync to Spine")

        # Get unsynced records and send them to Spine
        unsynced = await self._wal.unsynced_records(limit=100)
        synced_count = 0
        for record in unsynced:
            try:
                result = await self._send_request("POST", "/api/v1/events", record.payload)
                # Attach receipt if server provides one
                if "receipt" in result:
                    from .types import Receipt
                    receipt = Receipt(
                        server_ts=result["receipt"].get("server_ts", ""),
                        server_seq=result["receipt"].get("server_seq", 0),
                        server_sig=result["receipt"].get("server_sig", ""),
                    )
                    await self._wal.attach_receipt(record.event_id, receipt)
                synced_count += 1
            except Exception as e:
                logger.warning(f"Failed to sync event {record.event_id}: {e}")
                break  # Stop on first failure to maintain order

        logger.info(f"WAL sync complete: {synced_count}/{len(unsynced)} events synced")

    async def get_stats(self) -> dict:
        """Get client statistics."""
        stats = {
            "base_url": self.config.base_url,
            "circuit_breaker": None,
            "wal": None,
        }

        if self._circuit_breaker:
            stats["circuit_breaker"] = self._circuit_breaker.get_stats()

        if self._wal:
            stats["wal"] = await self._wal.get_stats()

        return stats
