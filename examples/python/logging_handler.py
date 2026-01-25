#!/usr/bin/env python3
"""
Python Logging Handler for Spine - Bridge stdlib logging to signed audit logs.

This example demonstrates:
- Custom logging.Handler that writes to Spine WAL
- Mapping Python log levels to Spine Severity
- Rate limiting to prevent log floods
- Sampling for high-volume debug logs
- Thread-safe async bridging

Use cases:
- Retrofit existing applications with audit logging
- Capture security-relevant logs (auth failures, access denials)
- Compliance logging without changing application code

Run:
    python logging_handler.py

Verify:
    spine-cli verify --wal ./audit_log
"""

import asyncio
import logging
import os
import queue
import threading
import time
from pathlib import Path

from spine_client import WAL, WALConfig, SigningKey, AuditEvent, Severity


KEY_FILE = Path(__file__).parent / "signing.key"
WAL_DIR = Path(__file__).parent / "audit_log"


class SpineHandler(logging.Handler):
    """
    Logging handler that writes to Spine WAL.

    Features:
    - Async-safe: uses a queue + background thread
    - Rate limiting: prevents log floods
    - Sampling: optionally sample high-volume logs
    - Filtering: only capture specific loggers/levels

    Note: This handler uses a thread with its own event loop to handle
    async WAL operations. This adds complexity but ensures thread safety.
    """

    # Map Python log levels to Spine severity
    LEVEL_MAP = {
        logging.DEBUG: Severity.DEBUG,
        logging.INFO: Severity.INFO,
        logging.WARNING: Severity.WARNING,
        logging.ERROR: Severity.HIGH,
        logging.CRITICAL: Severity.CRITICAL,
    }

    def __init__(
        self,
        wal: WAL,
        min_level: int = logging.INFO,
        rate_limit_per_second: int = 100,
        sample_rate_debug: float = 0.1,  # Sample 10% of DEBUG logs
    ):
        super().__init__(level=min_level)
        self._wal = wal
        self._rate_limit = rate_limit_per_second
        self._sample_rate_debug = sample_rate_debug

        # Rate limiting state
        self._token_bucket = rate_limit_per_second
        self._last_refill = time.time()
        self._dropped_count = 0

        # Queue for async processing
        self._queue: queue.Queue = queue.Queue(maxsize=1000)
        self._shutdown = threading.Event()

        # Background thread with its own event loop
        self._thread = threading.Thread(target=self._process_loop, daemon=True)
        self._thread.start()

    def _refill_tokens(self) -> None:
        """Refill rate limit tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self._last_refill
        self._token_bucket = min(
            self._rate_limit,
            self._token_bucket + int(elapsed * self._rate_limit)
        )
        self._last_refill = now

    def _should_sample(self, record: logging.LogRecord) -> bool:
        """Determine if this record should be sampled (for DEBUG)."""
        if record.levelno > logging.DEBUG:
            return True  # Always log non-DEBUG
        # Sample DEBUG logs
        import random
        return random.random() < self._sample_rate_debug

    def emit(self, record: logging.LogRecord) -> None:
        """Called by the logging framework for each log record."""
        # Sampling for DEBUG
        if not self._should_sample(record):
            return

        # Rate limiting
        self._refill_tokens()
        if self._token_bucket <= 0:
            self._dropped_count += 1
            return
        self._token_bucket -= 1

        # Build audit event
        severity = self.LEVEL_MAP.get(record.levelno, Severity.INFO)
        event = AuditEvent(
            event_type=f"log.{record.name}",
            severity=severity,
            source=record.name,
            payload={
                "message": record.getMessage(),
                "level": record.levelname,
                "module": record.module,
                "funcName": record.funcName,
                "lineno": record.lineno,
                "process": record.process,
                "thread": record.thread,
            }
        )

        # Add exception info if present
        if record.exc_info:
            event.payload["exception"] = self.format(record)

        # Queue for async processing (non-blocking)
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self._dropped_count += 1

    def _process_loop(self) -> None:
        """Background thread that writes events to WAL."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        while not self._shutdown.is_set():
            try:
                # Wait for event with timeout
                event = self._queue.get(timeout=0.1)
                # Write to WAL
                loop.run_until_complete(self._wal.append(event.to_dict()))
            except queue.Empty:
                continue
            except Exception as e:
                # Don't crash the thread on errors
                print(f"SpineHandler error: {e}")

        loop.close()

    def close(self) -> None:
        """Shutdown the handler gracefully."""
        self._shutdown.set()
        self._thread.join(timeout=5.0)
        super().close()

    def get_stats(self) -> dict:
        """Get handler statistics."""
        return {
            "queue_size": self._queue.qsize(),
            "dropped_count": self._dropped_count,
            "rate_limit_tokens": self._token_bucket,
        }


def load_or_create_key() -> SigningKey:
    """Load signing key from environment, file, or generate new one."""
    if os.environ.get("SPINE_KEY"):
        return SigningKey.from_env("SPINE_KEY")
    if KEY_FILE.exists():
        return SigningKey.from_file(KEY_FILE, key_id="logging-example")
    key = SigningKey.generate(key_id="logging-example")
    key.save_to_file(KEY_FILE, key_format="hex")
    print(f"Generated new signing key: {KEY_FILE}")
    return key


async def main():
    # Initialize WAL
    key = load_or_create_key()
    wal = WAL(key, WALConfig(data_dir=str(WAL_DIR)))
    await wal.initialize()

    # Create and configure handler
    spine_handler = SpineHandler(
        wal=wal,
        min_level=logging.INFO,
        rate_limit_per_second=50,
        sample_rate_debug=0.1,
    )

    # Set up logging
    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.DEBUG)
    audit_logger.addHandler(spine_handler)

    # Also log to console for visibility
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    ))
    audit_logger.addHandler(console_handler)

    print("Logging some events...")
    print()

    try:
        # Simulate application logging
        audit_logger.info("User authentication successful", extra={"user_id": "alice"})
        audit_logger.warning("Failed login attempt", extra={"user_id": "bob", "ip": "192.168.1.100"})
        audit_logger.info("Data export initiated", extra={"records": 1500})
        audit_logger.error("Permission denied for admin action")

        # Simulate some DEBUG logs (10% sampled)
        for i in range(20):
            audit_logger.debug(f"Debug message {i}")

        # Simulate an exception
        try:
            raise ValueError("Something went wrong")
        except ValueError:
            audit_logger.exception("Caught an exception")

        # Wait for events to be processed
        await asyncio.sleep(1)

        # Get stats
        print()
        print("Handler stats:", spine_handler.get_stats())

        wal_stats = await wal.get_stats()
        print(f"WAL stats: {wal_stats['seq']} records")

    finally:
        # Cleanup
        spine_handler.close()
        # WAL persists automatically

    print()
    print(f"Events logged to {WAL_DIR}/")
    print(f"Verify with: spine-cli verify --wal {WAL_DIR}")


if __name__ == "__main__":
    asyncio.run(main())
