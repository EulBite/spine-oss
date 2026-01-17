# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Circuit Breaker implementation for fault-tolerant Spine integration.

The circuit breaker prevents cascading failures when Spine is unavailable
by failing fast after a threshold of failures is reached.

States:
- CLOSED: Normal operation, requests flow through
- OPEN: Spine is considered down, requests fail immediately
- HALF_OPEN: Testing if Spine has recovered

Usage:
    breaker = CircuitBreaker(
        failure_threshold=3,
        recovery_timeout=30.0,
        half_open_max_calls=1
    )

    async with breaker:
        await spine_client.send(event)
"""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable, Any
import logging

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing fast
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    # Number of consecutive failures before opening circuit
    failure_threshold: int = 3
    # Seconds to wait before attempting recovery
    recovery_timeout: float = 30.0
    # Number of test requests in half-open state
    half_open_max_calls: int = 1
    # Number of successes needed to close circuit
    success_threshold: int = 2
    # Timeout for individual requests (seconds)
    call_timeout: float = 5.0


class CircuitBreakerError(Exception):
    """Raised when circuit is open and request is rejected."""
    pass


class CircuitBreaker:
    """
    Async-compatible circuit breaker for Spine client.

    Example:
        breaker = CircuitBreaker()

        # Using as context manager
        async with breaker:
            result = await risky_operation()

        # Using execute method
        result = await breaker.execute(risky_operation)

        # Check state
        if breaker.state == CircuitState.OPEN:
            use_fallback()
    """

    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 1,
        success_threshold: int = 2,
        call_timeout: float = 5.0,
        on_state_change: Optional[Callable[[CircuitState, CircuitState], None]] = None,
    ):
        self.config = CircuitBreakerConfig(
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            half_open_max_calls=half_open_max_calls,
            success_threshold=success_threshold,
            call_timeout=call_timeout,
        )

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[float] = None
        self._half_open_calls = 0
        self._lock = asyncio.Lock()
        self._on_state_change = on_state_change

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        return self._state

    @property
    def failure_count(self) -> int:
        """Number of consecutive failures."""
        return self._failure_count

    @property
    def is_closed(self) -> bool:
        """True if circuit is closed (normal operation)."""
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """True if circuit is open (failing fast)."""
        return self._state == CircuitState.OPEN

    def _set_state(self, new_state: CircuitState) -> None:
        """Update state with callback notification."""
        if new_state != self._state:
            old_state = self._state
            self._state = new_state
            logger.info(f"Circuit breaker state change: {old_state.value} -> {new_state.value}")
            if self._on_state_change:
                try:
                    self._on_state_change(old_state, new_state)
                except Exception as e:
                    logger.warning(f"State change callback error: {e}")

    async def _check_state(self) -> bool:
        """
        Check if request should be allowed.
        Returns True if request can proceed.
        """
        async with self._lock:
            if self._state == CircuitState.CLOSED:
                return True

            if self._state == CircuitState.OPEN:
                # Check if recovery timeout has passed
                if self._last_failure_time is not None:
                    elapsed = time.monotonic() - self._last_failure_time
                    if elapsed >= self.config.recovery_timeout:
                        self._set_state(CircuitState.HALF_OPEN)
                        self._half_open_calls = 0
                        self._success_count = 0
                        return True
                return False

            if self._state == CircuitState.HALF_OPEN:
                # Allow limited requests in half-open state
                if self._half_open_calls < self.config.half_open_max_calls:
                    self._half_open_calls += 1
                    return True
                return False

            return False

    async def _record_success(self) -> None:
        """Record a successful call."""
        async with self._lock:
            self._failure_count = 0

            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._set_state(CircuitState.CLOSED)
                    logger.info("Circuit breaker closed - service recovered")

    async def _record_failure(self) -> None:
        """Record a failed call."""
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()

            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open state opens the circuit
                self._set_state(CircuitState.OPEN)
                logger.warning("Circuit breaker opened - recovery test failed")
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    self._set_state(CircuitState.OPEN)
                    logger.warning(
                        f"Circuit breaker opened after {self._failure_count} failures"
                    )

    async def execute(self, func: Callable[[], Any], *args, **kwargs) -> Any:
        """
        Execute a function through the circuit breaker.

        Args:
            func: Async function to execute
            *args, **kwargs: Arguments to pass to function

        Returns:
            Result of the function

        Raises:
            CircuitBreakerError: If circuit is open
            Exception: Any exception from the function
        """
        if not await self._check_state():
            raise CircuitBreakerError(
                f"Circuit breaker is {self._state.value}, request rejected"
            )

        try:
            # Apply timeout to the call
            result = await asyncio.wait_for(
                func(*args, **kwargs) if asyncio.iscoroutinefunction(func)
                else asyncio.to_thread(func, *args, **kwargs),
                timeout=self.config.call_timeout
            )
            await self._record_success()
            return result
        except asyncio.TimeoutError:
            await self._record_failure()
            raise
        except Exception as e:
            await self._record_failure()
            raise

    async def __aenter__(self):
        """Context manager entry - check if request allowed."""
        if not await self._check_state():
            raise CircuitBreakerError(
                f"Circuit breaker is {self._state.value}, request rejected"
            )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - record result."""
        if exc_type is None:
            await self._record_success()
        else:
            await self._record_failure()
        return False  # Don't suppress exceptions

    def reset(self) -> None:
        """Manually reset the circuit breaker to closed state."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time = None
        self._half_open_calls = 0
        logger.info("Circuit breaker manually reset")

    def get_stats(self) -> dict:
        """Get circuit breaker statistics."""
        return {
            "state": self._state.value,
            "failure_count": self._failure_count,
            "success_count": self._success_count,
            "last_failure_time": self._last_failure_time,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout": self.config.recovery_timeout,
                "success_threshold": self.config.success_threshold,
            }
        }
