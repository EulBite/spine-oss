#!/usr/bin/env python3
"""
FastAPI Audit Middleware - Log all HTTP requests to Spine WAL.

This example demonstrates:
- FastAPI middleware integration
- Request/response audit logging
- Header allowlist/denylist for privacy
- Idempotency key based on request ID
- Proper startup/shutdown lifecycle

Requirements:
    pip install fastapi uvicorn

Run:
    python fastapi_middleware.py

Test:
    curl http://localhost:8000/
    curl http://localhost:8000/users/123
    curl -X POST http://localhost:8000/data -d '{"key": "value"}'

Verify:
    spine-cli verify --wal ./audit_log
"""

import asyncio
import hashlib
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.routing import APIRoute

from spine_client import WAL, WALConfig, SigningKey, AuditEvent, Severity, Actor, Resource


# Configuration
KEY_FILE = Path(__file__).parent / "signing.key"
WAL_DIR = Path(__file__).parent / "audit_log"

# Headers to include in audit log (allowlist)
LOGGED_REQUEST_HEADERS = {"user-agent", "content-type", "accept", "x-request-id"}
LOGGED_RESPONSE_HEADERS = {"content-type", "content-length"}

# Headers to NEVER log (denylist - takes precedence)
REDACTED_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}


# Global WAL instance (initialized on startup)
_wal: WAL | None = None


def load_or_create_key() -> SigningKey:
    """Load signing key from environment, file, or generate new one."""
    if os.environ.get("SPINE_KEY"):
        return SigningKey.from_env("SPINE_KEY")
    if KEY_FILE.exists():
        return SigningKey.from_file(KEY_FILE, key_id="fastapi-example")
    key = SigningKey.generate(key_id="fastapi-example")
    key.save_to_file(KEY_FILE, key_format="hex")
    print(f"Generated new signing key: {KEY_FILE}")
    return key


def filter_headers(headers: dict, allowed: set, redacted: set) -> dict:
    """Filter headers for audit logging."""
    result = {}
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower in redacted:
            result[key] = "[REDACTED]"
        elif key_lower in allowed:
            result[key] = value
    return result


def generate_idempotency_key(request: Request) -> str:
    """
    Generate deterministic idempotency key for request deduplication.

    Uses request ID if present, otherwise hashes method + path + timestamp.
    """
    request_id = request.headers.get("x-request-id")
    if request_id:
        return f"req:{request_id}"

    # Fallback: hash of request details (less reliable for dedup)
    content = f"{request.method}:{request.url.path}:{time.time_ns()}"
    return f"req:{hashlib.sha256(content.encode()).hexdigest()[:16]}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan handler for WAL initialization and cleanup."""
    global _wal

    # Startup
    key = load_or_create_key()
    _wal = WAL(key, WALConfig(data_dir=str(WAL_DIR)))
    await _wal.initialize()
    print(f"Spine WAL initialized: {WAL_DIR}")

    yield

    # Shutdown (WAL persists automatically, no explicit close needed)
    print("Spine WAL shutdown complete")


app = FastAPI(
    title="Spine Audit Example",
    lifespan=lifespan,
)


@app.middleware("http")
async def audit_middleware(request: Request, call_next: Callable) -> Response:
    """Log all HTTP requests to Spine WAL."""
    global _wal

    if _wal is None:
        return await call_next(request)

    # Capture request details before processing
    start_time = time.time()
    request_id = request.headers.get("x-request-id", str(uuid.uuid4()))

    # Extract client info for actor
    client_host = request.client.host if request.client else "unknown"

    # Process request
    try:
        response = await call_next(request)
        status_code = response.status_code
        error_detail = None
    except Exception as e:
        status_code = 500
        error_detail = str(e)
        raise
    finally:
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Determine severity based on status code
        if status_code >= 500:
            severity = Severity.HIGH
        elif status_code >= 400:
            severity = Severity.WARNING
        else:
            severity = Severity.INFO

        # Build audit event
        event = AuditEvent(
            event_type="http.request",
            severity=severity,
            idempotency_key=generate_idempotency_key(request),
            actor=Actor(
                id=request.headers.get("x-user-id"),  # Set by auth middleware
                ip_address=client_host,
            ),
            resource=Resource(
                type="http_endpoint",
                id=request.url.path,
                name=f"{request.method} {request.url.path}",
            ),
            payload={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "query": str(request.url.query) if request.url.query else None,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "request_headers": filter_headers(
                    dict(request.headers),
                    LOGGED_REQUEST_HEADERS,
                    REDACTED_HEADERS,
                ),
                "error": error_detail,
            }
        )

        # Log to WAL (fire-and-forget, don't block response)
        try:
            await _wal.append(event.to_dict())
        except Exception as e:
            # Don't fail the request if audit logging fails
            print(f"Audit logging failed: {e}")

    return response


# Example routes
@app.get("/")
async def root():
    return {"message": "Hello, World!"}


@app.get("/users/{user_id}")
async def get_user(user_id: str):
    return {"user_id": user_id, "name": f"User {user_id}"}


@app.post("/data")
async def create_data(data: dict):
    return {"received": data, "id": str(uuid.uuid4())}


@app.get("/health")
async def health():
    """Health check endpoint (not audited in production)."""
    global _wal
    if _wal:
        stats = await _wal.get_stats()
        return {"status": "healthy", "wal_records": stats.get("seq", 0)}
    return {"status": "healthy", "wal": "not initialized"}


if __name__ == "__main__":
    import uvicorn
    print("Starting FastAPI server with Spine audit logging...")
    print(f"WAL directory: {WAL_DIR}")
    print()
    uvicorn.run(app, host="0.0.0.0", port=8000)
