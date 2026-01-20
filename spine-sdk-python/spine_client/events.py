# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Event types for Spine audit logging.
"""

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Actor:
    """
    Entity performing the action.

    Attributes:
        id: Unique identifier (user ID, service account, etc.)
        email: Email address if applicable
        role: Role or permission level
        ip_address: Source IP address
    """
    id: str | None = None
    email: str | None = None
    role: str | None = None
    ip_address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Resource:
    """
    Resource being accessed or modified.

    Attributes:
        type: Resource type (e.g., "database", "file", "api")
        id: Resource identifier
        name: Human-readable name
    """
    type: str | None = None
    id: str | None = None
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class AuditEvent:
    """
    Audit event to be logged to Spine.

    Attributes:
        event_type: Classification (e.g., "auth.login", "data.export")
        payload: Arbitrary event data
        actor: Entity performing the action
        resource: Resource being accessed
        severity: Event severity level
        source: Originating system/service
        timestamp: Event timestamp (auto-generated if not provided)
        idempotency_key: For deduplication (auto-generated if not provided)

    Example:
        event = AuditEvent(
            event_type="auth.privilege_escalation",
            severity=Severity.CRITICAL,
            actor=Actor(id="user_42", role="user"),
            resource=Resource(type="role", id="admin"),
            payload={
                "previous_role": "user",
                "new_role": "admin",
                "approved_by": "system"
            }
        )
    """
    event_type: str
    payload: dict[str, Any] = field(default_factory=dict)
    actor: Actor | None = None
    resource: Resource | None = None
    severity: Severity = Severity.INFO
    source: str | None = None
    timestamp: str | None = None
    idempotency_key: str | None = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.idempotency_key is None:
            self.idempotency_key = str(uuid.uuid4())

    def to_dict(self) -> dict[str, Any]:
        """Convert to API request format.

        Validates that payload is JSON-serializable before returning.

        Raises:
            ValueError: If payload contains non-serializable values
        """
        # Validate payload is JSON-serializable
        self._validate_payload()

        result = {
            "event_type": self.event_type,
            "payload": self.payload,
            "severity": self.severity.value,
            "timestamp": self.timestamp,
            "idempotency_key": self.idempotency_key,  # Always include for dedup
        }

        if self.actor:
            result["actor"] = self.actor.to_dict()
        if self.resource:
            result["resource"] = self.resource.to_dict()
        if self.source:
            result["source"] = self.source

        return result

    def _validate_payload(self) -> None:
        """Validate that payload is JSON-serializable.

        Raises:
            ValueError: If payload contains non-serializable values
        """
        import json
        try:
            json.dumps(self.payload)
        except (TypeError, ValueError) as e:
            raise ValueError(
                f"Payload contains non-JSON-serializable values: {e}. "
                f"Use default=str or convert values before creating AuditEvent."
            ) from e

    def to_json(self) -> str:
        """Serialize to JSON string."""
        import json
        return json.dumps(self.to_dict())
