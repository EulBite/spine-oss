# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Core data types for Spine SDK.

Data model:
- Event: User-facing audit event (what the app creates)
- LocalRecord: WAL entry with crypto metadata (internal)
- Receipt: Server acknowledgment (authoritative proof)
- VerifyResult: Verification outcome

Security levels:
- Without receipt: "Client Integrity Claim" (useful, but not authoritative)
- With receipt: "Audit-grade Proof" (server-attested, time-bound, verifiable)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from enum import Enum
import uuid
import time


class Severity(str, Enum):
    """Event severity levels."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class VerifyStatus(str, Enum):
    """Verification result status."""
    VALID = "valid"                    # All checks passed
    INVALID_HASH = "invalid_hash"      # Hash mismatch
    INVALID_SIGNATURE = "invalid_sig"  # Signature verification failed
    INVALID_CHAIN = "invalid_chain"    # prev_hash doesn't match
    MISSING_RECEIPT = "no_receipt"     # No server receipt (client claim only)
    INVALID_RECEIPT = "invalid_rcpt"   # Receipt signature invalid
    EXPIRED_RECEIPT = "expired_rcpt"   # Receipt too old


# =============================================================================
# Actor and Resource (re-exported from events.py for convenience)
# =============================================================================

@dataclass
class Actor:
    """Entity performing the action."""
    id: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None
    ip_address: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class Resource:
    """Resource being accessed or modified."""
    type: Optional[str] = None
    id: Optional[str] = None
    name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


# =============================================================================
# Receipt (server acknowledgment)
# =============================================================================

@dataclass
class Receipt:
    """
    Server receipt proving an event was accepted into the system of record.

    This is what makes an event "audit-grade" vs just a "client claim".

    Attributes:
        event_id: ID of the acknowledged event
        payload_hash: Hash of the event payload (must match client's)
        server_time: Server timestamp (RFC3339)
        server_seq: Server-assigned sequence number
        receipt_sig: Server's Ed25519 signature over receipt data
        server_key_id: ID of the server signing key
        sig_alg: Signature algorithm (ed25519)
        batch_id: Batch ID when event was sealed (None if pending)
    """
    event_id: str
    payload_hash: str
    server_time: str
    server_seq: int
    receipt_sig: str
    server_key_id: str
    sig_alg: str = "ed25519"
    batch_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "event_id": self.event_id,
            "payload_hash": self.payload_hash,
            "server_time": self.server_time,
            "server_seq": self.server_seq,
            "receipt_sig": self.receipt_sig,
            "server_key_id": self.server_key_id,
            "sig_alg": self.sig_alg,
        }
        if self.batch_id:
            result["batch_id"] = self.batch_id
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Receipt":
        return cls(
            event_id=data["event_id"],
            payload_hash=data["payload_hash"],
            server_time=data["server_time"],
            server_seq=data["server_seq"],
            receipt_sig=data["receipt_sig"],
            server_key_id=data["server_key_id"],
            sig_alg=data.get("sig_alg", "ed25519"),
            batch_id=data.get("batch_id"),
        )

    def receipt_data_for_signing(self) -> str:
        """
        Canonical string used for receipt signature verification.

        Format: event_id|payload_hash|server_time|server_seq
        """
        return f"{self.event_id}|{self.payload_hash}|{self.server_time}|{self.server_seq}"


# =============================================================================
# Format Version
# =============================================================================

# Current WAL record format version.
# Increment this when making breaking changes to the record structure.
#
# Version history:
#   1 - Initial format (2025-01): event_id, stream_id, seq, prev_hash, ts_client,
#       payload, payload_hash, hash_alg, sig_client, key_id, public_key, receipt
#
# Compatibility guarantee: CLI and SDK will support reading all previous versions.
# Breaking changes require version bump and migration documentation.
WAL_FORMAT_VERSION = 1


# =============================================================================
# LocalRecord (WAL entry with crypto metadata)
# =============================================================================

@dataclass
class LocalRecord:
    """
    A record in the local WAL with full cryptographic metadata.

    This is the internal representation. Users create Events, SDK creates Records.

    Attributes:
        format_version: WAL format version (for forward compatibility)
        event_id: Unique event identifier (UUID v7 / ULID preferred)
        stream_id: Stream identifier (derived from key_id or explicit)
        seq: Monotonic sequence number within this stream
        prev_hash: Hash of the previous record in this stream (chain)
        ts_client: Client timestamp (RFC3339)
        payload: The actual event data
        payload_hash: Hash of canonical JSON payload
        hash_alg: Hash algorithm used (blake3 or sha256)
        sig_client: Client signature over entry hash
        key_id: ID of the client signing key
        public_key: Full public key hex (for CLI signature verification)
        receipt: Server receipt (None until acknowledged)
    """
    event_id: str
    stream_id: str
    seq: int
    prev_hash: str
    ts_client: str
    payload: Dict[str, Any]
    payload_hash: str
    hash_alg: str
    sig_client: str
    key_id: str
    format_version: int = WAL_FORMAT_VERSION
    public_key: Optional[str] = None  # Full public key hex for CLI compatibility
    receipt: Optional[Receipt] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for WAL storage."""
        result = {
            "format_version": self.format_version,
            "event_id": self.event_id,
            "stream_id": self.stream_id,
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "ts_client": self.ts_client,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "hash_alg": self.hash_alg,
            "sig_client": self.sig_client,
            "key_id": self.key_id,
        }
        if self.public_key:
            result["public_key"] = self.public_key
        if self.receipt:
            result["receipt"] = self.receipt.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LocalRecord":
        receipt = None
        if "receipt" in data and data["receipt"]:
            receipt = Receipt.from_dict(data["receipt"])

        return cls(
            event_id=data["event_id"],
            stream_id=data["stream_id"],
            seq=data["seq"],
            prev_hash=data["prev_hash"],
            ts_client=data["ts_client"],
            payload=data["payload"],
            payload_hash=data["payload_hash"],
            hash_alg=data["hash_alg"],
            sig_client=data["sig_client"],
            key_id=data["key_id"],
            format_version=data.get("format_version", 1),  # Default to v1 for old records
            public_key=data.get("public_key"),
            receipt=receipt,
        )

    def has_receipt(self) -> bool:
        """Check if this record has a server receipt."""
        return self.receipt is not None

    def is_authoritative(self) -> bool:
        """
        Check if this record is authoritative (has valid server receipt).

        Note: This only checks presence, not validity. Use verify_receipt() for full check.
        """
        return self.receipt is not None


# =============================================================================
# VerifyResult
# =============================================================================

@dataclass
class VerifyResult:
    """
    Result of verifying a record or chain.

    Attributes:
        valid: Overall validity (True only if all checks pass)
        status: Detailed status code
        message: Human-readable explanation
        is_authoritative: True if server receipt is present and valid
        checked_at: Timestamp of verification
        details: Additional verification details
    """
    valid: bool
    status: VerifyStatus
    message: str
    is_authoritative: bool = False
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(cls, is_authoritative: bool = False, details: Optional[Dict] = None) -> "VerifyResult":
        """Create a successful verification result."""
        if is_authoritative:
            msg = "Audit-grade proof: server receipt verified"
        else:
            msg = "Client integrity claim: local chain and signature valid"

        return cls(
            valid=True,
            status=VerifyStatus.VALID,
            message=msg,
            is_authoritative=is_authoritative,
            details=details or {},
        )

    @classmethod
    def failure(cls, status: VerifyStatus, message: str, details: Optional[Dict] = None) -> "VerifyResult":
        """Create a failed verification result."""
        return cls(
            valid=False,
            status=status,
            message=message,
            is_authoritative=False,
            details=details or {},
        )


# =============================================================================
# Helper functions
# =============================================================================

def generate_event_id() -> str:
    """
    Generate a unique event ID.

    Uses UUID v7 (time-ordered) if available, otherwise UUID v4.
    Format: evt_<uuid>
    """
    # Python 3.11+ has uuid7, fallback to uuid4
    try:
        # Try uuid7 (time-ordered, better for databases)
        event_uuid = uuid.uuid7()  # type: ignore
    except AttributeError:
        # Fallback: uuid4 with timestamp prefix for rough ordering
        event_uuid = uuid.uuid4()

    return f"evt_{event_uuid}"


def generate_stream_id(key_id: str, namespace: Optional[str] = None) -> str:
    """
    Generate a stream ID from key_id and optional namespace.

    Stream ID determines the scope of the hash chain.
    Each (key_id, namespace) pair has its own independent chain.

    Args:
        key_id: Client signing key ID
        namespace: Optional namespace (e.g., app name, tenant ID)

    Returns:
        Stream ID in format: stream_<hash>
    """
    import hashlib
    source = f"{key_id}:{namespace or 'default'}"
    stream_hash = hashlib.sha256(source.encode()).hexdigest()[:16]
    return f"stream_{stream_hash}"
