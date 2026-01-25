# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Cryptographic primitives for Spine SDK.

Provides:
- Canonical JSON serialization (deterministic, RFC 8785-like)
- Hashing (BLAKE3 primary, SHA-256 for compatibility)
- Ed25519 signing and verification
- Key management (generation, serialization, BYOK)

Security model:
- Client signatures = "integrity claim" (proves client created the event)
- Server receipts = "authoritative proof" (proves system of record accepted it)

Architecture note (Future refactor):
    Currently, this module only provides client-side signing (SigningKey/VerifyingKey).
    Server receipts are treated as opaque data in types.Receipt.

    When server receipt verification is needed, consider:
    - ServerVerifyingKey class (loads server's public key)
    - Receipt.verify(server_key) method
    - Separation of "client signature" vs "server attestation" in type system

    For now, receipt verification is deferred to server-side or CLI tooling.
"""

import base64
import hashlib
import json
import os
import secrets
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

# Ed25519 via cryptography library (widely available)
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

# BLAKE3 (optional, faster)
try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False


# =============================================================================
# Canonical JSON
# =============================================================================

# Note: float intentionally excluded - see canonical_json() docstring for rationale
JsonValue = dict | list | str | int | bool | None


def _normalize_unicode(obj: JsonValue) -> JsonValue:
    """
    Recursively apply Unicode NFC normalization to all strings.

    This ensures that equivalent Unicode sequences produce identical bytes:
    - "café" (é as single codepoint U+00E9)
    - "café" (e + combining acute U+0065 U+0301)
    Both normalize to the composed form (NFC).

    Also rejects float values to ensure cross-implementation compatibility.

    Args:
        obj: JSON-serializable object

    Returns:
        Object with all strings NFC-normalized

    Raises:
        TypeError: If obj contains float values (not supported for audit logs)
    """
    if isinstance(obj, str):
        return unicodedata.normalize('NFC', obj)
    elif isinstance(obj, dict):
        return {
            unicodedata.normalize('NFC', k) if isinstance(k, str) else k: _normalize_unicode(v)
            for k, v in obj.items()
        }
    elif isinstance(obj, list):
        return [_normalize_unicode(item) for item in obj]
    elif isinstance(obj, float):
        # RFC8785 requires specific float canonicalization (no 1.0, no 1e3, no -0).
        # Python's json.dumps does NOT guarantee this (e.g., 1.0 → "1.0" but RFC wants "1").
        # Floats in audit logs are also semantically questionable (precision drift).
        # Reject floats entirely - use int, str, or Decimal (as string) instead.
        raise TypeError(
            f"Float values not allowed in canonical JSON for audit logs. "
            f"Got: {obj}. Use int, str, or Decimal (serialized as string) instead."
        )
    else:
        return obj


def canonical_json(obj: dict | list | str | int | bool | None) -> bytes:
    """
    Serialize object to canonical JSON (deterministic byte representation).

    Rules (RFC 8785-like):
    - Unicode NFC normalization (ensures equivalent strings produce same bytes)
    - Keys sorted lexicographically (Unicode code points)
    - No whitespace
    - Strings: minimal escaping (only required chars)
    - UTF-8 encoded output
    - **Float values are rejected** (see below)

    Float Rejection:
        RFC 8785 requires specific float canonicalization (no "1.0", no "1e3",
        no "-0"), but Python's json.dumps does NOT guarantee this. Example:
            Python: 1.0 → "1.0"
            RFC8785: 1.0 → "1"

        This breaks cross-implementation verification. Additionally, floats in
        audit logs are semantically questionable (precision drift across
        languages/platforms). Use int, str, or Decimal (as string) instead.

    Args:
        obj: JSON-serializable object (no floats)

    Returns:
        Canonical JSON as UTF-8 bytes

    Raises:
        TypeError: If obj contains float values

    Example:
        >>> canonical_json({"b": 1, "a": 2})
        b'{"a":2,"b":1}'
        >>> canonical_json({"café": 1}) == canonical_json({"cafe\u0301": 1})  # NFC normalization
        True
        >>> canonical_json({"x": 1.0})  # Raises TypeError
    """
    # Apply Unicode NFC normalization before serialization
    normalized = _normalize_unicode(obj)

    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False,
    ).encode('utf-8')


# =============================================================================
# Hashing
# =============================================================================

class HashAlgorithm:
    """Supported hash algorithms."""
    BLAKE3 = "blake3"
    SHA256 = "sha256"


def compute_hash(
    data: bytes,
    algorithm: str = HashAlgorithm.BLAKE3,
) -> tuple[str, str]:
    """
    Compute cryptographic hash of data.

    Args:
        data: Bytes to hash
        algorithm: Hash algorithm (blake3 or sha256)

    Returns:
        Tuple of (hex_digest, algorithm_used)

    Raises:
        ValueError: If algorithm not supported or not available
    """
    if algorithm == HashAlgorithm.BLAKE3:
        if not HAS_BLAKE3:
            raise RuntimeError(
                "BLAKE3 is required but not installed. "
                "Install with: pip install blake3"
            )
        digest = blake3.blake3(data).hexdigest()
        return (digest, HashAlgorithm.BLAKE3)

    if algorithm == HashAlgorithm.SHA256:
        digest = hashlib.sha256(data).hexdigest()
        return (digest, HashAlgorithm.SHA256)

    raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def hash_payload(payload: dict, algorithm: str = HashAlgorithm.BLAKE3) -> tuple[str, str]:
    """
    Compute hash of a payload dict using canonical JSON.

    Args:
        payload: Dict to hash
        algorithm: Hash algorithm

    Returns:
        Tuple of (hex_digest, algorithm_used)
    """
    canonical = canonical_json(payload)
    return compute_hash(canonical, algorithm)


# =============================================================================
# Ed25519 Signing
# =============================================================================

@dataclass
class SigningKey:
    """Ed25519 signing key (private key)."""
    key_id: str
    _private_key: "Ed25519PrivateKey"
    created_at: str

    @classmethod
    def generate(cls, key_id: str | None = None) -> "SigningKey":
        """
        Generate a new Ed25519 signing key.

        Args:
            key_id: Optional key identifier. If not provided, generates one.

        Returns:
            New SigningKey instance
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library required for Ed25519 signing")

        if key_id is None:
            # Generate key_id: kid_<random>
            key_id = f"kid_{secrets.token_hex(8)}"

        private_key = Ed25519PrivateKey.generate()

        return cls(
            key_id=key_id,
            _private_key=private_key,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def from_seed_bytes(cls, seed: bytes, key_id: str) -> "SigningKey":
        """
        Load signing key from a 32-byte Ed25519 seed.

        IMPORTANT: Ed25519 "private key" terminology is confusing:
        - The 32-byte value you provide is the SEED
        - cryptography library internally expands this to 64 bytes (via SHA-512)
        - The actual signing uses the expanded key, not the seed directly

        This method accepts raw seed bytes (e.g., from `os.urandom(32)` or
        another key derivation). The cryptography library handles the Ed25519
        key expansion internally.

        For BYOK (Bring Your Own Key):
        - If you have a 32-byte seed from another system, use this method
        - If you have a PEM file, use `from_pem()`
        - If you want to generate a new key, use `generate()`

        Args:
            seed: 32-byte Ed25519 seed (NOT the expanded 64-byte key)
            key_id: Key identifier for tracking/rotation

        Returns:
            SigningKey instance

        Raises:
            ValueError: If seed is not exactly 32 bytes
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library required for Ed25519 signing")

        if len(seed) != 32:
            raise ValueError(f"Ed25519 seed must be exactly 32 bytes, got {len(seed)}")

        private_key = Ed25519PrivateKey.from_private_bytes(seed)

        return cls(
            key_id=key_id,
            _private_key=private_key,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def from_pem(cls, pem_data: bytes, key_id: str) -> "SigningKey":
        """
        Load signing key from PEM format.

        Args:
            pem_data: PEM-encoded private key
            key_id: Key identifier

        Returns:
            SigningKey instance
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library required for Ed25519 signing")

        private_key = serialization.load_pem_private_key(pem_data, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("PEM does not contain an Ed25519 private key")

        return cls(
            key_id=key_id,
            _private_key=private_key,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def from_env(
        cls,
        env_var: str = "SPINE_SIGNING_KEY",
        key_id_var: str | None = "SPINE_KEY_ID",
    ) -> "SigningKey":
        """
        Load signing key from environment variable.

        Supports multiple formats (auto-detected):
        - Hex string (64 chars): raw 32-byte key as hex
        - Base64 string (44 chars): raw 32-byte key as base64
        - PEM string: full PEM-encoded private key

        Args:
            env_var: Environment variable containing the key (default: SPINE_SIGNING_KEY)
            key_id_var: Environment variable for key ID (default: SPINE_KEY_ID).
                        If None or not set, generates a random key_id.

        Returns:
            SigningKey instance

        Raises:
            ValueError: If environment variable not set or key format invalid

        Example:
            # Set in environment:
            # export SPINE_SIGNING_KEY=<64-char-hex>
            # export SPINE_KEY_ID=my-service-key

            key = SigningKey.from_env()
        """
        key_data = os.environ.get(env_var)
        if not key_data:
            raise ValueError(
                f"Environment variable {env_var} not set. "
                f"Set it to a hex (64 chars), base64 (44 chars), or PEM private key."
            )

        # Get key_id from env or generate
        key_id = None
        if key_id_var:
            key_id = os.environ.get(key_id_var)
        if not key_id:
            key_id = f"kid_{secrets.token_hex(8)}"

        key_data = key_data.strip()

        # Detect format and load (order: PEM → hex → base64)
        if key_data.startswith("-----BEGIN"):
            # PEM format
            return cls.from_pem(key_data.encode("utf-8"), key_id)

        # Try hex (64 chars = 32 bytes)
        if len(key_data) == 64:
            try:
                key_bytes = bytes.fromhex(key_data)
                return cls.from_seed_bytes(key_bytes, key_id)
            except ValueError:
                pass  # Not valid hex, try base64

        # Try base64 (handles with/without padding, with/without whitespace)
        # Don't use length heuristics - just try to decode and check result
        try:
            # validate=True rejects invalid chars (stricter than default)
            key_bytes = base64.b64decode(key_data, validate=True)
            if len(key_bytes) == 32:
                return cls.from_seed_bytes(key_bytes, key_id)
            # Decoded but wrong length - fall through to error
        except Exception:
            pass  # Not valid base64

        raise ValueError(
            f"Unrecognized key format in {env_var}. "
            f"Expected: PEM, 64-char hex, or base64 (decoding to 32 bytes). "
            f"Got {len(key_data)} chars that don't match any format."
        )

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        key_id: str | None = None,
    ) -> "SigningKey":
        """
        Load signing key from file.

        Supports multiple formats (auto-detected by content):
        - PEM file: standard Ed25519 private key PEM
        - Hex file: 64-character hex string (optionally with newline)
        - Raw binary: 32-byte raw key (useful for keys from other tools)

        Args:
            path: Path to key file
            key_id: Key identifier. If None, uses filename (without extension).

        Returns:
            SigningKey instance

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If key format invalid

        Example:
            # From PEM file
            key = SigningKey.from_file("/etc/spine/signing.pem")

            # From hex file
            key = SigningKey.from_file("./my-key.hex", key_id="production-signer")
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Key file not found: {path}")

        # Default key_id from filename
        if key_id is None:
            key_id = path.stem  # filename without extension

        # Read file content
        content = path.read_bytes()

        # Detect format
        if content.startswith(b"-----BEGIN"):
            # PEM format
            return cls.from_pem(content, key_id)
        elif len(content) == 32:
            # Raw 32-byte seed
            return cls.from_seed_bytes(content, key_id)
        elif len(content) in (64, 65):  # 64 hex chars, optionally with newline
            # Hex format
            try:
                hex_str = content.decode("utf-8").strip()
                key_bytes = bytes.fromhex(hex_str)
                return cls.from_seed_bytes(key_bytes, key_id)
            except (UnicodeDecodeError, ValueError) as e:
                raise ValueError(f"Invalid hex key file {path}: {e}") from e
        else:
            raise ValueError(
                f"Unrecognized key format in {path}. "
                f"Expected: PEM, 32-byte raw, or 64-char hex. Got {len(content)} bytes."
            )

    def save_to_file(
        self,
        path: str | Path,
        key_format: str = "pem",
    ) -> Path:
        """
        Save signing key to file.

        Args:
            path: Destination path
            key_format: Output format - "pem", "hex", or "raw"

        Returns:
            Path to saved file

        Example:
            key = SigningKey.generate(key_id="my-key")
            key.save_to_file("./my-key.pem")
            key.save_to_file("./my-key.hex", key_format="hex")
        """
        path = Path(path)

        if key_format == "pem":
            content = self.to_pem()
        elif key_format == "hex":
            content = self.to_bytes().hex().encode("utf-8")
        elif key_format == "raw":
            content = self.to_bytes()
        else:
            raise ValueError(f"Unknown format: {key_format}. Use 'pem', 'hex', or 'raw'.")

        path.write_bytes(content)
        return path

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with this key.

        Args:
            data: Bytes to sign

        Returns:
            64-byte Ed25519 signature
        """
        return self._private_key.sign(data)

    def sign_hex(self, data: bytes) -> str:
        """Sign data and return hex-encoded signature."""
        return self.sign(data).hex()

    def public_key(self) -> "VerifyingKey":
        """Get the corresponding public key."""
        return VerifyingKey(
            key_id=self.key_id,
            _public_key=self._private_key.public_key(),
        )

    def to_bytes(self) -> bytes:
        """Export private key as raw bytes (32 bytes)."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def to_pem(self) -> bytes:
        """Export private key as PEM."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


@dataclass
class VerifyingKey:
    """Ed25519 verifying key (public key)."""
    key_id: str
    _public_key: "Ed25519PublicKey"

    @classmethod
    def from_bytes(cls, public_bytes: bytes, key_id: str) -> "VerifyingKey":
        """
        Load verifying key from raw bytes (32 bytes).

        Args:
            public_bytes: 32-byte Ed25519 public key
            key_id: Key identifier

        Returns:
            VerifyingKey instance
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library required for Ed25519 verification")

        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

        return cls(key_id=key_id, _public_key=public_key)

    @classmethod
    def from_hex(cls, hex_string: str, key_id: str) -> "VerifyingKey":
        """Load verifying key from hex-encoded bytes."""
        return cls.from_bytes(bytes.fromhex(hex_string), key_id)

    @classmethod
    def from_pem(cls, pem_data: bytes, key_id: str) -> "VerifyingKey":
        """
        Load verifying key from PEM format.

        Args:
            pem_data: PEM-encoded public key
            key_id: Key identifier

        Returns:
            VerifyingKey instance
        """
        if not HAS_CRYPTOGRAPHY:
            raise RuntimeError("cryptography library required for Ed25519 verification")

        public_key = serialization.load_pem_public_key(pem_data)
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("PEM does not contain an Ed25519 public key")

        return cls(key_id=key_id, _public_key=public_key)

    def verify(self, signature: bytes, data: bytes) -> bool:
        """
        Verify a signature.

        Args:
            signature: 64-byte Ed25519 signature
            data: Original signed data

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            self._public_key.verify(signature, data)
            return True
        except Exception:
            return False

    def verify_hex(self, signature_hex: str, data: bytes) -> bool:
        """Verify a hex-encoded signature."""
        return self.verify(bytes.fromhex(signature_hex), data)

    def to_bytes(self) -> bytes:
        """Export public key as raw bytes (32 bytes)."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def to_hex(self) -> str:
        """Export public key as hex string."""
        return self.to_bytes().hex()

    def to_pem(self) -> bytes:
        """Export public key as PEM."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


# =============================================================================
# Convenience functions
# =============================================================================

def sign_payload(payload: dict, signing_key: SigningKey) -> tuple[str, str, str]:
    """
    Sign a payload dict.

    Args:
        payload: Dict to sign
        signing_key: Key to sign with

    Returns:
        Tuple of (payload_hash, signature_hex, hash_algorithm)
    """
    canonical = canonical_json(payload)
    payload_hash, hash_alg = compute_hash(canonical)
    signature = signing_key.sign_hex(canonical)
    return (payload_hash, signature, hash_alg)


def verify_payload_signature(
    payload: dict,
    signature_hex: str,
    verifying_key: VerifyingKey,
) -> bool:
    """
    Verify a payload signature.

    Args:
        payload: Original payload dict
        signature_hex: Hex-encoded signature
        verifying_key: Key to verify with

    Returns:
        True if signature is valid
    """
    canonical = canonical_json(payload)
    return verifying_key.verify_hex(signature_hex, canonical)


# =============================================================================
# Entry Hash (chain linking)
# =============================================================================

def compute_entry_hash(
    seq: int,
    timestamp_ns: int,
    prev_hash: str,
    payload_hash: str,
    algorithm: str = HashAlgorithm.BLAKE3,
) -> tuple[str, str]:
    """
    Compute the entry hash for chain linking.

    This hash binds all entry metadata together and is used for:
    1. Chain linking (prev_hash of next entry)
    2. Signature computation

    The format is identical to spine-cli (Rust) for compatibility:
    BLAKE3(seq_le_bytes || timestamp_ns_le_bytes || prev_hash_bytes || payload_hash_bytes)

    IMPORTANT: Entry hash MUST use BLAKE3 for CLI compatibility.
    Install blake3: pip install blake3

    Args:
        seq: Sequence number (u64)
        timestamp_ns: Timestamp in nanoseconds (i64)
        prev_hash: Previous entry hash (hex string)
        payload_hash: Payload hash (hex string)
        algorithm: Hash algorithm (must be blake3 for CLI compatibility)

    Returns:
        Tuple of (entry_hash_hex, algorithm_used)

    Raises:
        RuntimeError: If BLAKE3 is required but not installed
    """
    import struct

    # Entry hash MUST use BLAKE3 for CLI compatibility - enforce contract
    if algorithm != HashAlgorithm.BLAKE3:
        raise ValueError(
            f"Entry hash must use BLAKE3 for CLI compatibility, got: {algorithm}"
        )

    if not HAS_BLAKE3:
        raise RuntimeError(
            "BLAKE3 is required for entry hash computation (CLI compatibility). "
            "Install it with: pip install blake3"
        )

    # Binary format MUST match spine-cli (Rust) exactly for cross-language verification:
    # - Little-endian: matches Rust's to_le_bytes() on x86/ARM (most platforms)
    # - UTF-8 for hashes: ensures consistent byte representation across languages
    # - Field order: seq || ts || prev || payload (immutable contract)
    seq_bytes = struct.pack('<Q', seq)   # u64 LE
    ts_bytes = struct.pack('<q', timestamp_ns)   # i64 LE (signed for future-proofing)

    data = seq_bytes + ts_bytes + prev_hash.encode('utf-8') + payload_hash.encode('utf-8')

    return compute_hash(data, algorithm)


def timestamp_to_nanos(iso_timestamp: str) -> int:
    """
    Convert ISO timestamp string to nanoseconds since epoch.

    Uses integer arithmetic to avoid floating-point precision loss.
    Python's datetime only has microsecond precision, so we multiply by 1000.

    Args:
        iso_timestamp: ISO 8601 timestamp (e.g., "2025-01-15T10:30:00.123456+00:00")

    Returns:
        Nanoseconds since Unix epoch (i64)
    """
    import calendar
    from datetime import datetime, timezone

    # Parse ISO timestamp
    dt = datetime.fromisoformat(iso_timestamp)

    # Ensure timezone aware (assume UTC if naive)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    # Convert to UTC for consistent calculation
    dt_utc = dt.astimezone(timezone.utc)

    # Why calendar.timegm instead of dt.timestamp()?
    # - timestamp() returns float, loses precision at ~15 significant digits
    # - For ns since 1970: ~19 digits needed (1737000000000000000)
    # - Float would give 1737000000000000000 vs 1737000000000000512 (wrong!)
    # - Integer arithmetic preserves exact nanosecond values for CLI matching
    seconds = calendar.timegm(dt_utc.timetuple())
    microseconds = dt_utc.microsecond  # Python's max precision is microseconds
    return seconds * 1_000_000_000 + microseconds * 1_000
