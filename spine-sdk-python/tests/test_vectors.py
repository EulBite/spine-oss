# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""
Cross-language compatibility test vectors.

These tests validate that the Spine SDK produces deterministic,
reproducible output that matches the expected vectors. This ensures:
1. Cross-language compatibility (Python SDK ↔ Rust CLI)
2. No accidental changes to hash/signature algorithms
3. Unicode NFC normalization works correctly
4. Edge cases are handled consistently

If any of these tests fail, it indicates a breaking change in
the cryptographic primitives that could break WAL verification.
"""

import json
from pathlib import Path

import pytest

from spine_client.crypto import (
    SigningKey,
    VerifyingKey,
    canonical_json,
    compute_entry_hash,
    hash_payload,
    timestamp_to_nanos,
)

# Load test vectors from shared cross-language location
VECTORS_PATH = Path(__file__).parent.parent.parent / "test-vectors" / "vectors.json"
with open(VECTORS_PATH, encoding="utf-8") as f:
    VECTORS = json.load(f)


# =============================================================================
# Canonical JSON Tests
# =============================================================================


class TestCanonicalJson:
    """Test RFC 8785-like canonical JSON serialization."""

    @pytest.mark.parametrize(
        "case",
        [
            c for c in VECTORS["canonical_json"]["cases"]
            if c.get("_test_type") != "documentation_only"
        ],
        ids=lambda c: c["name"],
    )
    def test_canonical_json_vectors(self, case):
        """Canonical JSON must produce expected byte output."""
        result = canonical_json(case["input"])

        # Verify UTF-8 output matches expected
        if "expected_utf8" in case:
            assert result.decode("utf-8") == case["expected_utf8"], (
                f"Canonical JSON mismatch for '{case['name']}': "
                f"expected {case['expected_utf8']!r}, got {result.decode('utf-8')!r}"
            )

        # Verify hex output if provided
        if "expected_bytes_hex" in case:
            assert result.hex() == case["expected_bytes_hex"], (
                f"Hex mismatch for '{case['name']}': "
                f"expected {case['expected_bytes_hex']}, got {result.hex()}"
            )

    def test_unicode_nfc_normalization_equivalence(self):
        """NFC and NFD forms of same string must produce identical output.

        This is critical for cross-language compatibility:
        - macOS HFS+ uses NFD by default
        - Windows/Linux use NFC
        - Without normalization, same filename could hash differently!
        """
        # "café" in NFC (single codepoint é)
        nfc = {"name": "caf\u00e9"}
        # "café" in NFD (e + combining acute)
        nfd = {"name": "cafe\u0301"}

        result_nfc = canonical_json(nfc)
        result_nfd = canonical_json(nfd)

        assert result_nfc == result_nfd, (
            "Unicode NFC normalization failed: "
            f"NFC={result_nfc!r}, NFD={result_nfd!r}"
        )

    def test_key_ordering_deterministic(self):
        """Key order must be deterministic regardless of Python dict order."""
        # Create dicts with different insertion orders
        dict1 = {"z": 1, "a": 2, "m": 3}
        dict2 = {"a": 2, "z": 1, "m": 3}
        dict3 = {"m": 3, "z": 1, "a": 2}

        result1 = canonical_json(dict1)
        result2 = canonical_json(dict2)
        result3 = canonical_json(dict3)

        assert result1 == result2 == result3, (
            "Key ordering not deterministic: "
            f"{result1!r} != {result2!r} != {result3!r}"
        )


# =============================================================================
# Hash Payload Tests
# =============================================================================


class TestHashPayload:
    """Test BLAKE3 payload hashing over canonical JSON."""

    @pytest.mark.parametrize(
        "case",
        VECTORS["hash_payload"]["cases"],
        ids=lambda c: c["name"],
    )
    def test_hash_payload_vectors(self, case):
        """Payload hash must match expected BLAKE3 digest."""
        # First verify canonical form
        canonical = canonical_json(case["payload"])
        assert canonical.decode("utf-8") == case["expected_canonical"], (
            f"Canonical form mismatch for '{case['name']}'"
        )

        payload_hash, alg = hash_payload(case["payload"])

        assert alg == "blake3", f"Expected blake3, got {alg}"
        assert payload_hash == case["expected_hash_blake3"], (
            f"BLAKE3 hash mismatch for '{case['name']}': "
            f"expected {case['expected_hash_blake3']}, got {payload_hash}"
        )

    def test_hash_determinism(self):
        """Same payload must always produce same hash."""
        payload = {"event": "test", "timestamp": "2025-01-24T00:00:00Z"}

        hashes = [hash_payload(payload)[0] for _ in range(100)]

        assert len(set(hashes)) == 1, "Hash is not deterministic!"

    def test_hash_sensitivity(self):
        """Tiny changes must produce completely different hash."""
        payload1 = {"value": "test"}
        payload2 = {"value": "Test"}  # Capital T
        payload3 = {"value": "test "}  # Trailing space

        hash1, _ = hash_payload(payload1)
        hash2, _ = hash_payload(payload2)
        hash3, _ = hash_payload(payload3)

        assert hash1 != hash2, "Case change should affect hash"
        assert hash1 != hash3, "Whitespace should affect hash"
        assert hash2 != hash3, "Different changes should produce different hashes"


# =============================================================================
# Timestamp Conversion Tests
# =============================================================================


class TestTimestampConversion:
    """Test ISO timestamp to nanoseconds conversion."""

    @pytest.mark.parametrize(
        "case",
        VECTORS["timestamp_conversion"]["cases"],
        ids=lambda c: c["name"],
    )
    def test_timestamp_vectors(self, case):
        """Timestamp conversion must match expected nanoseconds."""
        result_ns = timestamp_to_nanos(case["iso"])

        assert result_ns == case["expected_ns"], (
            f"Timestamp conversion mismatch for '{case['name']}': "
            f"expected {case['expected_ns']}, got {result_ns}"
        )

    def test_timezone_normalization(self):
        """Different timezone representations of same instant must be equal."""
        # All represent the same instant: 2025-01-24 12:00:00 UTC
        timestamps = [
            "2025-01-24T12:00:00+00:00",
            "2025-01-24T12:00:00Z",
            "2025-01-24T13:00:00+01:00",
            "2025-01-24T07:00:00-05:00",
            "2025-01-24T20:00:00+08:00",
        ]

        # Handle Z suffix by replacing with +00:00
        def normalize(ts):
            return ts.replace("Z", "+00:00") if ts.endswith("Z") else ts

        ns_values = [timestamp_to_nanos(normalize(ts)) for ts in timestamps]

        assert len(set(ns_values)) == 1, (
            f"Timezone normalization failed: {dict(zip(timestamps, ns_values, strict=True))}"
        )

    def test_microsecond_precision(self):
        """Microsecond precision must be preserved (Python's max)."""
        ts = "2025-01-24T12:00:00.123456+00:00"
        ns = timestamp_to_nanos(ts)

        # Extract microseconds from nanoseconds
        us = (ns % 1_000_000_000) // 1000

        assert us == 123456, f"Microsecond precision lost: expected 123456, got {us}"


# =============================================================================
# Entry Hash Tests
# =============================================================================


class TestEntryHash:
    """Test entry hash computation for chain linking."""

    @pytest.mark.parametrize(
        "case",
        VECTORS["entry_hash"]["cases"],
        ids=lambda c: c["name"],
    )
    def test_entry_hash_vectors(self, case):
        """Entry hash must match expected BLAKE3 digest."""
        entry_hash, alg = compute_entry_hash(
            seq=case["seq"],
            timestamp_ns=case["timestamp_ns"],
            prev_hash=case["prev_hash"],
            payload_hash=case["payload_hash"],
        )

        assert alg == "blake3", f"Expected blake3, got {alg}"
        assert entry_hash == case["expected_entry_hash"], (
            f"Entry hash mismatch for '{case['name']}': "
            f"expected {case['expected_entry_hash']}, got {entry_hash}"
        )

    @pytest.mark.parametrize(
        "case",
        VECTORS["entry_hash"]["cases"],
        ids=lambda c: c["name"],
    )
    def test_entry_hash_payload_ref_consistency(self, case):
        """Verify _payload_ref matches actual hash_payload vectors."""
        if "_payload_ref" not in case:
            pytest.skip("No _payload_ref in this case")

        # Parse reference like "hash_payload.simple_event"
        ref = case["_payload_ref"]
        section, name = ref.split(".")

        # Find referenced case
        ref_case = next(
            (c for c in VECTORS[section]["cases"] if c["name"] == name),
            None
        )
        assert ref_case is not None, f"Referenced case not found: {ref}"

        # Verify payload_hash matches
        assert case["payload_hash"] == ref_case["expected_hash_blake3"], (
            f"payload_hash in '{case['name']}' doesn't match {ref}: "
            f"expected {ref_case['expected_hash_blake3']}, got {case['payload_hash']}"
        )

    def test_entry_hash_format(self):
        """Entry hash must use BLAKE3 and return 64-char hex."""
        entry_hash, alg = compute_entry_hash(
            seq=1,
            timestamp_ns=1737720000000000000,
            prev_hash="0" * 64,
            payload_hash="a" * 64,
        )

        assert alg == "blake3", f"Expected blake3, got {alg}"
        assert len(entry_hash) == 64, f"Expected 64-char hex, got {len(entry_hash)}"

    def test_entry_hash_determinism(self):
        """Same inputs must produce same entry hash."""
        kwargs = {
            "seq": 1,
            "timestamp_ns": 1737720000000000000,
            "prev_hash": "0" * 64,
            "payload_hash": "ba0ec9bd9cf1b301fae5608349497d6ac27dd1ea071ed9469b8894ba58f385b8",
        }

        hashes = [compute_entry_hash(**kwargs)[0] for _ in range(100)]

        assert len(set(hashes)) == 1, "Entry hash is not deterministic!"

    def test_entry_hash_field_sensitivity(self):
        """Each field must affect the entry hash."""
        base = {
            "seq": 1,
            "timestamp_ns": 1737720000000000000,
            "prev_hash": "0" * 64,
            "payload_hash": "a" * 64,
        }

        base_hash, _ = compute_entry_hash(**base)

        # Change each field and verify hash changes
        variations = [
            {"seq": 2},
            {"timestamp_ns": 1737720000000000001},
            {"prev_hash": "1" + "0" * 63},
            {"payload_hash": "b" + "a" * 63},
        ]

        for var in variations:
            modified = {**base, **var}
            mod_hash, _ = compute_entry_hash(**modified)
            assert mod_hash != base_hash, f"Changing {list(var.keys())} should affect hash"

    def test_entry_hash_rejects_non_blake3(self):
        """Entry hash must reject non-BLAKE3 algorithms."""
        with pytest.raises(ValueError, match="must use BLAKE3"):
            compute_entry_hash(
                seq=1,
                timestamp_ns=1737720000000000000,
                prev_hash="0" * 64,
                payload_hash="a" * 64,
                algorithm="sha256",
            )


# =============================================================================
# Signature Verification Tests
# =============================================================================


class TestSignatureVerification:
    """Test Ed25519 signature verification with known vectors."""

    @pytest.mark.parametrize(
        "case",
        VECTORS["signature_verification"]["cases"],
        ids=lambda c: c["name"],
    )
    def test_rfc8032_vectors(self, case):
        """Ed25519 signatures must match RFC 8032 test vectors."""
        # Load keys
        private_key = SigningKey.from_seed_bytes(
            bytes.fromhex(case["private_key_hex"]),
            key_id="test",
        )
        public_key = VerifyingKey.from_hex(
            case["public_key_hex"],
            key_id="test",
        )

        # Verify public key derivation
        derived_pub = private_key.public_key()
        assert derived_pub.to_hex() == case["public_key_hex"], (
            "Public key derivation mismatch"
        )

        # Sign message
        message = bytes.fromhex(case["message_hex"])
        signature = private_key.sign(message)

        assert signature.hex() == case["signature_hex"], (
            f"Signature mismatch for '{case['name']}': "
            f"expected {case['signature_hex']}, got {signature.hex()}"
        )

        # Verify signature
        assert public_key.verify(signature, message), (
            f"Signature verification failed for '{case['name']}'"
        )

    def test_signature_tampering_detection(self):
        """Tampered signatures must fail verification."""
        key = SigningKey.generate(key_id="test")
        message = b"important message"
        signature = key.sign(message)

        # Tamper with signature (flip one bit)
        tampered = bytearray(signature)
        tampered[0] ^= 0x01
        tampered = bytes(tampered)

        assert not key.public_key().verify(tampered, message), (
            "Tampered signature should fail verification"
        )

    def test_message_tampering_detection(self):
        """Signatures on tampered messages must fail verification."""
        key = SigningKey.generate(key_id="test")
        message = b"important message"
        signature = key.sign(message)

        # Tamper with message
        tampered_message = b"Important message"  # Capital I

        assert not key.public_key().verify(signature, tampered_message), (
            "Signature on tampered message should fail verification"
        )


# =============================================================================
# Corrupted WAL Handling Tests
# =============================================================================


class TestCorruptedWalHandling:
    """Test handling of corrupted/malformed WAL entries."""

    @pytest.mark.parametrize(
        "case",
        [c for c in VECTORS["corrupted_wal"]["cases"] if c.get("should_skip")],
        ids=lambda c: c["name"],
    )
    def test_malformed_json_detection(self, case):
        """Malformed JSON lines should be detected and skipped."""
        line = case["line"]

        # These should fail JSON parsing
        if case.get("should_skip"):
            try:
                result = json.loads(line) if line.strip() else None
                if result is None:
                    pass  # Empty line correctly handled
                else:
                    pytest.fail(f"Expected JSON parse failure for: {line!r}")
            except json.JSONDecodeError:
                pass  # Expected

    def test_valid_json_parsing(self):
        """Valid JSON lines should parse correctly."""
        case = next(
            c for c in VECTORS["corrupted_wal"]["cases"]
            if c["name"] == "valid_minimal"
        )

        # Valid JSON should parse
        data = json.loads(case["line"])
        assert data["event"] == "test", "Valid JSON should parse correctly"
