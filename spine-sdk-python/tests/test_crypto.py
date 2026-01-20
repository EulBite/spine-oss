# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 Eul Bite

"""Basic tests for crypto module."""

from spine_client.crypto import (
    SigningKey,
    canonical_json,
    hash_payload,
)


def test_canonical_json_sorts_keys():
    """Canonical JSON should sort keys alphabetically."""
    obj = {"b": 1, "a": 2, "c": 3}
    result = canonical_json(obj)
    # canonical_json returns bytes
    assert result == b'{"a":2,"b":1,"c":3}'


def test_canonical_json_no_whitespace():
    """Canonical JSON should have no unnecessary whitespace."""
    obj = {"key": "value", "nested": {"inner": 123}}
    result = canonical_json(obj)
    # canonical_json returns bytes
    assert b" " not in result
    assert b"\n" not in result


def test_canonical_json_unicode_normalization():
    """Unicode strings should be NFC normalized."""
    # é as single codepoint vs e + combining accent
    obj1 = {"name": "caf\u00e9"}  # NFC form
    obj2 = {"name": "cafe\u0301"}  # NFD form (e + combining acute)

    result1 = canonical_json(obj1)
    result2 = canonical_json(obj2)

    # Both should normalize to the same canonical form
    assert result1 == result2


def test_hash_payload_deterministic():
    """Same payload should always produce same hash."""
    payload = {"event": "test", "value": 123}

    hash1, alg1 = hash_payload(payload)
    hash2, alg2 = hash_payload(payload)

    assert hash1 == hash2
    assert alg1 == alg2


def test_hash_payload_different_for_different_input():
    """Different payloads should produce different hashes."""
    payload1 = {"event": "test1"}
    payload2 = {"event": "test2"}

    hash1, _ = hash_payload(payload1)
    hash2, _ = hash_payload(payload2)

    assert hash1 != hash2


def test_signing_key_generate():
    """Should be able to generate a new signing key."""
    key = SigningKey.generate()
    assert key is not None
    # public_key() is a method, not a property
    assert key.public_key() is not None


def test_signing_key_sign_and_verify():
    """Signatures should be verifiable."""
    key = SigningKey.generate()
    message = b"test message"

    signature = key.sign(message)
    assert signature is not None

    # Verify with public key - verify(signature, data) order
    is_valid = key.public_key().verify(signature, message)
    assert is_valid


def test_signing_key_wrong_signature_fails():
    """Wrong signature should fail verification."""
    key = SigningKey.generate()
    message = b"test message"

    signature = key.sign(message)

    # Tamper with the message
    wrong_message = b"wrong message"
    is_valid = key.public_key().verify(signature, wrong_message)
    assert not is_valid
