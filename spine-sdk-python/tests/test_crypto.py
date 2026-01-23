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


def test_signing_key_from_file_pem(tmp_path):
    """Should load key from PEM file."""
    # Generate and save key
    original = SigningKey.generate(key_id="test-key")
    pem_path = tmp_path / "test.pem"
    original.save_to_file(pem_path, key_format="pem")

    # Load and verify
    loaded = SigningKey.from_file(pem_path)
    assert loaded.key_id == "test"  # Uses filename stem

    # Verify keys are functionally equivalent
    message = b"test message"
    sig = original.sign(message)
    assert loaded.public_key().verify(sig, message)


def test_signing_key_from_file_hex(tmp_path):
    """Should load key from hex file."""
    original = SigningKey.generate(key_id="hex-key")
    hex_path = tmp_path / "test.hex"
    original.save_to_file(hex_path, key_format="hex")

    loaded = SigningKey.from_file(hex_path, key_id="custom-id")
    assert loaded.key_id == "custom-id"

    # Verify keys match
    message = b"test"
    sig = original.sign(message)
    assert loaded.public_key().verify(sig, message)


def test_signing_key_from_file_raw(tmp_path):
    """Should load key from raw binary file."""
    original = SigningKey.generate()
    raw_path = tmp_path / "test.raw"
    original.save_to_file(raw_path, key_format="raw")

    loaded = SigningKey.from_file(raw_path, key_id="raw-key")

    # Verify keys match
    message = b"raw test"
    sig = original.sign(message)
    assert loaded.public_key().verify(sig, message)


def test_signing_key_from_env_hex(monkeypatch):
    """Should load key from environment variable (hex format)."""
    original = SigningKey.generate()
    hex_key = original.to_bytes().hex()

    monkeypatch.setenv("SPINE_SIGNING_KEY", hex_key)
    monkeypatch.setenv("SPINE_KEY_ID", "env-key")

    loaded = SigningKey.from_env()
    assert loaded.key_id == "env-key"

    # Verify keys match
    message = b"env test"
    sig = original.sign(message)
    assert loaded.public_key().verify(sig, message)


def test_signing_key_from_env_missing(monkeypatch):
    """Should raise error if env var not set."""
    monkeypatch.delenv("SPINE_SIGNING_KEY", raising=False)

    import pytest
    with pytest.raises(ValueError, match="not set"):
        SigningKey.from_env()


def test_signing_key_roundtrip_all_formats(tmp_path):
    """Key should survive roundtrip through all formats."""
    original = SigningKey.generate(key_id="roundtrip")
    message = b"roundtrip test"
    original_sig = original.sign(message)

    for fmt in ["pem", "hex", "raw"]:
        path = tmp_path / f"key.{fmt}"
        original.save_to_file(path, key_format=fmt)
        loaded = SigningKey.from_file(path, key_id=f"loaded-{fmt}")

        # Must verify original signature
        assert loaded.public_key().verify(original_sig, message)

        # Must produce valid signatures
        new_sig = loaded.sign(message)
        assert original.public_key().verify(new_sig, message)
