# Spine Test Vectors

This directory contains canonical test vectors for implementing and verifying
Spine-compatible clients in any language.

## Purpose

Test vectors ensure deterministic, cross-implementation compatibility for:
- Canonical JSON serialization (with Unicode NFC normalization)
- Payload hashing (BLAKE3)
- Entry hash computation (chain linking)
- Ed25519 signature generation and verification

## Files

- `vectors.json` - Machine-readable test vectors
- `README.md` - This documentation

## Using Test Vectors

### 1. Canonical JSON

Given an input payload, your implementation must produce the exact same byte
sequence as specified in `expected_canonical_json`.

Key rules:
- Unicode NFC normalization applied to all strings
- Keys sorted lexicographically (Unicode code points)
- No whitespace
- UTF-8 encoded output

### 2. Payload Hash

```
payload_hash = BLAKE3(canonical_json(payload))
```

Output: 64-character lowercase hex string (256 bits).

### 3. Entry Hash

The entry hash links records in the chain and is what gets signed:

```
entry_hash = BLAKE3(
    seq.to_le_bytes(8) ||           // u64 little-endian
    timestamp_ns.to_le_bytes(8) ||  // i64 little-endian
    prev_hash.as_utf8_bytes() ||    // hex string as UTF-8
    payload_hash.as_utf8_bytes()    // hex string as UTF-8
)
```

### 4. Signature

```
signature = Ed25519_Sign(private_key, entry_hash.as_utf8_bytes())
```

The signature covers the hex-encoded entry hash as UTF-8 bytes.

## Verification Checklist

Your implementation is correct if:

1. `canonical_json(test.payload) == test.expected_canonical_json`
2. `BLAKE3(canonical_json) == test.expected_payload_hash`
3. `compute_entry_hash(...) == test.expected_entry_hash`
4. `Ed25519_Verify(public_key, entry_hash, signature) == true`

## Format Version

These vectors are for WAL format version 1.
