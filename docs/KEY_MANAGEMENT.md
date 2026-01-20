# Key Management Guide

This document describes key management best practices for Spine SDK, including
key generation, rotation, and revocation procedures.

## Overview

Spine uses Ed25519 keys for client-side signing:
- **Signing Key** (private): Used to sign WAL entries
- **Verifying Key** (public): Stored in records for offline verification

Each key has a `key_id` (e.g., `kid_a1b2c3d4`) for tracking and rotation.

## Key Lifecycle

```
Generate --> Active --> Rotate (new key) --> Revoked (archived)
```

## Key Generation

### Python SDK

```python
from spine_client import SigningKey

# Generate new key with auto-generated ID
key = SigningKey.generate()
print(f"Key ID: {key.key_id}")           # kid_a1b2c3d4e5f6g7h8
print(f"Public: {key.public_key().to_hex()}")

# Generate with custom ID (for tracking)
key = SigningKey.generate(key_id="kid_production_2025_01")

# Export for secure storage
private_pem = key.to_pem()
private_bytes = key.to_bytes()  # 32 bytes
```

### Storage Recommendations

| Environment | Storage Method |
|-------------|----------------|
| Development | Local file (encrypted) |
| Production | HSM, AWS KMS, HashiCorp Vault |
| CI/CD | Secrets manager (GitHub Secrets, etc.) |

**NEVER** store private keys in:
- Version control
- Environment variables in logs
- Unencrypted files
- Client-side storage (browser, mobile app)

## Key Rotation

### When to Rotate

1. **Scheduled rotation** (recommended: every 90 days)
2. **Personnel changes** (employee leaves, role change)
3. **Security incident** (suspected compromise)
4. **Compliance requirements** (SOC 2, HIPAA, etc.)

### Rotation Procedure

```python
from spine_client import SigningKey, WAL, WALConfig

# 1. Generate new key
new_key = SigningKey.generate(key_id="kid_production_2025_02")

# 2. Create new WAL instance with new key
# Note: Each key has its own stream (chain)
config = WALConfig(data_dir="/var/spine/audit")
new_wal = WAL(new_key, config, namespace="production")
await new_wal.initialize()

# 3. Old WAL continues to be readable
# (public keys are stored in each record)

# 4. Archive old key securely (don't delete immediately)
# Keep for verification of historical records
```

### Rotation Timeline

```
Day 0:  Generate new key
Day 1:  Deploy new key to production
Day 1:  Old key stops signing new records
Day 30: Monitor for any issues
Day 90: Archive old key to cold storage
```

## Key Revocation

### Revocation Scenarios

1. **Key Compromise**: Private key exposed or stolen
2. **Unauthorized Access**: Key used by unauthorized party
3. **Policy Violation**: Key used outside approved scope

### Immediate Response (Compromise)

```bash
# 1. IMMEDIATELY stop using compromised key
# 2. Generate replacement key
# 3. Update all systems to use new key
# 4. Document the incident
```

### Revocation List

Spine does not have a built-in revocation list (like X.509 CRL). Instead:

#### Option 1: Application-Level Revocation

```python
# Maintain a revocation list in your application
REVOKED_KEYS = {
    "kid_compromised_001": {
        "revoked_at": "2025-01-15T10:00:00Z",
        "reason": "Key compromise - employee laptop stolen",
        "valid_until": "2025-01-15T09:59:59Z",  # Records before this are still valid
    }
}

def verify_record_with_revocation(record, revoked_keys):
    """Verify record, checking revocation status."""
    if record.key_id in revoked_keys:
        revocation = revoked_keys[record.key_id]
        record_time = parse_iso(record.ts_client)
        valid_until = parse_iso(revocation["valid_until"])

        if record_time > valid_until:
            raise SecurityError(
                f"Record signed with revoked key {record.key_id} "
                f"after revocation time {revocation['revoked_at']}"
            )
        # Records before revocation are still valid

    # Continue with normal verification
    return verify_record(record)
```

#### Option 2: Spine Server Enforcement (On-Premise)

With Spine server deployed on-premise, revocation is enforced server-side:
- Server maintains revocation list in your infrastructure
- Rejects records signed with revoked keys
- Returns error with revocation reason
- All data stays within your network perimeter

### Post-Revocation Verification

Records signed **before** revocation remain valid and verifiable:

```python
# Historical records are valid if:
# 1. Signature is cryptographically valid
# 2. Record timestamp is before revocation time
# 3. Chain integrity is intact

# Example verification with revocation check
from spine_client import verify_wal

result = await verify_wal(wal, revoked_keys=REVOKED_KEYS)
if not result.valid:
    print(f"Verification failed: {result.message}")
```

### Incident Documentation

When revoking a key, document:

```yaml
incident_report:
  key_id: "kid_compromised_001"
  public_key: "d75a980182b10ab7..."
  revoked_at: "2025-01-15T10:00:00Z"
  discovered_at: "2025-01-15T09:30:00Z"

  reason: "Key compromise"
  details: |
    Employee laptop containing unencrypted key backup was stolen.
    Key was used for production audit logging from 2024-06-01.

  impact_assessment:
    records_potentially_affected: 150000
    time_range: "2024-06-01 to 2025-01-15"
    unauthorized_signatures_found: 0

  remediation:
    - Generated replacement key kid_production_2025_02
    - Deployed to all production systems
    - Enabled full-disk encryption policy
    - Rotated to HSM-based key storage

  valid_records_before: "2025-01-15T09:59:59Z"
```

## Multi-Key Architecture (Advanced)

For high-security environments, consider:

### Separate Keys by Environment

```
kid_dev_2025_01     → Development
kid_staging_2025_01 → Staging
kid_prod_2025_01    → Production
```

### Separate Keys by Service

```
kid_auth_service_01    → Authentication events
kid_payment_service_01 → Payment events
kid_admin_service_01   → Admin operations
```

### Key Hierarchy

```
Root Key (offline, HSM)
  |
  +-- Intermediate Key 1 (signs daily keys)
  |     +-- Daily Key 2025-01-15
  |     +-- Daily Key 2025-01-16
  |
  +-- Intermediate Key 2 (backup)
```

## Future: Quorum Signing (Roadmap)

Planned support for m-of-n signing:

```python
# Future API (not yet implemented)
quorum_config = QuorumConfig(
    threshold=2,  # 2 of 3 signatures required
    keys=[key1, key2, key3]
)

record = await wal.append(payload, quorum=quorum_config)
# record.signatures = [sig1, sig2]  # Any 2 of 3
```

## Security Checklist

- [ ] Private keys stored securely (HSM/KMS/Vault)
- [ ] Key rotation schedule defined (90 days recommended)
- [ ] Revocation procedure documented
- [ ] Incident response plan includes key compromise
- [ ] Audit trail for key operations
- [ ] Backup keys in secure cold storage
- [ ] Different keys for different environments
- [ ] Key access logged and monitored

## Related Documentation

- [WAL Format Specification](./WAL_FORMAT.md)
- [Test Vectors](../test-vectors/README.md)
- [Verification Guide](./VERIFICATION.md)
