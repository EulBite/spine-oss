# Spine Threat Model

**Version**: 1.1
**Last Updated**: 2026-01-24
**Status**: Draft

## 1. Introduction

This document describes the threat model for Spine, an audit logging system with cryptographic integrity guarantees. It identifies protected assets, threat actors, trust assumptions, and security boundaries.

**Purpose**: Help users understand what Spine protects against—and what it does not.

## 2. System Overview

```
+---------------------------------------------------------------+
|                      Client Application                       |
|  +-------------+    +-------------+    +-------------------+  |
|  | SigningKey  |--->|    WAL      |--->|   SpineClient     |  |
|  |  (Ed25519)  |    |   (local)   |    | (HTTP to server)  |  |
|  +-------------+    +-------------+    +-------------------+  |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                        Spine Server                           |
|  +-------------+    +-------------+    +-------------------+  |
|  |   Receipt   |    |  Timestamp  |    |     Storage       |  |
|  | Generation  |    |  Authority  |    |   (encrypted)     |  |
|  +-------------+    +-------------+    +-------------------+  |
+---------------------------------------------------------------+
                              |
                              v
+---------------------------------------------------------------+
|                        Verification                           |
|  +-------------+    +-------------+                           |
|  |  spine-cli  |    | Python SDK  |  (independent verifier)   |
|  |   (Rust)    |    |  verify_*() |                           |
|  +-------------+    +-------------+                           |
+---------------------------------------------------------------+
```

## 3. Protected Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| **Event Integrity** | Audit events cannot be modified after signing | Critical |
| **Chain Ordering** | Events maintain cryptographic ordering (prev_hash linkage) | Critical |
| **Attribution** | Event is bound to signing key; accountability requires key custody controls | High (conditional) |
| **Timestamp Authenticity** | Server receipts provide authoritative timestamps | Medium |
| **Key Provenance** | Key rotation creates verifiable chain of trust | High |

> **Note on Attribution vs Non-Repudiation**: True non-repudiation requires (a) exclusive key control via HSM/KMS with policy enforcement, (b) robust identity↔key binding with attestation, and (c) revocation management. Without these, Spine provides *attribution* (event signed by key X) but not *non-repudiation* (person Y cannot deny signing). If the key was compromised, attribution to the original holder is contestable.

## 4. Threat Actors

### 4.1 External Attackers
- **Network attacker (internal/lateral)**: Adversary with access to internal network path between SDK and Spine API (compromised host, misconfigured proxy, insider)—capable of intercepting, delaying, dropping, or replaying traffic. Impact limited to availability/timing, not integrity (TLS + signatures).
- **Storage attacker**: Gains access to WAL files or server storage

### 4.2 Internal Threats
- **Malicious insider (client-side)**: Developer or operator with access to signing keys
- **Malicious insider (server-side)**: Operator with access to Spine server
- **Compromised application**: Application code that generates fraudulent events

### 4.3 Accidental Threats
- **Operational errors**: Accidental deletion, misconfiguration
- **Data corruption**: Disk failures, incomplete writes

## 5. Trust Assumptions

> ⚠️ **Critical**: Spine's security guarantees depend on these assumptions holding true.

| Assumption | Description | If Violated |
|------------|-------------|-------------|
| **A1: Signing key confidentiality** | Private signing key is not compromised | Attacker can forge signatures |
| **A2: Cryptographic algorithm security** | BLAKE3 and Ed25519 are secure | All integrity guarantees void |
| **A3: Client code integrity** | SDK is not maliciously modified | Events may be forged at source |
| **A4: Server honesty (for receipts)** | Server provides accurate timestamps | Receipt timestamps unreliable |
| **A5: Verifier independence** | spine-cli runs on trusted machine | Verification results unreliable |

### Trust Boundary Diagram

```
+----------------------------------------------------------------+
|                     FULLY TRUSTED ZONE                         |
|  - Signing key storage (HSM/KMS)                               |
|  - spine-cli verification environment                          |
+----------------------------------------------------------------+
                              |
                    Trust Boundary 1
                              |
+----------------------------------------------------------------+
|                   PARTIALLY TRUSTED ZONE                       |
|  - Client application (generates events)                       |
|  - Local WAL storage                                           |
|                                                                |
|  Trust: Integrity (via signatures)                             |
|  Distrust: May omit events, timestamps approximate             |
+----------------------------------------------------------------+
                              |
                    Trust Boundary 2
                              |
+----------------------------------------------------------------+
|                       EXTERNAL ZONE                            |
|  - Network (TLS required)                                      |
|  - Spine Server (provides receipts)                            |
|                                                                |
|  Trust: Timestamp authority (server receipts)                  |
|  Distrust: May be unavailable, could collude with client       |
+----------------------------------------------------------------+
```

### Timestamp Semantics

| Timestamp | Source | Trust Level | Assertion |
|-----------|--------|-------------|-----------|
| **event_time** | Client-provided | Untrusted | Claims when event occurred (can be fabricated) |
| **receipt_time** | Server-provided | Trusted per A4 | Server observed event no later than this time |
| **tsa_time** | RFC 3161 TSA | External trust | Third-party timestamp authority attestation |

> **Forensic interpretation**: A receipt proves the server received the event *no later than* `receipt_time`. It does NOT prove the event occurred at `event_time`. For regulatory compliance, use `receipt_time` as the authoritative timestamp; treat `event_time` as application metadata only.

## 6. Threats and Mitigations

### 6.1 Threats MITIGATED ✅

| Threat | Attack | Mitigation |
|--------|--------|------------|
| **T1: Post-write tampering** | Modify event payload after signing | BLAKE3 hash + Ed25519 signature; any modification invalidates signature |
| **T2: Event reordering** | Change chronological order of events | prev_hash chain links each event to predecessor; reordering breaks chain |
| **T3: Event insertion** | Insert fraudulent event into chain | Would require valid signature from compromised key AND correct prev_hash |
| **T4a: Mid-chain deletion** | Remove event from middle of chain | Creates gap in sequence numbers or breaks prev_hash linkage |
| **T4b: Tail truncation** | Remove events from end of chain | Detectable only with external reference (receipt, anchor, expected seq) |
| **T5: Replay attacks** | Resubmit old valid event | `event_id` (UUIDv7) + sequence numbers prevent duplicates; server enforces idempotency |
| **T6: Key substitution** | Claim event was signed by different key | public_key embedded in each record; key_id provides tracking |
| **T7: Timestamp backdating (client)** | Client claims event happened earlier | Server receipt provides independent timestamp authority |
| **T8: Cross-stream contamination** | Mix events from different streams | stream_id field isolates chains; verification is per-stream |

### 6.2 Threats PARTIALLY MITIGATED ⚠️

| Threat | Attack | Partial Mitigation | Residual Risk |
|--------|--------|-------------------|---------------|
| **T9: Silent event omission** | Never write certain events | Server receipts prove which events reached server | Events never written leave no trace |
| **T10: Key rotation attacks** | Inject forged rotation record | Rotation records require valid signature from current trusted key | First key in chain must be trusted out-of-band |
| **T11: Timestamp manipulation (server)** | Server provides false timestamp | Cross-verify with external timestamp authorities | Requires additional infrastructure |
| **T12: Network interception** | MITM captures traffic | TLS 1.2+ required, cert verification on, timeouts; SDK rejects plaintext HTTP | TLS misconfiguration; optional cert pinning for high-security |

### 6.3 Threats NOT MITIGATED ❌

| Threat | Attack | Why Not Mitigated | Recommendation |
|--------|--------|-------------------|----------------|
| **T13: Signing key compromise** | Attacker obtains private key | Cryptographic assumption; no defense once key is leaked | HSM/KMS, key rotation, monitoring |
| **T14: Event omission at source** | Application never calls log() | Spine cannot force application to log | Code review, testing, monitoring |
| **T15: Client-server collusion** | Both parties agree to falsify | No third-party witness | See Trust Ladder below |
| **T16: Compromised verification** | Attacker controls spine-cli | Verifier must be trusted | Run verification on isolated system |
| **T17: Denial of service** | Prevent logging by overwhelming system | Availability is not an integrity guarantee | Rate limiting, redundancy |
| **T18: Side-channel attacks** | Extract key via timing/power analysis | Not in scope for SDK | Use HSM for high-security deployments |

> **Note on T9/T14 (event omission)**: This limitation is fundamental to all append-only audit systems without mandatory interception at the application boundary. Spine cannot force an application to log—it can only guarantee integrity of events that *are* logged.

### 6.4 Supply Chain Threats 🔗

| Threat | Attack Vector | Mitigation |
|--------|--------------|------------|
| **S1: Typosquatting** | Malicious package with similar name on PyPI | Verify package name exactly (`spine-sdk-python`), use lockfiles |
| **S2: Dependency confusion** | Internal package name shadowed by public PyPI | Use scoped/namespaced packages, private index priority |
| **S3: Maintainer account hijack** | Compromised PyPI credentials | 2FA + hardware keys for org, limited publish permissions |
| **S4: Malicious release** | Attacker pushes backdoored version | Pin versions with hashes, verify signatures, audit updates |
| **S5: CI/CD compromise** | Injection in wheel/sdist build pipeline | SLSA provenance, reproducible builds, signed artifacts |
| **S6: Transitive dependency attack** | Compromised dependency of dependency | Minimal dependencies, hash pinning, lockfile with checksums |
| **S7: Malicious extras** | Attack via optional `[extra]` dependencies | Audit all extras before enabling, pin optional deps |

**Recommended Mitigations**:

1. **Hash pinning**: Use `pip-tools`, `poetry.lock`, or `uv.lock` with checksums
2. **Reproducible builds**: Verify wheel contents match source (where feasible)
3. **Release signing**: Sigstore/cosign attestations (when available)
4. **SLSA provenance**: GitHub Actions attestation for builds
5. **2FA enforcement**: Hardware keys for PyPI organization members
6. **Minimal dependencies**: Reduce attack surface (Spine uses few deps)
7. **Dependency audit**: Regular `pip-audit` / `safety` scans

### 6.5 Trust Ladder (Collusion Resistance) 📶

| Level | Mechanism | Protects Against | Cost/Complexity |
|-------|-----------|------------------|-----------------|
| **0** | Local WAL only | Accidental loss | Zero |
| **1** | Server receipts | Client tampering (single witness) | Low |
| **2** | Quorum receipts | Single server compromise (2+ independent endpoints) | Medium |
| **3** | RFC 3161 TSA | Client-server collusion (external timestamp authority) | Medium-High |
| **4** | Public anchoring | All parties colluding (blockchain/transparency log, daily batch) | High |

> **Recommendation**: Most deployments should use Level 1-2. Level 3+ only needed for regulatory compliance or adversarial environments where client and server may collude.

## 7. Attack Scenarios

### Scenario A: Disgruntled Employee

**Context**: Employee with access to application server wants to delete evidence of fraudulent transaction.

**Attack path**:
1. Access WAL files on disk
2. Delete or modify incriminating record
3. Hope no one notices

**Spine defense**:
- ✅ Modification detected: signature verification fails
- ✅ Deletion detected: sequence gap or broken prev_hash chain
- ✅ If synced: server has independent copy with receipt

**Residual risk**: If employee has access to signing key, they could append a "correction" event—but cannot modify history.

### Scenario B: Compromised Signing Key

**Context**: Attacker obtains signing key through phishing or server breach.

**Attack path**:
1. Generate fraudulent events with valid signatures
2. Inject into WAL or send directly to server

**Spine defense**:
- ⚠️ Signatures will be valid—cannot detect forgery
- ✅ Timestamps: fraudulent events will have recent timestamps
- ✅ Sequence: cannot inject into middle of existing chain

**Mitigation**: Immediate key rotation, revocation list, forensic analysis of timestamp anomalies.

### Scenario C: Malicious Insider (Server Operator)

**Context**: Spine server operator wants to help client hide events.

**Attack path**:
1. Delete events from server storage
2. Withhold receipts for certain events

**Spine defense**:
- ✅ Client has local WAL with signatures (client's proof)
- ⚠️ Missing receipts only prove server didn't acknowledge
- ❌ If both collude, no external witness

**Mitigation**: External timestamp anchoring, multi-party receipts, regulatory audits.

## 8. Security Boundaries Summary

| Boundary | Spine Guarantees | Spine Does NOT Guarantee |
|----------|------------------|--------------------------|
| **Data integrity** | Events immutable after signing | Events are truthful or complete |
| **Chronological order** | Cryptographic chain enforces order | Timestamps are accurate |
| **Attribution** | Signatures prove key holder signed | Key holder is who they claim |
| **Availability** | WAL provides offline resilience | System cannot be DoS'd |
| **Confidentiality** | (Not in scope) | Event contents are encrypted |

### Privacy Considerations

While Spine does not provide confidentiality guarantees, operators should be aware of privacy risks:

| Risk | Description | Mitigation |
|------|-------------|------------|
| **PII in payloads** | Application may inadvertently log sensitive data | Field allowlist, payload schema validation |
| **Metadata leakage** | `stream_id`, `key_id`, endpoints in logs/telemetry | Redact sensitive identifiers in error messages |
| **Credential exposure** | Secrets accidentally included in event payloads | Secret scanning (e.g., `detect-secrets`), pre-commit hooks |
| **Data minimization** | Logging more than necessary increases exposure | Define retention policy, log only required fields |

> **Recommendation**: Implement payload schema validation at the application layer. Use a field allowlist rather than blocklist. Set `max_payload_size` limits to prevent accidental large data dumps.

### Explicitly Out of Scope

The following threats are **not addressed** by Spine and require external controls:

| Threat | Why Out of Scope | External Control |
|--------|-----------------|------------------|
| **Malware on client** | SDK runs in compromised environment | Endpoint security, code signing |
| **Kernel/hypervisor compromise** | Below application layer | Secure boot, attestation |
| **System time rollback** | OS-level manipulation | NTP monitoring, secure time sources |
| **RNG compromise** | Weak randomness for key generation | Hardware RNG, entropy monitoring |
| **DNS/PKI attacks** | TLS relies on CA trust | Certificate pinning, CT logs |
| **Physical access** | Attacker with hardware access | Physical security, HSM |

## 9. Recommendations by Deployment Scenario

### Low Security (Development/Testing)
- Local signing key in encrypted file
- Self-signed TLS acceptable
- Single verification point

### Medium Security (Production SaaS)
- Signing keys in cloud KMS (AWS KMS, GCP KMS)
- Proper TLS certificate management
- Regular key rotation (90 days)
- Automated verification in CI/CD

### High Security (Financial/Regulatory)
- HSM for signing keys
- External timestamp authority (RFC 3161)
- Multi-party verification
- Air-gapped verification environment
- Consider blockchain anchoring for critical events

## 10. Incident Response

### If signing key is compromised:
1. **Immediately** rotate to new key
2. Mark compromised key_id in revocation list
3. Forensic analysis: identify events signed after compromise
4. Notify affected parties if regulatory requirement

### If WAL tampering detected:
1. Preserve evidence (copy of tampered files)
2. Compare with server-side records
3. Identify scope of tampering (which events affected)
4. Restore from server if available
5. Investigate root cause

## 11. References

- [WAL Format Specification](./WAL_FORMAT.md)
- [Key Management Guide](./KEY_MANAGEMENT.md)
- [RFC 8032 - Ed25519](https://tools.ietf.org/html/rfc8032)
- [BLAKE3 Specification](https://github.com/BLAKE3-team/BLAKE3-specs)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.1 | 2026-01-24 | Attribution vs non-repudiation clarification; Supply chain threats (S1-S7); T4 split (mid-chain vs tail); Timestamp semantics table; Trust Ladder (levels 0-4); Privacy considerations; Out of scope section; TLS hardening details |
| 1.0 | 2026-01-24 | Initial draft |
