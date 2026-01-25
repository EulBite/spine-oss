# Spine

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776ab.svg)](https://www.python.org/downloads/)
[![Rust 1.75+](https://img.shields.io/badge/Rust-1.75+-dea584.svg)](https://www.rust-lang.org/)

**Tamper-proof audit logs you can verify yourself — no trusted third party required.**

Spine creates cryptographically signed audit trails that prove your logs haven't been modified. When regulators ask "can you prove no one touched these logs?", you can.

```
spine-cli verify --wal ./audit_log

SPINE WAL VERIFICATION REPORT
=============================
Status:              VALID
Events verified:     847
Signatures verified: 847
Chain integrity:     INTACT
```

---

## Why Spine Exists

### The Compliance Problem

Regulations like **DORA**, **NIS2**, **SOC 2**, and **GDPR** increasingly require *proof* that audit logs are immutable — not just promises. Traditional SIEM solutions (Splunk, ELK, Datadog) store logs, but they can't cryptographically prove those logs weren't altered after the fact.

When an incident happens, you need to demonstrate:
- No one deleted inconvenient entries
- No one modified timestamps
- The sequence of events is authentic

**Spine gives you that proof.**

### The Trust Problem

Most audit systems require you to trust:
- The vendor's servers
- The vendor's employees
- The vendor's security practices

With Spine, verification is **local and independent**. The CLI runs on your machine, uses standard cryptography (Ed25519 + BLAKE3), and doesn't phone home. You don't have to trust us — you can verify the math yourself.

### The Vendor Lock-in Problem

Your audit data is too important to be trapped in a proprietary format. Spine's WAL format is [fully documented](./docs/WAL_FORMAT.md), and the verification tool is open source. Even if Spine disappears tomorrow, your audit logs remain verifiable forever.

---

## Who Should Use Spine

| Role | Pain Point | How Spine Helps |
|------|-----------|-----------------|
| **Compliance Officers** | "Prove logs weren't tampered with" | Cryptographic chain of custody |
| **Security Engineers** | Post-incident forensics credibility | Independent, verifiable audit trail |
| **DevOps / SRE** | Audit requirements without operational overhead | Drop-in SDK, local-first architecture |
| **External Auditors** | Verifying client claims independently | Run verification without vendor access |
| **Legal / Risk Teams** | Evidence integrity for litigation | Mathematically provable log integrity |

### Industries

- **Financial Services** — DORA, MiFID II, SOX compliance
- **Healthcare** — HIPAA audit trails, access logging
- **Government / Defense** — Classified system logging, chain of custody
- **Critical Infrastructure** — SCADA/ICS event logging, NIS2 compliance
- **SaaS / Cloud** — SOC 2 Type II, customer audit requirements

---

## Try It in 5 Minutes

### 1. Install the Python SDK

```bash
pip install spine-client
```

### 2. Create Signed Audit Logs

```python
from spine_client import WAL, WALConfig, SigningKey

key = SigningKey.generate()
wal = WAL(key, WALConfig(data_dir="./audit_log"))
await wal.initialize()

# Every event is signed and hash-chained
await wal.append({"event": "user.login", "user": "alice", "ip": "10.0.1.42"})
await wal.append({"event": "data.export", "records": 1547, "user": "alice"})
```

### 3. Verify Independently

```bash
# Build the verifier (requires Rust)
cd spine-cli && cargo build --release

# Verify your logs — no server, no network, no trust required
./target/release/spine-cli verify --wal ../audit_log
```

**That's it.** Your audit logs are now cryptographically verifiable.

---

## How It Works

```
+------------------+     +------------------+     +------------------+
|  Your App        | --> |  Spine SDK       | --> |  WAL Files       |
|                  |     |  (signs events)  |     |  (JSONL, local)  |
+------------------+     +------------------+     +------------------+
                                                          |
                                                          v
                                                  +------------------+
                                                  |  spine-cli       |
                                                  |  (verify)        |
                                                  +------------------+
                                                          |
                                                          v
                                                  VALID / TAMPERED
```

Each audit event is:
1. **Signed** with Ed25519 (your private key)
2. **Hash-chained** with BLAKE3 (links to previous event)
3. **Timestamped** with nanosecond precision
4. **Sequenced** with monotonic counter

Tampering with any event breaks the chain. The CLI detects:
- Modified content (signature fails)
- Deleted events (sequence gap)
- Reordered events (hash chain breaks)
- Inserted events (signature invalid)

---

## Optional: Spine Server

The open-source SDK and CLI work **completely standalone** — no server required.

For additional guarantees, you can deploy Spine Server (on-premise) to get:
- **Third-party timestamps** — Prove events existed at a specific time
- **Off-site backup** — Redundant storage for disaster recovery
- **Multi-party attestation** — Server receipts as independent witness

Your data stays in your infrastructure. The server adds a timestamp witness, not a trust dependency.

[Learn more about Spine Server →](https://eulbite.com/spine)

---

## Documentation

| Document | Description |
|----------|-------------|
| [WAL Format Specification](./docs/WAL_FORMAT.md) | Complete format spec for implementers |
| [Key Management Guide](./docs/KEY_MANAGEMENT.md) | Key generation, rotation, revocation |
| [Threat Model](./docs/THREAT_MODEL.md) | What Spine protects against (and doesn't) |
| [Test Vectors](./test-vectors/) | Cross-implementation verification |
| [Python SDK Docs](./spine-sdk-python/) | Full API reference |
| [CLI Reference](./spine-cli/) | All verification commands |

---

## Components

| Component | Language | Purpose |
|-----------|----------|---------|
| [spine-sdk-python](./spine-sdk-python/) | Python 3.10+ | Create signed audit logs |
| [spine-cli](./spine-cli/) | Rust 1.75+ | Verify log integrity |

---

## Get Involved

- **Questions?** [Open a discussion](https://github.com/EulBite/spine-oss/discussions)
- **Found a bug?** [File an issue](https://github.com/EulBite/spine-oss/issues)
- **Security issue?** Email security@eulbite.com (not public issues)
- **Want to contribute?** PRs welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md)

---

## License

Apache License 2.0 — Use it, modify it, ship it.

The SDK, CLI, and format specification are fully open source. The Spine Server is a separate commercial product.

---

<p align="center">
  <a href="https://eulbite.com/spine">Product Page</a> ·
  <a href="./docs/WAL_FORMAT.md">Format Spec</a> ·
  <a href="https://github.com/EulBite/spine-oss/issues">Report Issue</a>
</p>
