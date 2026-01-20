# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**security@eulbite.com**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

Please include the following information in your report:

- Type of vulnerability (e.g., signature bypass, hash collision, chain manipulation)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment (what an attacker could achieve)

## Security Model

Spine's security relies on:

1. **Ed25519 signatures**: Each WAL entry is signed at the source
2. **BLAKE3 hash chains**: Entries are cryptographically linked
3. **Client-side verification**: The CLI verifies without trusting any server

### In Scope

- Signature forgery or bypass
- Hash chain manipulation without detection
- Timestamp manipulation attacks
- Key extraction from WAL files
- Denial of service through malformed WAL files

### Out of Scope

- Attacks requiring physical access to the signing machine
- Social engineering
- Attacks on the optional Spine server (report to separate channel)

## Preferred Languages

We prefer all communications to be in English.

## Disclosure Policy

We follow coordinated disclosure:

1. Reporter sends vulnerability details
2. We acknowledge within 48 hours
3. We investigate and develop a fix
4. We coordinate disclosure timing with reporter
5. We release fix and publish advisory
6. Reporter may publish details after fix is released

## Recognition

We maintain a security acknowledgments section in our release notes for researchers who responsibly disclose vulnerabilities.
