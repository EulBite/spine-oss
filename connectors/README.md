# Spine Connectors

Connectors that bridge Spine cryptographic audit logs to compliance platforms (Vanta, Drata, etc.).

## Available Connectors

| Connector | Platform | Status |
|-----------|----------|--------|
| [vanta](./vanta/) | Vanta | ✅ Ready |
| drata | Drata | 🚧 Planned |
| servicenow | ServiceNow | 🚧 Planned |

## Quick Start

### Vanta Connector

```bash
# Install
cd connectors/vanta
npm install

# Generate attestation (dry-run)
npx spine-vanta --dry-run --data-dir /path/to/wal

# Upload to Vanta
npx spine-vanta --upload attestation.json --api-token $VANTA_API_TOKEN
```

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌────────────┐
│  Your App   │────▶│  Spine WAL   │────▶│  Connector  │────▶│ Compliance │
│  (Events)   │     │  (Tamper-    │     │  (Export +  │     │  Platform  │
│             │     │   proof)     │     │   Upload)   │     │  (Vanta)   │
└─────────────┘     └──────────────┘     └─────────────┘     └────────────┘
```

1. **Your app** logs audit events to Spine WAL (hash-chained, signed)
2. **Connector** generates cryptographic attestation
3. **Attestation** uploaded to compliance platform as evidence

## Attestation Format

```json
{
  "version": "1.0",
  "type": "spine.attestation.v1",
  "attestation_id": "39921f1ee8ff9f5a",
  "period": {
    "start": "2026-01-01T00:00:00Z",
    "end": "2026-01-31T23:59:59Z"
  },
  "count": 1523,
  "verification": {
    "status": "VERIFIED"
  },
  "signature": {
    "algo": "ed25519",
    "value": "base64..."
  }
}
```

## Screenshots

### 1. Generate Attestation (--dry-run)
![Dry Run](./screenshots/01-dry-run.png)

```bash
$ npx spine-vanta --dry-run
{
  "version": "1.0",
  "type": "spine.attestation.v1",
  "attestation_id": "39921f1ee8ff9f5a",
  ...
}
```

### 2. Attestation with Signature
![Signed Attestation](./screenshots/02-signed-attestation.png)

The attestation includes an Ed25519 signature over canonical JSON of signed fields.

### 3. Upload to Vanta
![Upload Success](./screenshots/03-vanta-upload.png)

```bash
$ npx spine-vanta --upload attestation.json
Uploading to Vanta: spine-attestation-39921f1ee8ff9f5a.json
Upload successful. Document ID: doc_abc123
```

### 4. Evidence in Vanta Dashboard
![Vanta Dashboard](./screenshots/04-vanta-dashboard.png)

Attestation appears as document evidence in Vanta.

### 5. Verification Details
![Verification Details](./screenshots/05-verification-details.png)

Click to view full attestation JSON with cryptographic proof.

## Building a New Connector

1. Create directory: `connectors/<platform>/`
2. Use `spine-sdk-node` to generate attestations
3. Implement platform-specific upload logic
4. Add CLI with `--dry-run` and `--upload`

Example structure:
```
connectors/
├── vanta/
│   ├── package.json
│   ├── src/
│   │   └── cli.ts
│   └── dist/
└── <your-platform>/
    ├── package.json
    └── src/
        └── cli.ts
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VANTA_API_TOKEN` | Vanta API bearer token |
| `SPINE_DATA_DIR` | Default WAL data directory |
| `SPINE_KEY_FILE` | Default signing key file |

## API Reference

See [Spine Node SDK](../spine-node/) for core functionality:
- `WAL` - Write-ahead log for events
- `exportAttestation()` - Generate signed attestation
- `verify()` - Verify chain integrity

## License

Apache-2.0
