# Spine Vanta Connector

Upload Spine cryptographic attestations to Vanta as audit evidence.

## Installation

```bash
npm install spine-vanta-connector
```

Or from source:
```bash
cd connectors/vanta
npm install
npm run build
```

## Usage

### Generate Attestation (Dry Run)

```bash
# Print attestation JSON to stdout
npx spine-vanta --dry-run --data-dir ./my-wal

# Save to file
npx spine-vanta --dry-run > attestation.json
```

### Upload to Vanta

```bash
# Set API token
export VANTA_API_TOKEN=sk_xxx

# Upload attestation
npx spine-vanta --upload attestation.json
```

## CLI Reference

```
spine-vanta v0.1.0 - Spine Vanta Connector

USAGE:
  spine-vanta --dry-run [options]    Generate attestation JSON
  spine-vanta --upload <file.json>   Upload attestation to Vanta

OPTIONS:
  --data-dir <path>      WAL data directory (default: ./spine-data)
  --key-file <path>      Signing key JSON file (default: ./spine-key.json)
  --period-start <iso>   Period start (default: 24h ago)
  --period-end <iso>     Period end (default: now)
  --api-token <token>    Vanta API token (or VANTA_API_TOKEN env)
  --help, -h             Show help
  --version, -v          Show version
```

## Vanta API Setup

1. Go to Vanta Settings → Integrations → API
2. Create new API token with `documents:write` scope
3. Set `VANTA_API_TOKEN` environment variable

## Example Output

```json
{
  "version": "1.0",
  "type": "spine.attestation.v1",
  "attestation_id": "39921f1ee8ff9f5a",
  "period": {
    "start": "2026-01-25T00:00:00Z",
    "end": "2026-01-26T00:00:00Z"
  },
  "count": 1523,
  "verification": {
    "status": "VERIFIED",
    "tool": "spine-node/0.1.0"
  },
  "signature": {
    "algo": "ed25519",
    "format": "base64",
    "value": "tMUL46WTHObrEQ..."
  }
}
```

## License

Apache-2.0
