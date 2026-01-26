#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

/**
 * Spine Vanta Connector CLI
 *
 * Usage:
 *   spine-vanta --dry-run [--data-dir <path>] [--key-file <path>]
 *   spine-vanta --upload <file.json> [--api-token <token>]
 */

import * as fs from 'fs';
import * as path from 'path';
import { SigningKey, WAL, exportAttestation, Attestation } from 'spine-sdk-node';

const VERSION = '0.1.0';
const VANTA_API_URL = 'https://api.vanta.com/v1/documents';

interface CliArgs {
  command: 'dry-run' | 'upload' | 'help' | 'version';
  dataDir?: string;
  keyFile?: string;
  uploadFile?: string;
  apiToken?: string;
  periodStart?: string;
  periodEnd?: string;
}

function parseArgs(args: string[]): CliArgs {
  const result: CliArgs = { command: 'help' };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '--dry-run':
        result.command = 'dry-run';
        break;
      case '--upload':
        result.command = 'upload';
        result.uploadFile = args[++i];
        break;
      case '--data-dir':
        result.dataDir = args[++i];
        break;
      case '--key-file':
        result.keyFile = args[++i];
        break;
      case '--api-token':
        result.apiToken = args[++i];
        break;
      case '--period-start':
        result.periodStart = args[++i];
        break;
      case '--period-end':
        result.periodEnd = args[++i];
        break;
      case '--help':
      case '-h':
        result.command = 'help';
        break;
      case '--version':
      case '-v':
        result.command = 'version';
        break;
    }
  }

  return result;
}

function printHelp(): void {
  console.log(`
spine-vanta v${VERSION} - Spine Vanta Connector

USAGE:
  spine-vanta --dry-run [options]    Generate attestation JSON (no upload)
  spine-vanta --upload <file.json>   Upload attestation to Vanta

OPTIONS:
  --data-dir <path>      WAL data directory (default: ./spine-data)
  --key-file <path>      Signing key JSON file (default: ./spine-key.json)
  --period-start <iso>   Period start (default: 24h ago)
  --period-end <iso>     Period end (default: now)
  --api-token <token>    Vanta API token (or set VANTA_API_TOKEN env)
  --help, -h             Show this help
  --version, -v          Show version

ENVIRONMENT:
  VANTA_API_TOKEN        Vanta API bearer token
  SPINE_DATA_DIR         Default data directory
  SPINE_KEY_FILE         Default key file path

EXAMPLES:
  # Generate attestation and print to stdout
  spine-vanta --dry-run --data-dir ./my-wal

  # Generate and save to file
  spine-vanta --dry-run > attestation.json

  # Upload existing attestation to Vanta
  spine-vanta --upload attestation.json --api-token sk_xxx
`);
}

async function loadOrCreateKey(keyFile: string): Promise<SigningKey> {
  if (fs.existsSync(keyFile)) {
    const data = JSON.parse(fs.readFileSync(keyFile, 'utf-8'));
    return SigningKey.fromPrivateKey(data.privateKey, data.keyId);
  }

  // Generate new key and save
  const key = await SigningKey.generate('spine-vanta-key');
  const keyData = {
    keyId: key.keyId,
    privateKey: key.privateKeyHex(),
    publicKey: key.publicKeyHex(),
    createdAt: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(keyFile), { recursive: true });
  fs.writeFileSync(keyFile, JSON.stringify(keyData, null, 2));
  console.error(`Created new signing key: ${keyFile}`);
  return key;
}

async function dryRun(args: CliArgs): Promise<void> {
  const dataDir = args.dataDir ?? process.env.SPINE_DATA_DIR ?? './spine-data';
  const keyFile = args.keyFile ?? process.env.SPINE_KEY_FILE ?? './spine-key.json';

  if (!fs.existsSync(dataDir)) {
    console.error(`Error: Data directory not found: ${dataDir}`);
    console.error('Create WAL data first or specify --data-dir');
    process.exit(1);
  }

  const signingKey = await loadOrCreateKey(keyFile);
  const wal = new WAL(signingKey, { dataDir });

  const period = args.periodStart && args.periodEnd
    ? { start: args.periodStart, end: args.periodEnd }
    : undefined;

  const attestation = await exportAttestation(wal, signingKey, { period });

  // Output JSON to stdout
  console.log(JSON.stringify(attestation, null, 2));
}

async function uploadToVanta(filePath: string, apiToken: string): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }

  const attestation: Attestation = JSON.parse(fs.readFileSync(filePath, 'utf-8'));

  // Prepare document metadata
  const documentName = `spine-attestation-${attestation.attestation_id}.json`;
  const description = [
    `Spine Cryptographic Attestation`,
    `Period: ${attestation.period.start} to ${attestation.period.end}`,
    `Status: ${attestation.verification.status}`,
    `Events: ${attestation.count}`,
  ].join('\n');

  // Create form data for Vanta API
  const boundary = `----SpineFormBoundary${Date.now()}`;
  const fileContent = fs.readFileSync(filePath);

  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="displayName"`,
    '',
    documentName,
    `--${boundary}`,
    `Content-Disposition: form-data; name="description"`,
    '',
    description,
    `--${boundary}`,
    `Content-Disposition: form-data; name="file"; filename="${documentName}"`,
    'Content-Type: application/json',
    '',
    fileContent.toString('utf-8'),
    `--${boundary}--`,
  ].join('\r\n');

  console.error(`Uploading to Vanta: ${documentName}`);

  const response = await fetch(VANTA_API_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiToken}`,
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
    },
    body,
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error(`Error: Vanta API returned ${response.status}`);
    console.error(errorText);
    process.exit(1);
  }

  const result = await response.json();
  console.log(JSON.stringify(result, null, 2));
  console.error(`Upload successful. Document ID: ${(result as { id?: string }).id ?? 'unknown'}`);
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  switch (args.command) {
    case 'help':
      printHelp();
      break;

    case 'version':
      console.log(`spine-vanta v${VERSION}`);
      break;

    case 'dry-run':
      await dryRun(args);
      break;

    case 'upload': {
      const token = args.apiToken ?? process.env.VANTA_API_TOKEN;
      if (!token) {
        console.error('Error: API token required. Use --api-token or set VANTA_API_TOKEN');
        process.exit(1);
      }
      if (!args.uploadFile) {
        console.error('Error: File path required for --upload');
        process.exit(1);
      }
      await uploadToVanta(args.uploadFile, token);
      break;
    }
  }
}

main().catch((err) => {
  console.error('Error:', err.message);
  process.exit(1);
});
