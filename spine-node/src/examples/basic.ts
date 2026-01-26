// SPDX-License-Identifier: Apache-2.0

/**
 * Basic usage example for Spine Node SDK.
 *
 * Run: npx ts-node examples/basic.ts
 * Or after build: node dist/examples/basic.js
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SigningKey, WAL, verify, exportAttestation } from '../index.js';

async function main() {
  // Create temp directory for WAL
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spine-example-'));
  console.log(`WAL directory: ${dataDir}\n`);

  try {
    // Generate signing key
    const signingKey = await SigningKey.generate('example-key');
    console.log(`Signing key: ${signingKey.keyId}`);
    console.log(`Public key: ${signingKey.publicKeyHex().slice(0, 16)}...`);

    // Create WAL
    const wal = new WAL(signingKey, { dataDir });

    // Append audit events
    console.log('\n--- Appending events ---');

    const r1 = await wal.append({
      event_type: 'user.login',
      user_id: 'alice',
      ip_address: '192.168.1.1',
    });
    console.log(`Event 1: seq=${r1.seq}, hash=${r1.payload_hash.slice(0, 16)}...`);

    const r2 = await wal.append({
      event_type: 'document.create',
      user_id: 'alice',
      document_id: 'doc-123',
    });
    console.log(`Event 2: seq=${r2.seq}, hash=${r2.payload_hash.slice(0, 16)}...`);

    const r3 = await wal.append({
      event_type: 'user.logout',
      user_id: 'alice',
    });
    console.log(`Event 3: seq=${r3.seq}, hash=${r3.payload_hash.slice(0, 16)}...`);

    // Verify chain
    console.log('\n--- Verifying chain ---');
    const result = await verify(wal);
    console.log(`Status: ${result.status}`);
    console.log(`Count: ${result.count}`);
    console.log(`Sequence: ${result.first_seq} -> ${result.last_seq}`);
    console.log(`Root hash: ${result.root_hash?.slice(0, 16)}...`);

    // Export attestation
    console.log('\n--- Exporting attestation ---');
    const attestation = await exportAttestation(wal, signingKey);
    console.log(JSON.stringify(attestation, null, 2));

    // Signature info
    console.log(`\nSignature: ${attestation.signature?.value.slice(0, 20)}...`);
    console.log(`Signed fields: ${attestation.signature?.signed_fields.join(', ')}`);

    // Verify attestation_id is deterministic (same period = same ID)
    const fixedPeriod = { start: '2026-01-01T00:00:00Z', end: '2026-12-31T23:59:59Z' };
    const att1 = await exportAttestation(wal, signingKey, { period: fixedPeriod });
    const att2 = await exportAttestation(wal, signingKey, { period: fixedPeriod });
    console.log(`\nAttestation ID (fixed period): ${att1.attestation_id}`);
    console.log(`Attestation ID stable: ${att1.attestation_id === att2.attestation_id}`);

  } finally {
    // Cleanup
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

main().catch(console.error);
