// SPDX-License-Identifier: Apache-2.0

import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';
import { SigningKey, WAL } from 'spine-sdk-node';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('spine-vanta --dry-run', () => {
  let testDir: string;
  let dataDir: string;
  let keyFile: string;

  before(async () => {
    // Create test directories
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spine-vanta-test-'));
    dataDir = path.join(testDir, 'wal');
    keyFile = path.join(testDir, 'key.json');
    fs.mkdirSync(dataDir);

    // Generate key and save
    const signingKey = await SigningKey.generate('test-key');
    fs.writeFileSync(keyFile, JSON.stringify({
      keyId: signingKey.keyId,
      privateKey: signingKey.privateKeyHex(),
      publicKey: signingKey.publicKeyHex(),
    }));

    // Create WAL with some events
    const wal = new WAL(signingKey, { dataDir });
    await wal.append({ event: 'user.login', user: 'alice' });
    await wal.append({ event: 'document.create', doc_id: 'doc-1' });
    await wal.append({ event: 'user.logout', user: 'alice' });
  });

  after(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('generates valid attestation JSON', () => {
    const cliPath = path.join(__dirname, '..', 'cli.js');
    const result = execSync(
      `node "${cliPath}" --dry-run --data-dir "${dataDir}" --key-file "${keyFile}"`,
      { encoding: 'utf-8' }
    );

    const attestation = JSON.parse(result);

    // Check structure
    assert.strictEqual(attestation.version, '1.0');
    assert.strictEqual(attestation.type, 'spine.attestation.v1');
    assert.strictEqual(typeof attestation.attestation_id, 'string');
    assert.strictEqual(attestation.attestation_id.length, 16);

    // Check counts
    assert.strictEqual(attestation.count, 3);
    assert.strictEqual(attestation.ledger.first_seq, 1);
    assert.strictEqual(attestation.ledger.last_seq, 3);

    // Check verification
    assert.strictEqual(attestation.verification.status, 'VERIFIED');

    // Check signature exists
    assert.ok(attestation.signature);
    assert.strictEqual(attestation.signature.algo, 'ed25519');
    assert.strictEqual(attestation.signature.format, 'base64');
    assert.ok(attestation.signature.value);
    assert.ok(Array.isArray(attestation.signature.signed_fields));
  });

  it('attestation_id is deterministic for same period', () => {
    const cliPath = path.join(__dirname, '..', 'cli.js');

    const result1 = execSync(
      `node "${cliPath}" --dry-run --data-dir "${dataDir}" --key-file "${keyFile}" --period-start "2026-01-01T00:00:00Z" --period-end "2026-12-31T23:59:59Z"`,
      { encoding: 'utf-8' }
    );
    const result2 = execSync(
      `node "${cliPath}" --dry-run --data-dir "${dataDir}" --key-file "${keyFile}" --period-start "2026-01-01T00:00:00Z" --period-end "2026-12-31T23:59:59Z"`,
      { encoding: 'utf-8' }
    );

    const att1 = JSON.parse(result1);
    const att2 = JSON.parse(result2);

    assert.strictEqual(att1.attestation_id, att2.attestation_id);
  });
});
