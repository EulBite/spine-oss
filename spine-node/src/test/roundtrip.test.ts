// SPDX-License-Identifier: Apache-2.0

import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { SigningKey, VerifyingKey } from '../crypto.js';
import { WAL } from '../wal.js';
import { verify } from '../verify.js';
import { exportAttestation } from '../attestation.js';
import { canonicalJson } from '../canonical.js';

describe('roundtrip', () => {
  let testDir: string;
  let signingKey: SigningKey;
  let wal: WAL;

  before(async () => {
    testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'spine-test-'));
    signingKey = await SigningKey.generate('test-key');
    wal = new WAL(signingKey, { dataDir: testDir });
  });

  after(() => {
    fs.rmSync(testDir, { recursive: true, force: true });
  });

  it('append -> verify -> attestation', async () => {
    // Append events
    await wal.append({ event: 'login', user: 'alice' });
    await wal.append({ event: 'action', type: 'create' });
    await wal.append({ event: 'logout', user: 'alice' });

    // Verify
    const result = await verify(wal);
    assert.strictEqual(result.status, 'VERIFIED');
    assert.strictEqual(result.count, 3);
    assert.strictEqual(result.first_seq, 1);
    assert.strictEqual(result.last_seq, 3);
    assert.ok(result.root_hash);

    // Export attestation
    const attestation = await exportAttestation(wal, signingKey);
    assert.strictEqual(attestation.version, '1.0');
    assert.strictEqual(attestation.type, 'spine.attestation.v1');
    assert.strictEqual(attestation.verification.status, 'VERIFIED');
    assert.strictEqual(attestation.count, 3);
    assert.ok(attestation.attestation_id);
    assert.strictEqual(attestation.attestation_id.length, 16);
    assert.strictEqual(attestation.pubkey.format, 'raw32');
    assert.strictEqual(attestation.pubkey.algo, 'ed25519');
    assert.ok(attestation.root_hash);
    assert.strictEqual(attestation.root_hash.algo, 'blake3');
  });

  it('attestation_id is deterministic', async () => {
    const att1 = await exportAttestation(wal, signingKey, {
      period: { start: '2026-01-01T00:00:00Z', end: '2026-12-31T23:59:59Z' },
    });
    const att2 = await exportAttestation(wal, signingKey, {
      period: { start: '2026-01-01T00:00:00Z', end: '2026-12-31T23:59:59Z' },
    });
    assert.strictEqual(att1.attestation_id, att2.attestation_id);
  });

  it('empty period returns EMPTY status', async () => {
    const att = await exportAttestation(wal, signingKey, {
      period: { start: '2020-01-01T00:00:00Z', end: '2020-01-02T00:00:00Z' },
    });
    assert.strictEqual(att.verification.status, 'EMPTY');
    assert.strictEqual(att.count, 0);
    assert.strictEqual(att.ledger.first_seq, undefined);
    assert.strictEqual(att.root_hash, undefined);
  });

  it('attestation has valid signature', async () => {
    const att = await exportAttestation(wal, signingKey);

    // Signature must exist
    assert.ok(att.signature);
    assert.strictEqual(att.signature.algo, 'ed25519');
    assert.strictEqual(att.signature.format, 'base64');
    assert.ok(att.signature.value);
    assert.ok(att.signature.signed_fields.length > 0);

    // Verify signature
    const toSign: Record<string, unknown> = {};
    for (const field of att.signature.signed_fields) {
      const value = (att as unknown as Record<string, unknown>)[field];
      if (value !== undefined) {
        toSign[field] = value;
      }
    }
    const canonical = canonicalJson(toSign);
    const sigBytes = Buffer.from(att.signature.value, 'base64');
    const sigHex = sigBytes.toString('hex');

    const verifyingKey = VerifyingKey.fromBase64(att.pubkey.value, att.pubkey.id);
    const valid = await verifyingKey.verify(sigHex, canonical);
    assert.strictEqual(valid, true);
  });

  it('attestation without signature (sign: false)', async () => {
    const att = await exportAttestation(wal, signingKey, { sign: false });
    assert.strictEqual(att.signature, undefined);
  });
});
