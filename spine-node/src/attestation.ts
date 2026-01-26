// SPDX-License-Identifier: Apache-2.0

import { Attestation, VerifyResult } from './types.js';
import { WAL } from './wal.js';
import { verify, VerifyOptions } from './verify.js';
import { blake3Hash, SigningKey } from './crypto.js';
import { canonicalJson } from './canonical.js';

const VERSION = '0.1.0';

const SIGNED_FIELDS = [
  'version',
  'type',
  'attestation_id',
  'period',
  'ledger',
  'count',
  'root_hash',
  'pubkey',
  'verification',
] as const;

export interface AttestationOptions {
  period?: {
    start: string;
    end: string;
  };
  verificationTool?: string;
  sign?: boolean; // default: true
}

/**
 * Compute deterministic attestation_id.
 * attestation_id = blake3(stream_id | period.start | period.end | root_hash).hex[0:16]
 */
function computeAttestationId(
  streamId: string,
  periodStart: string,
  periodEnd: string,
  rootHash: string | undefined
): string {
  const input = `${streamId}|${periodStart}|${periodEnd}|${rootHash ?? ''}`;
  const hash = blake3Hash(Buffer.from(input, 'utf-8'));
  return hash.slice(0, 16);
}

export async function exportAttestation(
  wal: WAL,
  signingKey: SigningKey,
  options?: AttestationOptions
): Promise<Attestation> {
  const now = new Date().toISOString();
  const period = options?.period ?? {
    start: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(), // 24h ago
    end: now,
  };

  const verifyOptions: VerifyOptions = {
    startTime: period.start,
    endTime: period.end,
  };

  const result: VerifyResult = await verify(wal, verifyOptions);
  const streamId = wal.getStreamId();

  const attestationId = computeAttestationId(
    streamId,
    period.start,
    period.end,
    result.root_hash
  );

  const attestation: Attestation = {
    version: '1.0',
    type: 'spine.attestation.v1',
    attestation_id: attestationId,
    period,
    ledger: {
      stream_id: streamId,
    },
    count: result.count,
    pubkey: {
      id: signingKey.keyId,
      algo: 'ed25519',
      format: 'raw32',
      value: signingKey.publicKeyBase64(),
    },
    verification: {
      status: result.status,
      checked_at: now,
      tool: options?.verificationTool ?? `spine-node/${VERSION}`,
    },
    generated_at: now,
    generator: `spine-node/${VERSION}`,
  };

  // Add optional fields only when present
  if (result.first_seq !== undefined) {
    attestation.ledger.first_seq = result.first_seq;
  }
  if (result.last_seq !== undefined) {
    attestation.ledger.last_seq = result.last_seq;
  }
  if (result.root_hash) {
    attestation.root_hash = {
      algo: 'blake3',
      value: result.root_hash,
    };
  }
  if (result.missing_ranges && result.missing_ranges.length > 0) {
    attestation.verification.missing_ranges = result.missing_ranges;
  }

  // Sign attestation (default: true)
  if (options?.sign !== false) {
    attestation.signature = await signAttestation(attestation, signingKey);
  }

  return attestation;
}

/**
 * Sign the attestation fields.
 * Signature covers canonical JSON of signed_fields only.
 */
async function signAttestation(
  attestation: Attestation,
  signingKey: SigningKey
): Promise<Attestation['signature']> {
  // Extract only signed fields
  const toSign: Record<string, unknown> = {};
  for (const field of SIGNED_FIELDS) {
    const value = attestation[field as keyof Attestation];
    if (value !== undefined) {
      toSign[field] = value;
    }
  }

  // Canonical JSON → sign
  const canonical = canonicalJson(toSign);
  const signatureHex = await signingKey.sign(canonical);
  const signatureBase64 = Buffer.from(signatureHex, 'hex').toString('base64');

  return {
    algo: 'ed25519',
    format: 'base64',
    value: signatureBase64,
    signed_fields: [...SIGNED_FIELDS],
  };
}
