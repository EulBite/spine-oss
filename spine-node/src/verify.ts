// SPDX-License-Identifier: Apache-2.0

import { LocalRecord, VerifyResult, MissingRange, GENESIS_HASH } from './types.js';
import { hashPayload, computeEntryHash, isoToNanos, VerifyingKey } from './crypto.js';
import { WAL } from './wal.js';

export interface VerifyOptions {
  startTime?: string;
  endTime?: string;
}

export async function verify(wal: WAL, options?: VerifyOptions): Promise<VerifyResult> {
  const records: LocalRecord[] = [];

  for await (const record of wal.readRecords()) {
    // Filter by time if specified
    if (options?.startTime && record.ts_client < options.startTime) continue;
    if (options?.endTime && record.ts_client > options.endTime) continue;
    records.push(record);
  }

  if (records.length === 0) {
    return {
      status: 'EMPTY',
      count: 0,
    };
  }

  // Sort by sequence
  records.sort((a, b) => a.seq - b.seq);

  const missingRanges: MissingRange[] = [];
  let lastEntryHash = GENESIS_HASH;
  let expectedSeq = 1;

  // Check if records start after seq 1 (missing beginning)
  if (records[0].seq > 1) {
    missingRanges.push({ from: 1, to: records[0].seq - 1 });
  }

  // Check first record genesis
  if (records[0].seq === 1 && records[0].prev_hash !== GENESIS_HASH) {
    return {
      status: 'TAMPERED',
      count: records.length,
      first_seq: records[0].seq,
      last_seq: records[records.length - 1].seq,
    };
  }

  for (const record of records) {
    // Check sequence gaps
    if (record.seq !== expectedSeq) {
      missingRanges.push({ from: expectedSeq, to: record.seq - 1 });
    }
    expectedSeq = record.seq + 1;

    // Verify payload hash
    const computedPayloadHash = hashPayload(record.payload);
    if (computedPayloadHash !== record.payload_hash) {
      return {
        status: 'TAMPERED',
        count: records.length,
        first_seq: records[0].seq,
        last_seq: records[records.length - 1].seq,
      };
    }

    // Verify chain linkage (for non-first records or first with prev_hash)
    if (record.seq > 1 || (record.seq === 1 && records.length > 1)) {
      // For seq > 1, check prev_hash matches last entry hash
      if (record.seq > 1 && record.prev_hash !== lastEntryHash) {
        return {
          status: 'TAMPERED',
          count: records.length,
          first_seq: records[0].seq,
          last_seq: records[records.length - 1].seq,
        };
      }
    }

    // Compute entry hash
    const tsNs = isoToNanos(record.ts_client);
    const entryHash = computeEntryHash(record.seq, tsNs, record.prev_hash, record.payload_hash);

    // Verify signature (public_key is base64 raw32)
    if (record.public_key) {
      const verifyingKey = VerifyingKey.fromBase64(record.public_key, record.key_id);
      const validSig = await verifyingKey.verify(record.sig_client, Buffer.from(entryHash, 'utf-8'));
      if (!validSig) {
        return {
          status: 'TAMPERED',
          count: records.length,
          first_seq: records[0].seq,
          last_seq: records[records.length - 1].seq,
        };
      }
    }

    lastEntryHash = entryHash;
  }

  if (missingRanges.length > 0) {
    return {
      status: 'INCOMPLETE',
      count: records.length,
      first_seq: records[0].seq,
      last_seq: records[records.length - 1].seq,
      root_hash: lastEntryHash,
      missing_ranges: missingRanges,
    };
  }

  return {
    status: 'VERIFIED',
    count: records.length,
    first_seq: records[0].seq,
    last_seq: records[records.length - 1].seq,
    root_hash: lastEntryHash,
  };
}
