// SPDX-License-Identifier: Apache-2.0

// Types
export {
  LocalRecord,
  VerifyResult,
  Attestation,
  AttestationSignature,
  MissingRange,
  VerificationStatus,
  GENESIS_HASH,
  WAL_FORMAT_VERSION,
} from './types.js';

// Crypto
export {
  SigningKey,
  VerifyingKey,
  blake3Hash,
  hashPayload,
  computeEntryHash,
  isoToNanos,
} from './crypto.js';

// Canonical JSON
export { canonicalJson } from './canonical.js';

// WAL
export { WAL, WALConfig } from './wal.js';

// Verification
export { verify, VerifyOptions } from './verify.js';

// Attestation
export { exportAttestation, AttestationOptions } from './attestation.js';
