// SPDX-License-Identifier: Apache-2.0

export interface LocalRecord {
  format_version: number;
  event_id: string;
  stream_id: string;
  seq: number;
  prev_hash: string;
  ts_client: string;
  payload: Record<string, unknown>;
  payload_hash: string;
  hash_alg: string;
  sig_client: string;
  key_id: string;
  public_key?: string;
}

export type VerificationStatus = 'VERIFIED' | 'TAMPERED' | 'INCOMPLETE' | 'EMPTY';

export interface MissingRange {
  from: number;
  to: number;
}

export interface VerifyResult {
  status: VerificationStatus;
  count: number;
  first_seq?: number;
  last_seq?: number;
  root_hash?: string;
  missing_ranges?: MissingRange[];
}

export interface AttestationSignature {
  algo: string;
  format: string;
  value: string;
  signed_fields: string[];
}

export interface Attestation {
  version: string;
  type: string;
  attestation_id: string;
  period: {
    start: string;
    end: string;
  };
  ledger: {
    stream_id: string;
    first_seq?: number;
    last_seq?: number;
  };
  count: number;
  root_hash?: {
    algo: string;
    value: string;
  };
  pubkey: {
    id: string;
    algo: string;
    format: string;
    value: string;
  };
  verification: {
    status: VerificationStatus;
    checked_at: string;
    tool: string;
    missing_ranges?: MissingRange[];
  };
  generated_at: string;
  generator: string;
  signature?: AttestationSignature;
}

export const GENESIS_HASH = '0'.repeat(64);
export const WAL_FORMAT_VERSION = 1;
