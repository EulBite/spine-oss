// SPDX-License-Identifier: Apache-2.0

import * as fs from 'fs';
import * as path from 'path';
import { LocalRecord, GENESIS_HASH, WAL_FORMAT_VERSION } from './types.js';
import { SigningKey, hashPayload, computeEntryHash, isoToNanos } from './crypto.js';
import { randomUUID } from 'crypto';

export interface WALConfig {
  dataDir: string;
  streamId?: string;
}

interface ChainState {
  stream_id: string;
  seq: number;
  prev_hash: string;
}

export class WAL {
  private readonly config: WALConfig;
  private readonly signingKey: SigningKey;
  private streamId: string;
  private seq: number = 0;
  private prevHash: string = GENESIS_HASH;
  private initialized: boolean = false;

  constructor(signingKey: SigningKey, config: WALConfig) {
    this.signingKey = signingKey;
    this.config = config;
    this.streamId = config.streamId ?? `stream_${signingKey.keyId}`;
  }

  private get segmentPath(): string {
    return path.join(this.config.dataDir, 'segment_current.jsonl');
  }

  private get statePath(): string {
    return path.join(this.config.dataDir, 'chain_state.json');
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    if (!fs.existsSync(this.config.dataDir)) {
      fs.mkdirSync(this.config.dataDir, { recursive: true });
    }

    if (fs.existsSync(this.statePath)) {
      const state: ChainState = JSON.parse(fs.readFileSync(this.statePath, 'utf-8'));
      this.streamId = state.stream_id;
      this.seq = state.seq;
      this.prevHash = state.prev_hash;
    }

    this.initialized = true;
  }

  private saveState(): void {
    const state: ChainState = {
      stream_id: this.streamId,
      seq: this.seq,
      prev_hash: this.prevHash,
    };
    fs.writeFileSync(this.statePath, JSON.stringify(state));
  }

  async append(payload: Record<string, unknown>): Promise<LocalRecord> {
    await this.initialize();

    const eventId = `evt_${randomUUID()}`;
    this.seq += 1;
    const seq = this.seq;
    const tsClient = new Date().toISOString();
    const tsNs = isoToNanos(tsClient);
    const payloadHash = hashPayload(payload);

    const entryHash = computeEntryHash(seq, tsNs, this.prevHash, payloadHash);
    const signature = await this.signingKey.sign(Buffer.from(entryHash, 'utf-8'));

    const record: LocalRecord = {
      format_version: WAL_FORMAT_VERSION,
      event_id: eventId,
      stream_id: this.streamId,
      seq,
      prev_hash: this.prevHash,
      ts_client: tsClient,
      payload,
      payload_hash: payloadHash,
      hash_alg: 'blake3',
      sig_client: signature,
      key_id: this.signingKey.keyId,
      public_key: this.signingKey.publicKeyBase64(),
    };

    fs.appendFileSync(this.segmentPath, JSON.stringify(record) + '\n');

    this.prevHash = entryHash;
    this.saveState();

    return record;
  }

  async *readRecords(): AsyncGenerator<LocalRecord> {
    await this.initialize();

    if (!fs.existsSync(this.segmentPath)) return;

    const content = fs.readFileSync(this.segmentPath, 'utf-8');
    for (const line of content.split('\n')) {
      if (line.trim()) {
        try {
          yield JSON.parse(line) as LocalRecord;
        } catch {
          // Skip corrupted lines
        }
      }
    }
  }

  getStreamId(): string {
    return this.streamId;
  }

  getSeq(): number {
    return this.seq;
  }

  getPrevHash(): string {
    return this.prevHash;
  }
}
