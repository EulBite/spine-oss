// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'blake3';
import * as ed from '@noble/ed25519';
import { canonicalJson } from './canonical.js';

export function blake3Hash(data: Buffer): string {
  return createHash().update(data).digest('hex');
}

export function hashPayload(payload: Record<string, unknown>): string {
  const canonical = canonicalJson(payload);
  return blake3Hash(canonical);
}

/**
 * Compute entry hash for chain linking.
 * Format: BLAKE3(seq_le_u64 || ts_ns_le_i64 || prev_hash_utf8 || payload_hash_utf8)
 */
export function computeEntryHash(
  seq: number,
  timestampNs: bigint,
  prevHash: string,
  payloadHash: string
): string {
  const seqBuf = Buffer.alloc(8);
  seqBuf.writeBigUInt64LE(BigInt(seq));

  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigInt64LE(timestampNs);

  const data = Buffer.concat([
    seqBuf,
    tsBuf,
    Buffer.from(prevHash, 'utf-8'),
    Buffer.from(payloadHash, 'utf-8'),
  ]);

  return blake3Hash(data);
}

export function isoToNanos(isoTimestamp: string): bigint {
  const date = new Date(isoTimestamp);
  // Date.getTime() returns milliseconds
  return BigInt(date.getTime()) * 1_000_000n;
}

export class SigningKey {
  readonly keyId: string;
  private readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;

  private constructor(keyId: string, privateKey: Uint8Array, publicKey: Uint8Array) {
    this.keyId = keyId;
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  static async generate(keyId?: string): Promise<SigningKey> {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    const id = keyId ?? `kid_${Buffer.from(privateKey.slice(0, 8)).toString('hex')}`;
    return new SigningKey(id, privateKey, publicKey);
  }

  static async fromSeed(seed: Uint8Array, keyId: string): Promise<SigningKey> {
    if (seed.length !== 32) {
      throw new Error(`Ed25519 seed must be 32 bytes, got ${seed.length}`);
    }
    const publicKey = await ed.getPublicKeyAsync(seed);
    return new SigningKey(keyId, seed, publicKey);
  }

  static async fromHex(hexSeed: string, keyId: string): Promise<SigningKey> {
    const seed = Buffer.from(hexSeed, 'hex');
    return SigningKey.fromSeed(seed, keyId);
  }

  static async fromPrivateKey(privateKeyHex: string, keyId: string): Promise<SigningKey> {
    return SigningKey.fromHex(privateKeyHex, keyId);
  }

  async sign(data: Buffer): Promise<string> {
    const signature = await ed.signAsync(data, this.privateKey);
    return Buffer.from(signature).toString('hex');
  }

  privateKeyHex(): string {
    return Buffer.from(this.privateKey).toString('hex');
  }

  publicKeyHex(): string {
    return Buffer.from(this.publicKey).toString('hex');
  }

  publicKeyBase64(): string {
    return Buffer.from(this.publicKey).toString('base64');
  }
}

export class VerifyingKey {
  readonly keyId: string;
  readonly publicKey: Uint8Array;

  constructor(keyId: string, publicKey: Uint8Array) {
    this.keyId = keyId;
    this.publicKey = publicKey;
  }

  static fromHex(hex: string, keyId: string): VerifyingKey {
    const publicKey = Buffer.from(hex, 'hex');
    if (publicKey.length !== 32) {
      throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKey.length}`);
    }
    return new VerifyingKey(keyId, publicKey);
  }

  static fromBase64(base64: string, keyId: string): VerifyingKey {
    const publicKey = Buffer.from(base64, 'base64');
    if (publicKey.length !== 32) {
      throw new Error(`Ed25519 public key must be 32 bytes, got ${publicKey.length}`);
    }
    return new VerifyingKey(keyId, publicKey);
  }

  async verify(signatureHex: string, data: Buffer): Promise<boolean> {
    try {
      const signature = Buffer.from(signatureHex, 'hex');
      return await ed.verifyAsync(signature, data, this.publicKey);
    } catch {
      return false;
    }
  }
}
