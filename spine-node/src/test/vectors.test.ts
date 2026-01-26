// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { canonicalJson } from '../canonical.js';
import { blake3Hash, computeEntryHash } from '../crypto.js';

// Test vectors from test-vectors/vectors.json
describe('canonical JSON', () => {
  it('key_ordering', () => {
    const input = { z: 1, a: 2, m: 3 };
    const result = canonicalJson(input).toString('utf-8');
    assert.strictEqual(result, '{"a":2,"m":3,"z":1}');
  });

  it('no_whitespace', () => {
    const input = { key: 'value', nested: { inner: 123 } };
    const result = canonicalJson(input).toString('utf-8');
    assert.strictEqual(result, '{"key":"value","nested":{"inner":123}}');
  });

  it('unicode_nfc_cafe_composed', () => {
    const input = { name: 'café' };
    const result = canonicalJson(input).toString('utf-8');
    assert.strictEqual(result, '{"name":"café"}');
  });

  it('unicode_nfc_cafe_decomposed', () => {
    const input = { name: 'cafe\u0301' }; // e + combining acute
    const result = canonicalJson(input).toString('utf-8');
    assert.strictEqual(result, '{"name":"café"}'); // Must normalize to composed
  });

  it('empty_object', () => {
    const result = canonicalJson({}).toString('utf-8');
    assert.strictEqual(result, '{}');
  });

  it('boolean_null', () => {
    const input = { t: true, f: false, n: null };
    const result = canonicalJson(input).toString('utf-8');
    assert.strictEqual(result, '{"f":false,"n":null,"t":true}');
  });

  it('rejects floats', () => {
    assert.throws(() => canonicalJson({ x: 1.5 }), TypeError);
  });
});

describe('payload hash', () => {
  it('simple_event', () => {
    const payload = { event: 'test' };
    const canonical = canonicalJson(payload);
    assert.strictEqual(canonical.toString('utf-8'), '{"event":"test"}');
    const hash = blake3Hash(canonical);
    assert.strictEqual(hash, 'ba0ec9bd9cf1b301fae5608349497d6ac27dd1ea071ed9469b8894ba58f385b8');
  });

  it('empty_payload', () => {
    const hash = blake3Hash(canonicalJson({}));
    assert.strictEqual(hash, '6e46dd10defc9b56c29a6ec56b508c21f54c08192194e4df25bf36f0c9c3c279');
  });

  it('unicode_payload', () => {
    const payload = { user: 'café', city: '東京' };
    const canonical = canonicalJson(payload);
    assert.strictEqual(canonical.toString('utf-8'), '{"city":"東京","user":"café"}');
    const hash = blake3Hash(canonical);
    assert.strictEqual(hash, 'dcb71029975d874f9197eedb1a838f3086a40237ef6d07b865f7bbdf22cd5897');
  });
});

describe('entry hash', () => {
  it('genesis_entry', () => {
    const seq = 1;
    const timestampNs = 1737720000000000000n;
    const prevHash = '0'.repeat(64);
    const payloadHash = 'ba0ec9bd9cf1b301fae5608349497d6ac27dd1ea071ed9469b8894ba58f385b8';

    const entryHash = computeEntryHash(seq, timestampNs, prevHash, payloadHash);
    assert.strictEqual(entryHash, '77adfc6abdc08c5e9e8f1da10b12f96f11a2609659e8bc5ea9d3854dd99c05db');
  });

  it('second_entry', () => {
    const seq = 2;
    const timestampNs = 1737720001000000000n;
    const prevHash = '77adfc6abdc08c5e9e8f1da10b12f96f11a2609659e8bc5ea9d3854dd99c05db';
    const payloadHash = '6e46dd10defc9b56c29a6ec56b508c21f54c08192194e4df25bf36f0c9c3c279';

    const entryHash = computeEntryHash(seq, timestampNs, prevHash, payloadHash);
    assert.strictEqual(entryHash, '5a9766d525452f87207c409393beeb39bfcd3ca40e1ad1c2a1abb1c2f08f9c32');
  });
});
