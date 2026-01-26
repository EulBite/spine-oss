// SPDX-License-Identifier: Apache-2.0

/**
 * Canonical JSON serialization (RFC 8785-like).
 * - Keys sorted lexicographically
 * - No whitespace
 * - Unicode NFC normalization
 * - Floats rejected
 */

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

function normalizeNFC(str: string): string {
  return str.normalize('NFC');
}

function normalizeValue(value: unknown): JsonValue {
  if (value === null) return null;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError(`Invalid number: ${value}`);
    }
    if (!Number.isInteger(value)) {
      throw new TypeError(`Float values not allowed in canonical JSON: ${value}`);
    }
    return value;
  }
  if (typeof value === 'string') {
    return normalizeNFC(value);
  }
  if (Array.isArray(value)) {
    return value.map(normalizeValue);
  }
  if (typeof value === 'object') {
    const result: { [key: string]: JsonValue } = {};
    for (const [k, v] of Object.entries(value)) {
      result[normalizeNFC(k)] = normalizeValue(v);
    }
    return result;
  }
  throw new TypeError(`Unsupported type: ${typeof value}`);
}

function stringifyCanonical(value: JsonValue): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(stringifyCanonical).join(',') + ']';
  }
  // Object: sort keys
  const keys = Object.keys(value).sort();
  const pairs = keys.map(k => JSON.stringify(k) + ':' + stringifyCanonical(value[k]));
  return '{' + pairs.join(',') + '}';
}

export function canonicalJson(obj: unknown): Buffer {
  const normalized = normalizeValue(obj);
  const str = stringifyCanonical(normalized);
  return Buffer.from(str, 'utf-8');
}
