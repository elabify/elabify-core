// Canonical JSON serialization per the wire-format spec §3 and
// elabify-core/README.md §5.2.
//
// Algorithm (M0 strict mode):
//   1. Walk the value recursively.
//   2. Objects: collect (key, value) pairs, NFC-normalize each key, then
//      sort by Unicode code-unit comparison; emit "k":canonicalize(v),
//      comma-separated, wrapped in {}.
//   3. Arrays: emit canonicalize(element), comma-separated, wrapped in [].
//   4. Strings: NFC-normalize, then RFC 8259 minimal escape.
//   5. Numbers: integers via JSON.stringify; reject NaN/±Infinity (code
//      'nan-or-inf') and non-integer floats (code 'float').
//   6. Booleans: true / false. Null: null.
//   7. Output UTF-8 bytes with no trailing newline, no BOM.
//
// Reject (throwing CanonicalizeError) per spec:
//   - 'nan-or-inf'        NaN, +Infinity, -Infinity
//   - 'float'             non-integer numeric (e.g. 1.5)
//   - 'cycle'             a value appears twice on the same recursion path
//   - 'depth'             nesting depth exceeds DEPTH_LIMIT (32)
//   - 'string-too-long'   string longer than STRING_BYTE_LIMIT (64 KiB UTF-8)
//
// The cycle detector uses a stack-set scoped to the current recursion path
// (NOT a global visited set), so structurally-shared but acyclic subgraphs
// emit correctly. Cycles produce 'cycle'; reuse of the same array/object
// across sibling positions in the tree is allowed.

import { utf8 } from './hex.js';

const DEPTH_LIMIT = 32;
const STRING_BYTE_LIMIT = 64 * 1024; // 64 KiB UTF-8

export type CanonicalizeErrorCode =
  | 'float'
  | 'cycle'
  | 'depth'
  | 'string-too-long'
  | 'nan-or-inf';

export class CanonicalizeError extends Error {
  readonly code: CanonicalizeErrorCode;
  constructor(code: CanonicalizeErrorCode, message: string) {
    super(message);
    this.name = 'CanonicalizeError';
    this.code = code;
  }
}

const encoder = new TextEncoder();

function emitString(s: string): string {
  const nfc = s.normalize('NFC');
  if (encoder.encode(nfc).byteLength > STRING_BYTE_LIMIT) {
    throw new CanonicalizeError(
      'string-too-long',
      `canonicalize: string exceeds ${STRING_BYTE_LIMIT}-byte UTF-8 limit`,
    );
  }
  return JSON.stringify(nfc);
}

function emit(value: unknown, depth: number, pathSet: Set<object>): string {
  if (depth > DEPTH_LIMIT) {
    throw new CanonicalizeError(
      'depth',
      `canonicalize: nesting depth exceeds limit of ${DEPTH_LIMIT}`,
    );
  }

  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';

  const t = typeof value;

  if (t === 'string') return emitString(value as string);

  if (t === 'number') {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new CanonicalizeError(
        'nan-or-inf',
        `canonicalize: numeric value is not finite (${String(n)})`,
      );
    }
    if (!Number.isInteger(n)) {
      throw new CanonicalizeError(
        'float',
        `canonicalize: non-integer numeric value ${n} — use string-typed identifiers for fractional values`,
      );
    }
    return JSON.stringify(n);
  }

  if (Array.isArray(value)) {
    if (pathSet.has(value)) {
      throw new CanonicalizeError('cycle', 'canonicalize: cyclic reference in array');
    }
    pathSet.add(value);
    const out = '[' + value.map((el) => emit(el, depth + 1, pathSet)).join(',') + ']';
    pathSet.delete(value);
    return out;
  }

  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    if (pathSet.has(obj)) {
      throw new CanonicalizeError('cycle', 'canonicalize: cyclic reference in object');
    }
    pathSet.add(obj);
    const normalizedKeys = Object.keys(obj).map((k) => ({ raw: k, nfc: k.normalize('NFC') }));
    normalizedKeys.sort((a, b) => (a.nfc < b.nfc ? -1 : a.nfc > b.nfc ? 1 : 0));
    const parts: string[] = [];
    for (const { raw, nfc } of normalizedKeys) {
      parts.push(emitString(nfc) + ':' + emit(obj[raw], depth + 1, pathSet));
    }
    pathSet.delete(obj);
    return '{' + parts.join(',') + '}';
  }

  // undefined, function, symbol, bigint, etc. — JSON.stringify drops these
  // silently; we surface them as a depth-0 'float'-adjacent failure to make
  // the call site loud. There is no spec code for "unsupported type" so we
  // reuse 'nan-or-inf' as the closest numeric-domain error and tag the type
  // in the message.
  throw new CanonicalizeError(
    'nan-or-inf',
    `canonicalize: unsupported value type "${t}" (only string, number-integer, boolean, null, array, object are accepted)`,
  );
}

/**
 * Canonical JSON serialization to a UTF-8 string. Sorts object keys
 * lexicographically (post NFC-normalization) by code-unit comparison;
 * preserves array order; rejects non-integer numbers, NaN/Infinity, cycles,
 * over-deep nesting, and over-long strings via CanonicalizeError.
 */
export function canonicalJsonString(value: unknown): string {
  return emit(value, 0, new Set<object>());
}

/**
 * Canonical JSON serialization to UTF-8 bytes — the API shape specified in
 * elabify-core/README.md §4.1.
 */
export function canonicalize(value: unknown): Uint8Array {
  return utf8(canonicalJsonString(value));
}
