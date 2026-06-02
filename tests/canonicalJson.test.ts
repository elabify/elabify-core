import { describe, expect, it } from 'vitest';
import {
  canonicalize,
  canonicalJsonString,
  CanonicalizeError,
} from '../src/canonicalJson.js';

describe('canonicalJson — happy path', () => {
  it('sorts object keys lexicographically', () => {
    expect(canonicalJsonString({ b: 1, a: 2, c: 3 })).toBe('{"a":2,"b":1,"c":3}');
  });

  it('preserves array order', () => {
    expect(canonicalJsonString([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles nested objects', () => {
    expect(canonicalJsonString({ z: { y: 1, x: 2 }, a: 1 })).toBe(
      '{"a":1,"z":{"x":2,"y":1}}',
    );
  });

  it('emits primitives via JSON.stringify', () => {
    expect(canonicalJsonString(null)).toBe('null');
    expect(canonicalJsonString(true)).toBe('true');
    expect(canonicalJsonString(false)).toBe('false');
    expect(canonicalJsonString(42)).toBe('42');
    expect(canonicalJsonString(0)).toBe('0');
    expect(canonicalJsonString(-1)).toBe('-1');
    expect(canonicalJsonString('hello')).toBe('"hello"');
  });

  it('escapes strings per JSON spec', () => {
    expect(canonicalJsonString('a"b')).toBe('"a\\"b"');
    expect(canonicalJsonString('a\nb')).toBe('"a\\nb"');
  });

  it('canonicalize returns Uint8Array of UTF-8 bytes', () => {
    const out = canonicalize({ a: 1 });
    expect(out).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(out)).toBe('{"a":1}');
  });
});

describe('canonicalJson — M0 strict mode: NFC normalization', () => {
  it('NFC-equivalent strings produce identical canonical bytes', () => {
    // "é" composed (U+00E9) vs decomposed (U+0065 U+0301). After NFC
    // normalization both collapse to the same canonical form. This was a
    // documented Phase 0 gap (mixed-script claim values would canonicalize
    // differently across senders); M0 closes it.
    const composed = 'é';        // é (one code point)
    const decomposed = 'é';     // é (e + combining acute)
    expect(canonicalJsonString(composed)).toBe(canonicalJsonString(decomposed));
  });

  it('NFC-normalizes object keys before sorting', () => {
    // If two keys are NFC-equivalent, they sort to the same position. Here
    // we use distinct keys to verify sort happens AFTER normalization.
    const obj = { 'é': 1, 'a': 2 }; // sorted: "a" < "é"
    expect(canonicalJsonString(obj)).toBe('{"a":2,"é":1}');
  });
});

describe('canonicalJson — error codes', () => {
  it('throws CanonicalizeError code "nan-or-inf" for NaN', () => {
    try {
      canonicalJsonString(NaN);
      expect.fail('expected CanonicalizeError');
    } catch (e) {
      expect(e).toBeInstanceOf(CanonicalizeError);
      expect((e as CanonicalizeError).code).toBe('nan-or-inf');
    }
  });

  it('throws CanonicalizeError code "nan-or-inf" for ±Infinity', () => {
    expect(() => canonicalJsonString(Infinity)).toThrow(CanonicalizeError);
    expect(() => canonicalJsonString(-Infinity)).toThrow(CanonicalizeError);
    try {
      canonicalJsonString(Infinity);
    } catch (e) {
      expect((e as CanonicalizeError).code).toBe('nan-or-inf');
    }
  });

  it('throws CanonicalizeError code "float" for non-integer numbers', () => {
    try {
      canonicalJsonString(1.5);
      expect.fail('expected CanonicalizeError');
    } catch (e) {
      expect((e as CanonicalizeError).code).toBe('float');
    }
  });

  it('integer-valued floats are accepted (Number.isInteger semantics)', () => {
    expect(canonicalJsonString(1.0)).toBe('1');
    expect(canonicalJsonString(-2.0)).toBe('-2');
  });

  it('throws CanonicalizeError code "cycle" for self-referential objects', () => {
    const a: Record<string, unknown> = { name: 'cycle' };
    a.self = a;
    try {
      canonicalJsonString(a);
      expect.fail('expected CanonicalizeError');
    } catch (e) {
      expect((e as CanonicalizeError).code).toBe('cycle');
    }
  });

  it('throws CanonicalizeError code "cycle" for self-referential arrays', () => {
    const arr: unknown[] = [1, 2];
    arr.push(arr);
    try {
      canonicalJsonString(arr);
      expect.fail('expected CanonicalizeError');
    } catch (e) {
      expect((e as CanonicalizeError).code).toBe('cycle');
    }
  });

  it('shared-but-acyclic subgraphs are allowed', () => {
    // Reusing the same value at sibling positions (not on the same path)
    // is fine — it's not a cycle.
    const shared = { x: 1 };
    expect(canonicalJsonString({ a: shared, b: shared })).toBe(
      '{"a":{"x":1},"b":{"x":1}}',
    );
  });

  it('throws CanonicalizeError code "depth" past 32 levels of nesting', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < 35; i++) deep = { next: deep };
    try {
      canonicalJsonString(deep);
      expect.fail('expected CanonicalizeError');
    } catch (e) {
      expect((e as CanonicalizeError).code).toBe('depth');
    }
  });

  it('accepts depth up to 32 levels', () => {
    let deep: unknown = 'leaf';
    for (let i = 0; i < 32; i++) deep = { n: deep };
    expect(() => canonicalJsonString(deep)).not.toThrow();
  });

  it('throws CanonicalizeError code "string-too-long" past 64 KiB UTF-8', () => {
    const huge = 'a'.repeat(64 * 1024 + 1);
    try {
      canonicalJsonString(huge);
      expect.fail('expected CanonicalizeError');
    } catch (e) {
      expect((e as CanonicalizeError).code).toBe('string-too-long');
    }
  });

  it('accepts strings exactly at the 64 KiB UTF-8 limit', () => {
    const max = 'a'.repeat(64 * 1024);
    expect(() => canonicalJsonString(max)).not.toThrow();
  });

  it('measures string length in UTF-8 bytes, not code units', () => {
    // A 3-byte UTF-8 character counted properly: 22000 × 3 = 66000 > 65536.
    const s = '中'.repeat(22000); // each '中' is 3 UTF-8 bytes
    try {
      canonicalJsonString(s);
      expect.fail('expected CanonicalizeError');
    } catch (e) {
      expect((e as CanonicalizeError).code).toBe('string-too-long');
    }
  });

  it('CanonicalizeError is an Error subclass with name and code field', () => {
    try {
      canonicalJsonString(1.5);
    } catch (e) {
      const err = e as CanonicalizeError;
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(CanonicalizeError);
      expect(err.name).toBe('CanonicalizeError');
      expect(typeof err.code).toBe('string');
    }
  });
});
