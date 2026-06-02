import { describe, expect, it } from 'vitest';
import { rpo256, rpo256Hex, rpo256TwoHex, rpo256Tagged } from '../src/rpo256.js';

describe('rpo256', () => {
  it('returns exactly 32 bytes', () => {
    expect(rpo256(new Uint8Array([])).length).toBe(32);
    expect(rpo256(new Uint8Array([0x42])).length).toBe(32);
    expect(rpo256('hello world').length).toBe(32);
  });

  it('is deterministic (same input → same output)', () => {
    const a = rpo256('test');
    const b = rpo256('test');
    expect(a).toEqual(b);
  });

  it('different inputs produce different outputs (within the 64-byte rate)', () => {
    expect(rpo256('a')).not.toEqual(rpo256('b'));
    expect(rpo256(new Uint8Array([0]))).not.toEqual(rpo256(new Uint8Array([1])));
  });

  it('inputs > 64 bytes are NOT silently truncated (sponge correction, ADR-0020)', () => {
    // Regression-blocker for the pre-ship truncation bug. With the sponge
    // construction, inputs longer than the 64-byte rate must influence the
    // output across all blocks. If a future change reintroduces the
    // single-permutation construction, this test fires immediately.
    const sixtyFour = 'A'.repeat(64);
    const sixtyFourPlus = sixtyFour + 'XXXXXXXX';
    expect(rpo256(sixtyFour)).not.toEqual(rpo256(sixtyFourPlus));
  });

  it('rpo256TwoHex(a, b) is sensitive to BOTH arguments (post-ADR-0020)', () => {
    // The pre-fix bug made rpo256TwoHex(a, b) === rpo256Hex(a) because the
    // 128-byte ASCII concatenation got truncated to its first 64 bytes (= a).
    // This test pins the corrected behavior so any regression of the sponge
    // construction surfaces immediately, even before the cascading symptoms
    // (broken Merkle commitment, broken selective disclosure) are reached.
    const a = rpo256Hex('alpha');
    const b1 = rpo256Hex('beta');
    const b2 = rpo256Hex('gamma');
    expect(rpo256TwoHex(a, b1)).not.toBe(rpo256Hex(a));
    expect(rpo256TwoHex(a, b1)).not.toBe(rpo256TwoHex(a, b2));
  });

  it('rpo256Hex returns 64 lowercase hex chars', () => {
    const hex = rpo256Hex('test');
    expect(hex).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rpo256Hex matches bytesToHex(rpo256())', () => {
    const fromBytes = rpo256('test');
    const fromHex = rpo256Hex('test');
    expect(fromHex.length).toBe(64);
    let asBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      asBytes[i] = parseInt(fromHex.slice(i * 2, i * 2 + 2), 16);
    }
    expect(asBytes).toEqual(fromBytes);
  });

  it('rpo256TwoHex(a, b) equals rpo256Hex(a + b) (string-concat semantics)', () => {
    const a = rpo256Hex('alpha');
    const b = rpo256Hex('beta');
    expect(rpo256TwoHex(a, b)).toBe(rpo256Hex(a + b));
  });
});

describe('rpo256Tagged', () => {
  it('returns exactly 32 bytes', () => {
    expect(rpo256Tagged(0x01, new Uint8Array([])).length).toBe(32);
    expect(rpo256Tagged(0x04, new Uint8Array([0x42, 0x43])).length).toBe(32);
  });

  it('equals rpo256([tag, ...input]) (manual construction)', () => {
    const input = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const manual = new Uint8Array(1 + input.length);
    manual[0] = 0x04;
    manual.set(input, 1);
    expect(rpo256Tagged(0x04, input)).toEqual(rpo256(manual));
  });

  it('different tags produce different outputs for the same input', () => {
    const input = new Uint8Array([0x00, 0x01, 0x02]);
    expect(rpo256Tagged(0x01, input)).not.toEqual(rpo256Tagged(0x02, input));
    expect(rpo256Tagged(0x03, input)).not.toEqual(rpo256Tagged(0x04, input));
  });

  it('rejects out-of-range tags', () => {
    expect(() => rpo256Tagged(-1, new Uint8Array([]))).toThrow(RangeError);
    expect(() => rpo256Tagged(256, new Uint8Array([]))).toThrow(RangeError);
    expect(() => rpo256Tagged(1.5, new Uint8Array([]))).toThrow(RangeError);
    expect(() => rpo256Tagged(NaN, new Uint8Array([]))).toThrow(RangeError);
  });

  it('accepts tag boundary values 0 and 255', () => {
    expect(rpo256Tagged(0, new Uint8Array([])).length).toBe(32);
    expect(rpo256Tagged(255, new Uint8Array([])).length).toBe(32);
  });
});
