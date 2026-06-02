import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, utf8 } from '../src/hex.js';

describe('hex', () => {
  it('round-trips arbitrary bytes', () => {
    const cases = [
      new Uint8Array([]),
      new Uint8Array([0x00]),
      new Uint8Array([0xff]),
      new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xff]),
    ];
    for (const bytes of cases) {
      expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
    }
  });

  it('emits lowercase hex without 0x prefix', () => {
    expect(bytesToHex(new Uint8Array([0xAB, 0xcd]))).toBe('abcd');
  });

  it('hexToBytes accepts both 0x-prefixed and bare hex', () => {
    expect(hexToBytes('0xabcd')).toEqual(new Uint8Array([0xab, 0xcd]));
    expect(hexToBytes('abcd')).toEqual(new Uint8Array([0xab, 0xcd]));
  });

  it('hexToBytes rejects odd-length input', () => {
    expect(() => hexToBytes('abc')).toThrow(/odd-length/);
  });

  it('hexToBytes rejects non-hex characters', () => {
    expect(() => hexToBytes('zz')).toThrow(/invalid hex/);
  });

  it('utf8 encodes ASCII and multi-byte chars', () => {
    expect(utf8('a')).toEqual(new Uint8Array([0x61]));
    expect(utf8('£')).toEqual(new Uint8Array([0xc2, 0xa3]));
  });
});
