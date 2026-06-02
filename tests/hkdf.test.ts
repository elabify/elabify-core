import { describe, expect, it } from 'vitest';
import { hkdfSha256 } from '../src/hkdf.js';
import { hexToBytes, bytesToHex } from '../src/hex.js';

// RFC 5869 official test vectors. These pin the byte-exact behavior of
// HKDF-SHA-256 across every binding (TS, Swift CryptoKit, Kotlin). Any
// regression in extract/expand surfaces immediately.

describe('hkdfSha256 — RFC 5869 vectors', () => {
  it('Test Case 1 (basic): 22-byte IKM, 13-byte salt, 10-byte info, 42-byte OKM', () => {
    const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const salt = hexToBytes('000102030405060708090a0b0c');
    const info = hexToBytes('f0f1f2f3f4f5f6f7f8f9');
    const okm = hkdfSha256(ikm, salt, info, 42);
    expect(bytesToHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a' +
      '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
      '34007208d5b887185865',
    );
  });

  it('Test Case 2 (longer): 80-byte IKM, 80-byte salt, 80-byte info, 82-byte OKM', () => {
    const ikm = hexToBytes(
      '000102030405060708090a0b0c0d0e0f' +
      '101112131415161718191a1b1c1d1e1f' +
      '202122232425262728292a2b2c2d2e2f' +
      '303132333435363738393a3b3c3d3e3f' +
      '404142434445464748494a4b4c4d4e4f',
    );
    const salt = hexToBytes(
      '606162636465666768696a6b6c6d6e6f' +
      '707172737475767778797a7b7c7d7e7f' +
      '808182838485868788898a8b8c8d8e8f' +
      '909192939495969798999a9b9c9d9e9f' +
      'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    );
    const info = hexToBytes(
      'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
      'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
      'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
      'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
      'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    );
    const okm = hkdfSha256(ikm, salt, info, 82);
    expect(bytesToHex(okm)).toBe(
      'b11e398dc80327a1c8e7f78c596a4934' +
      '4f012eda2d4efad8a050cc4c19afa97c' +
      '59045a99cac7827271cb41c65e590e09' +
      'da3275600c2f09b8367793a9aca3db71' +
      'cc30c58179ec3e87c14c01d5c1f3434f' +
      '1d87',
    );
  });

  it('Test Case 3 (empty salt + info): 22-byte IKM, 42-byte OKM', () => {
    const ikm = hexToBytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const okm = hkdfSha256(ikm, new Uint8Array(0), new Uint8Array(0), 42);
    expect(bytesToHex(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31' +
      'b8a11f5c5ee1879ec3454e5f3c738d2d' +
      '9d201395faa4b61a96c8',
    );
  });
});

describe('hkdfSha256 — input validation', () => {
  it('rejects length <= 0', () => {
    expect(() => hkdfSha256(new Uint8Array([1]), new Uint8Array(0), new Uint8Array(0), 0)).toThrow(RangeError);
    expect(() => hkdfSha256(new Uint8Array([1]), new Uint8Array(0), new Uint8Array(0), -1)).toThrow(RangeError);
  });

  it('rejects length > 255*HashLen (8160 for SHA-256)', () => {
    expect(() => hkdfSha256(new Uint8Array([1]), new Uint8Array(0), new Uint8Array(0), 8161)).toThrow(RangeError);
  });

  it('rejects non-integer length', () => {
    expect(() => hkdfSha256(new Uint8Array([1]), new Uint8Array(0), new Uint8Array(0), 32.5)).toThrow(RangeError);
    expect(() => hkdfSha256(new Uint8Array([1]), new Uint8Array(0), new Uint8Array(0), NaN)).toThrow(RangeError);
  });

  it('accepts boundary length 8160', () => {
    const okm = hkdfSha256(new Uint8Array([0x42]), new Uint8Array(0), new Uint8Array(0), 8160);
    expect(okm.length).toBe(8160);
  });
});

describe('hkdfSha256 — determinism', () => {
  it('same inputs produce same output', () => {
    const ikm = hexToBytes('deadbeef');
    const salt = hexToBytes('cafebabe');
    const info = hexToBytes('1234');
    const a = hkdfSha256(ikm, salt, info, 32);
    const b = hkdfSha256(ikm, salt, info, 32);
    expect(a).toEqual(b);
  });

  it('different info produces different output', () => {
    const ikm = hexToBytes('deadbeef');
    const salt = hexToBytes('cafebabe');
    const a = hkdfSha256(ikm, salt, hexToBytes('00'), 32);
    const b = hkdfSha256(ikm, salt, hexToBytes('01'), 32);
    expect(a).not.toEqual(b);
  });

  it('returns exactly `length` bytes', () => {
    expect(hkdfSha256(new Uint8Array([0x42]), new Uint8Array(0), new Uint8Array(0), 1).length).toBe(1);
    expect(hkdfSha256(new Uint8Array([0x42]), new Uint8Array(0), new Uint8Array(0), 32).length).toBe(32);
    expect(hkdfSha256(new Uint8Array([0x42]), new Uint8Array(0), new Uint8Array(0), 64).length).toBe(64);
  });
});
