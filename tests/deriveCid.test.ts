import { describe, expect, it } from 'vitest';
import { deriveCid, sortClaimKeys } from '../src/deriveCid.js';

describe('deriveCid', () => {
  const baseHeader = {
    v: 1,
    alg: 'ML-DSA-65',
    hash: 'RPO-256',
    iss: 'did:elabify:local:issuer:dev',
    sub: 'did:elabify:local:user:0xfeed',
    iat: 1_700_000_000,
    exp: 1_700_086_400,
    root: '0x' + '11'.repeat(32),
    schema: 'elabify://schema/global/passport/v1',
  } as const;

  it('returns 32 bytes', () => {
    const cid = deriveCid(baseHeader, baseHeader.iat);
    expect(cid.length).toBe(32);
  });

  it('is deterministic (same inputs → same cid)', () => {
    const a = deriveCid(baseHeader, baseHeader.iat);
    const b = deriveCid(baseHeader, baseHeader.iat);
    expect(a).toEqual(b);
  });

  it('changes when iat changes', () => {
    const a = deriveCid(baseHeader, baseHeader.iat);
    const b = deriveCid(baseHeader, baseHeader.iat + 1);
    expect(a).not.toEqual(b);
  });

  it('changes when any header field changes', () => {
    const a = deriveCid(baseHeader, baseHeader.iat);
    const b = deriveCid({ ...baseHeader, sub: 'did:elabify:local:user:0xbeef' }, baseHeader.iat);
    expect(a).not.toEqual(b);
  });

  it('rejects negative or non-integer iat', () => {
    expect(() => deriveCid(baseHeader, -1)).toThrow(/iat/);
    expect(() => deriveCid(baseHeader, 1.5)).toThrow(/iat/);
  });
});

describe('sortClaimKeys', () => {
  it('sorts keys by Unicode code point', () => {
    expect(sortClaimKeys({ b: 1, a: 2, c: 3 })).toEqual(['a', 'b', 'c']);
  });

  it('handles mixed-script keys deterministically', () => {
    const keys = sortClaimKeys({ z: 1, '日本': 2, a: 3, '0': 4 });
    // Code-point order: '0' < 'a' < 'z' < '日'
    expect(keys).toEqual(['0', 'a', 'z', '日本']);
  });

  it('returns a fresh array (does not mutate the input ordering of new objects)', () => {
    const claims = { b: 1, a: 2 };
    const sorted = sortClaimKeys(claims);
    expect(sorted).toEqual(['a', 'b']);
    expect(Object.keys(claims)).toEqual(['b', 'a']);
  });
});
