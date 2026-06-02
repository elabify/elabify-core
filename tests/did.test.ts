import { describe, expect, it } from 'vitest';
import { parseDID, formatDID, DIDError, type DID } from '../src/did.js';

describe('parseDID — happy path', () => {
  it('parses an issuer DID', () => {
    expect(parseDID('did:elabify:adgm:issuer:bank-of-abu-dhabi')).toEqual({
      network: 'adgm',
      entityType: 'issuer',
      identifier: 'bank-of-abu-dhabi',
    });
  });

  it('parses a user DID with hex identifier', () => {
    expect(parseDID('did:elabify:adgm:user:0x1a2b3c4d5e6f7890abcdef0123456789abcdef01')).toEqual({
      network: 'adgm',
      entityType: 'user',
      identifier: '0x1a2b3c4d5e6f7890abcdef0123456789abcdef01',
    });
  });

  it('parses a verifier DID', () => {
    expect(parseDID('did:elabify:eth:verifier:uniswap-v4-hook-0x1234')).toEqual({
      network: 'eth',
      entityType: 'verifier',
      identifier: 'uniswap-v4-hook-0x1234',
    });
  });

  it('parses a Sepolia issuer DID (from the live Phase 0 stack)', () => {
    expect(parseDID('did:elabify:sepolia:issuer:dev')).toEqual({
      network: 'sepolia',
      entityType: 'issuer',
      identifier: 'dev',
    });
  });
});

describe('parseDID — error cases', () => {
  it('rejects too few colons with code "malformed"', () => {
    expect(() => parseDID('did:elabify:adgm:issuer')).toThrow(DIDError);
    try {
      parseDID('did:elabify:adgm:issuer');
    } catch (e) {
      expect((e as DIDError).code).toBe('malformed');
    }
  });

  it('rejects extra colons in identifier with code "extra-colons"', () => {
    try {
      parseDID('did:elabify:adgm:user:foo:bar');
      expect.fail('expected DIDError');
    } catch (e) {
      expect(e).toBeInstanceOf(DIDError);
      expect((e as DIDError).code).toBe('extra-colons');
    }
  });

  it('rejects wrong scheme with code "malformed"', () => {
    try {
      parseDID('urn:elabify:adgm:issuer:dev');
      expect.fail('expected DIDError');
    } catch (e) {
      expect((e as DIDError).code).toBe('malformed');
    }
  });

  it('rejects wrong method with code "malformed"', () => {
    try {
      parseDID('did:other:adgm:issuer:dev');
      expect.fail('expected DIDError');
    } catch (e) {
      expect((e as DIDError).code).toBe('malformed');
    }
  });

  it('rejects mixed-case scheme/method with code "malformed"', () => {
    try {
      parseDID('DID:Elabify:adgm:issuer:dev');
      expect.fail('expected DIDError');
    } catch (e) {
      expect((e as DIDError).code).toBe('malformed');
    }
  });

  it('rejects empty network with code "empty-component"', () => {
    try {
      parseDID('did:elabify::issuer:dev');
      expect.fail('expected DIDError');
    } catch (e) {
      expect((e as DIDError).code).toBe('empty-component');
    }
  });

  it('rejects empty entityType with code "empty-component"', () => {
    try {
      parseDID('did:elabify:adgm::dev');
      expect.fail('expected DIDError');
    } catch (e) {
      expect((e as DIDError).code).toBe('empty-component');
    }
  });

  it('rejects empty identifier with code "empty-component"', () => {
    try {
      parseDID('did:elabify:adgm:issuer:');
      expect.fail('expected DIDError');
    } catch (e) {
      expect((e as DIDError).code).toBe('empty-component');
    }
  });

  it('rejects non-string input', () => {
    expect(() => parseDID(null as unknown as string)).toThrow(DIDError);
    expect(() => parseDID(undefined as unknown as string)).toThrow(DIDError);
    expect(() => parseDID(123 as unknown as string)).toThrow(DIDError);
  });
});

describe('formatDID', () => {
  it('joins the three components with the did:elabify: prefix', () => {
    expect(formatDID({ network: 'adgm', entityType: 'issuer', identifier: 'dev' })).toBe(
      'did:elabify:adgm:issuer:dev',
    );
  });

  it('round-trips for every parseDID-accepting input', () => {
    const inputs = [
      'did:elabify:adgm:issuer:bank-of-abu-dhabi',
      'did:elabify:adgm:user:0x1a2b3c4d5e6f7890abcdef0123456789abcdef01',
      'did:elabify:eth:verifier:uniswap-v4-hook-0x1234',
      'did:elabify:sepolia:issuer:dev',
      'did:elabify:local:verifier:dev',
      'did:elabify:sepolia:issuer:corporate',
    ];
    for (const s of inputs) {
      expect(formatDID(parseDID(s))).toBe(s);
    }
  });
});

describe('DIDError', () => {
  it('is an Error subclass with name "DIDError" and a code field', () => {
    try {
      parseDID('not a did');
    } catch (e) {
      const err = e as DIDError;
      expect(err).toBeInstanceOf(Error);
      expect(err).toBeInstanceOf(DIDError);
      expect(err.name).toBe('DIDError');
      expect(typeof err.code).toBe('string');
      expect(['malformed', 'extra-colons', 'empty-component']).toContain(err.code);
    }
  });
});

// Type-only smoke test: ensures the exported DID type stays read-only-shaped.
const _typeSmoke: DID = { network: 'x', entityType: 'y', identifier: 'z' };
void _typeSmoke;
