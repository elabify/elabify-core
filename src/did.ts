// did:elabify parsing and formatting per ADR-0021 and
// the wire-format spec §2.
//
// Grammar (exactly five colon-separated components):
//   did:elabify:<network>:<entityType>:<identifier>
//
// Examples:
//   did:elabify:adgm:issuer:bank-of-abu-dhabi
//   did:elabify:adgm:user:0x1a2b3c4d5e6f7890abcdef0123456789abcdef01
//   did:elabify:sepolia:issuer:dev
//   did:elabify:local:verifier:dev
//
// The scheme (`did`) and method (`elabify`) are required to be lowercase
// per RFC 3986 §3.1 and W3C DID Core §3.1 — implementations MUST NOT
// accept mixed-case forms. The remaining three components (network,
// entityType, identifier) are case-sensitive per W3C DID Core §3.1.
//
// Public API matches the spec in elabify-core/README.md §4.1.

const DID_PREFIX = 'did:elabify:';
const EXPECTED_PARTS = 5;

export interface DID {
  readonly network: string;
  readonly entityType: string;
  readonly identifier: string;
}

export type DIDErrorCode = 'malformed' | 'extra-colons' | 'empty-component';

export class DIDError extends Error {
  readonly code: DIDErrorCode;
  constructor(code: DIDErrorCode, message: string) {
    super(message);
    this.name = 'DIDError';
    this.code = code;
  }
}

/**
 * Parse a `did:elabify:<network>:<entityType>:<identifier>` string into its
 * three semantic components.
 *
 * Throws `DIDError`:
 *   - code 'malformed' when the input doesn't have exactly 5 colon-separated
 *     parts, or when scheme/method aren't exactly `did`/`elabify` lowercase.
 *   - code 'extra-colons' when the identifier itself contains a `:`
 *     (e.g. `did:elabify:adgm:user:foo:bar` has 6 parts and the colon-in-
 *     identifier is the diagnostic the spec wants surfaced separately).
 *   - code 'empty-component' when any of network / entityType / identifier
 *     is the empty string.
 */
export function parseDID(s: string): DID {
  if (typeof s !== 'string') {
    throw new DIDError('malformed', `parseDID: input must be a string, got ${typeof s}`);
  }
  const parts = s.split(':');
  if (parts.length > EXPECTED_PARTS) {
    throw new DIDError(
      'extra-colons',
      `parseDID: too many colons in ${JSON.stringify(s)} — identifier component must not contain ':'`,
    );
  }
  if (parts.length !== EXPECTED_PARTS) {
    throw new DIDError(
      'malformed',
      `parseDID: ${JSON.stringify(s)} is not a did:elabify: DID (expected exactly 5 colon-separated components)`,
    );
  }
  if (parts[0] !== 'did' || parts[1] !== 'elabify') {
    throw new DIDError(
      'malformed',
      `parseDID: ${JSON.stringify(s)} is not a did:elabify: DID (must start with lowercase 'did:elabify:')`,
    );
  }
  const network = parts[2] as string;
  const entityType = parts[3] as string;
  const identifier = parts[4] as string;
  if (network === '' || entityType === '' || identifier === '') {
    throw new DIDError(
      'empty-component',
      `parseDID: ${JSON.stringify(s)} has an empty network / entityType / identifier component`,
    );
  }
  return { network, entityType, identifier };
}

/**
 * Format a DID struct back to its string form. No validation — callers that
 * constructed an invalid struct internally see the bad output and that's a
 * caller bug. Round-trip property: formatDID(parseDID(s)) === s for any s
 * that parseDID accepts.
 */
export function formatDID(did: DID): string {
  return DID_PREFIX + did.network + ':' + did.entityType + ':' + did.identifier;
}
