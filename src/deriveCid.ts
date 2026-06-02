// Credential ID derivation per the wire-format spec §4.3.
//
// Input bytes:  0x04 (domain tag) || canonicalize({...header, cid:''}) || u64BE(iat)
// Output:       rpo256 of the input bytes - 32 bytes
//
// Phase 0 NOTE: matches the wire-formats.md spec exactly. Relies on the
// post-correction sponge construction in rpo256.ts (per ADR-0020) - pre-fix
// the multi-block input would have been silently truncated to its first 64 B.

import { canonicalize } from './canonicalJson.js';
import { rpo256 } from './rpo256.js';

const CID_DOMAIN_TAG = 0x04;

/**
 * Derive a 32-byte credential ID from a header (without `cid` set) and the
 * issued-at timestamp. The result is collision-resistant and self-binding -
 * any party with the header can recompute the CID without trusting the issuer.
 *
 * Returns 32 bytes (Uint8Array). Callers that need the wire-format hex form
 * prepend `0x` and lower-case-hex-encode.
 */
export function deriveCid(headerWithoutCid: Record<string, unknown>, iat: number): Uint8Array {
  if (!Number.isInteger(iat) || iat < 0) {
    throw new Error(`deriveCid: iat must be a non-negative integer, got ${iat}`);
  }
  const headerBytes = canonicalize({ ...headerWithoutCid, cid: '' });

  const total = new Uint8Array(1 + headerBytes.length + 8);
  total[0] = CID_DOMAIN_TAG;
  total.set(headerBytes, 1);

  // u64 big-endian of iat
  let n = BigInt(iat);
  for (let i = 7; i >= 0; i--) {
    total[1 + headerBytes.length + i] = Number(n & 0xffn);
    n >>= 8n;
  }

  return rpo256(total);
}

/**
 * Sort a claim-set's keys lexicographically by Unicode code point. The
 * resulting order is what the Merkle tree's `MerkleTree` constructor expects
 * (the leaf at index `i` corresponds to claim key `sortedKeys[i]`).
 *
 * Per wire-formats.md §3.1 #1, the comparison is by code-unit value (UTF-16),
 * which matches JavaScript `Array.prototype.sort()` default behavior on strings.
 */
export function sortClaimKeys(claims: Readonly<Record<string, unknown>>): string[] {
  return Object.keys(claims).sort();
}
