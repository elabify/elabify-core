// @elabify/core - Phase 0 skinny TypeScript cut.
//
// Public API matches the spec in elabify-core/README.md §4.1, with the
// known divergences documented in each module's file header. Phase 0 ports
// the demo's behavior byte-for-byte (truncation, empty-leaf padding, JSON
// stringify-not-canonicalize-for-values quirks included). M0 proper extends
// this code to the full spec and regenerates the KAT corpus.
//
// See ADR-0017 (TS canonical) and ADR-0019 (Phase 0 sequencing).

export { rpo256, rpo256Hex, rpo256Tagged } from './rpo256.js';
export { canonicalize, canonicalJsonString, CanonicalizeError } from './canonicalJson.js';
export type { CanonicalizeErrorCode } from './canonicalJson.js';
export {
  leafHash,
  claimLeafHash,
  emptyLeafHash,
  MerkleTree,
  verifyMerkleProof,
} from './merkle.js';
export type { MerkleProofEntry } from './merkle.js';
export { deriveCid, sortClaimKeys } from './deriveCid.js';
export { hkdfSha256 } from './hkdf.js';
export { parseDID, formatDID, DIDError } from './did.js';
export type { DID, DIDErrorCode } from './did.js';
export { bytesToHex, hexToBytes, utf8 } from './hex.js';
export type { Bytes, ClaimEntry } from './types.js';
