// HKDF-SHA-256 per RFC 5869.
//
// Used wherever Elabify derives bytes deterministically from a secret +
// context: verifier challenge derivation (verifier-server §"/v1/challenge"),
// holder long-term key derivation from a recovery seed (M4a iOS holder),
// and KAT-vector inputs for cross-platform binding consistency.
//
// Public API matches the spec in elabify-core/README.md §4.1. The
// underlying primitive is delegated to @noble/hashes/hkdf which provides
// the RFC 5869 extract/expand decomposition in pure JS for both Node and
// browser runtimes. The Swift port (bindings/swift) uses CryptoKit's
// HKDF<SHA256>; the Kotlin port uses javax.crypto's Mac/HKDF combinator.
// All three are verified byte-identical via the KAT corpus.

import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';

/**
 * HKDF-SHA-256 derivation.
 *
 * @param ikm Initial keying material (the secret). Any length.
 * @param salt Optional salt (per RFC 5869 §3.1). Passing an empty Uint8Array
 *             is equivalent to omitting the salt; the extract step uses a
 *             zero-string of HashLen bytes in that case.
 * @param info Context-specific application info. Bound into the output.
 * @param length Desired output length in bytes. Must be in (0, 255 * 32].
 * @returns `length` bytes of derived key material.
 *
 * Throws if `length` is non-positive or exceeds 255 * 32 = 8160 bytes
 * (the RFC 5869 maximum for SHA-256).
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new RangeError(
      `hkdfSha256: length must be a positive integer, got ${length}`,
    );
  }
  if (length > 255 * 32) {
    throw new RangeError(
      `hkdfSha256: length ${length} exceeds RFC 5869 maximum of 255*HashLen = 8160 bytes for SHA-256`,
    );
  }
  return hkdf(sha256, ikm, salt, info, length);
}
