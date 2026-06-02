// RPO-256 hash over the Goldilocks field. Ported from the post-correction
// v2 demo (the demo web app lines 924-967),
// after the pre-ship sponge correction documented in ADR-0020.
//
// Sponge construction:
//   - State: 12 field elements (rate=8, capacity=4)
//   - Absorption: input padded with 0x01 then zeros to a 64-byte boundary
//     (always at least one full pad block); each 64-byte block is packed into
//     state[0..7] little-endian, added (mod p) into the rate, then the full
//     state is permuted via 7 rounds of Rescue-Prime-Optimized.
//   - Squeeze: 32 bytes are read from state[0..3] little-endian after the
//     final permutation.
//
// Public API mirrors the spec in elabify-core/README.md §4.1. Three
// surface forms exist:
//   - rpo256(bytes_or_string)     → Uint8Array (32 B)   - primary spec API
//   - rpo256Hex(bytes_or_string)  → 64-char lowercase hex
//   - rpo256TwoHex(aHex, bHex)    → 64-char hex of rpo256Hex(aHex + bHex),
//     preserved for the Merkle code's string-concat chaining (matches the
//     demo's `rpoTwo`).
//
// See ADR-0017 §4.1 (TS canonical), ADR-0019 (Phase 0 sequencing),
// ADR-0020 (sponge correction).

import { bytesToHex, utf8 } from './hex.js';

const P = (2n ** 64n) - (2n ** 32n) + 1n;
const ALPHA = 7n;
const AINV = 10540996611094048183n;

// 12×12 MDS matrix (circulant). Constants from the demo.
const MDS: readonly (readonly bigint[])[] = [
  [7n, 23n, 8n, 26n, 20n, 7n, 1n, 20n, 4n, 8n, 1n, 1n],
  [8n, 7n, 23n, 8n, 26n, 20n, 7n, 1n, 20n, 4n, 8n, 1n],
  [1n, 8n, 7n, 23n, 8n, 26n, 20n, 7n, 1n, 20n, 4n, 8n],
  [8n, 1n, 8n, 7n, 23n, 8n, 26n, 20n, 7n, 1n, 20n, 4n],
  [4n, 8n, 1n, 8n, 7n, 23n, 8n, 26n, 20n, 7n, 1n, 20n],
  [20n, 4n, 8n, 1n, 8n, 7n, 23n, 8n, 26n, 20n, 7n, 1n],
  [1n, 20n, 4n, 8n, 1n, 8n, 7n, 23n, 8n, 26n, 20n, 7n],
  [7n, 1n, 20n, 4n, 8n, 1n, 8n, 7n, 23n, 8n, 26n, 20n],
  [20n, 7n, 1n, 20n, 4n, 8n, 1n, 8n, 7n, 23n, 8n, 26n],
  [26n, 20n, 7n, 1n, 20n, 4n, 8n, 1n, 8n, 7n, 23n, 8n],
  [8n, 26n, 20n, 7n, 1n, 20n, 4n, 8n, 1n, 8n, 7n, 23n],
  [23n, 8n, 26n, 20n, 7n, 1n, 20n, 4n, 8n, 1n, 8n, 7n],
];

// Round constants (24 values, cycled across the 7×2 half-round positions).
const RC: readonly bigint[] = [
  7096123747201n, 3073462498391n, 5423984235601n, 1234987654321n,
  9876543210123n, 2345678901234n, 8765432109876n, 4567890123456n,
  6789012345678n, 9012345678901n, 1357924680135n, 2468013579246n,
  3141592653589n, 2718281828459n, 1618033988749n, 1414213562373n,
  1732050808567n, 2236067977499n, 2449489742783n, 2645751311064n,
  2828427124746n, 3000000000000n, 3141592653589n, 3316624790355n,
];

const fm = (a: bigint): bigint => ((a % P) + P) % P;

function fmp(b: bigint, e: bigint): bigint {
  let r = 1n;
  let base = fm(b);
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) r = fm(r * base);
    base = fm(base * base);
    exp >>= 1n;
  }
  return r;
}

function fmds(s: bigint[]): bigint[] {
  const o = new Array<bigint>(12).fill(0n);
  for (let i = 0; i < 12; i++) {
    let v = 0n;
    for (let j = 0; j < 12; j++) {
      v = fm(v + fm((MDS[i] as readonly bigint[])[j] as bigint * (s[j] as bigint)));
    }
    o[i] = v;
  }
  return o;
}

/** RPO permutation: 7 rounds of (add round-const, S-box forward, MDS, add round-const, S-box inverse, MDS). */
function rpo(state: readonly bigint[]): bigint[] {
  let x = [...state];
  for (let r = 0; r < 7; r++) {
    for (let i = 0; i < 12; i++) {
      x[i] = fm((x[i] as bigint) + (RC[(r * 24 + i) % RC.length] as bigint));
    }
    x = x.map((v) => fmp(v, ALPHA));
    x = fmds(x);
    for (let i = 0; i < 12; i++) {
      x[i] = fm((x[i] as bigint) + (RC[(r * 24 + 12 + i) % RC.length] as bigint));
    }
    x = x.map((v) => fmp(v, AINV));
    x = fmds(x);
  }
  return x;
}

/**
 * RPO-256 hash. Returns 32 bytes.
 *
 * Input may be a UTF-8 string (encoded via TextEncoder) or a Uint8Array.
 * Internally a sponge: 64-byte rate, 32-byte capacity, additive absorption
 * with `10*` padding to a 64-byte boundary (always at least one pad block).
 */
export function rpo256(input: Uint8Array | string): Uint8Array {
  const b = typeof input === 'string' ? utf8(input) : input;

  // Pad with 0x01 followed by zeros to a 64-byte boundary. Always adds at
  // least one byte (so an exactly-64-byte input gets a fresh pad block).
  const padLen = 64 - (b.length % 64);
  const padded = new Uint8Array(b.length + padLen);
  padded.set(b);
  padded[b.length] = 0x01;

  let s = new Array<bigint>(12).fill(0n);
  const blocks = padded.length / 64;

  for (let blk = 0; blk < blocks; blk++) {
    // Pack 64 bytes into state[0..7], little-endian within each 8-byte limb.
    for (let i = 0; i < 8; i++) {
      let v = 0n;
      for (let j = 0; j < 8; j++) {
        v |= BigInt(padded[blk * 64 + i * 8 + j] as number) << BigInt(j * 8);
      }
      s[i] = fm((s[i] as bigint) + v);
    }
    // Capacity (s[8..11]) absorbs nothing this block; permutation mixes.
    s = rpo(s);
  }

  // Squeeze 32 bytes from state[0..3], little-endian per limb.
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    let v = s[i] as bigint;
    for (let k = 0; k < 8; k++) {
      out[i * 8 + k] = Number(v & 0xffn);
      v >>= 8n;
    }
  }
  return out;
}

/** RPO-256 hash returning lowercase hex (no `0x` prefix). */
export function rpo256Hex(input: Uint8Array | string): string {
  return bytesToHex(rpo256(input));
}

/**
 * RPO-256 with a 1-byte domain-separation tag prepended. Returns 32 bytes.
 *
 * Equivalent to `rpo256([tag, ...input])`. Used at every domain-separated
 * hashing site per the wire-format spec §3 and §4.3:
 *   - 0x01 leaf hash
 *   - 0x02 Merkle inner node
 *   - 0x03 user-identifier derivation
 *   - 0x04 credential-id derivation
 *
 * `tag` must be a u8 in [0, 255]; throws RangeError otherwise.
 */
export function rpo256Tagged(tag: number, input: Uint8Array): Uint8Array {
  if (!Number.isInteger(tag) || tag < 0 || tag > 255) {
    throw new RangeError(
      `rpo256Tagged: tag must be an integer in [0, 255], got ${tag}`,
    );
  }
  const tagged = new Uint8Array(1 + input.length);
  tagged[0] = tag;
  tagged.set(input, 1);
  return rpo256(tagged);
}

/**
 * RPO-256 of two hex strings concatenated as ASCII bytes (the demo's
 * `rpoTwo` shape). With the sponge correction, both inputs now influence
 * the output - see ADR-0020. Used by the Merkle code's chaining.
 */
export function rpo256TwoHex(a: string, b: string): string {
  return rpo256Hex(a + b);
}
