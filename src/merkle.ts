// Merkle tree construction per the wire-format spec §4 and
// elabify-core/README.md §5.3 — M0 spec-compliant.
//
// Construction:
//   leaf(k, v)    = rpo256(0x01 ‖ rpo256(utf8(nfc(k))) ‖ rpo256(canonicalize(v)))
//   emptyLeaf(i)  = rpo256(0x00 ‖ u64BE(i))
//   inner(l, r)   = rpo256(0x02 ‖ l ‖ r)
//
// Padding: leaves are padded with `emptyLeaf(i)` (index-tagged) up to the
// next power of two with a minimum of 8. Per-index empties block
// second-preimage attacks against padded slots — an attacker who finds
// a (key, value) that hashes to the empty-leaf-0 cannot reuse that
// finding at slot 5.
//
// Proof structure: each entry carries the sibling node and a flag for
// whether the sibling sits on the right. Verification reconstructs the
// root by hashing pairs with the inner-node combinator. `isRight === true`
// means current node is LEFT, sibling is RIGHT.
//
// External callers should use `claimLeafHash(key, value)` rather than the
// spec primitive `leafHash(keyBytes, valueBytes)` — the wrapper handles
// the NFC + canonicalize + double-rpo256 boilerplate so call sites stay
// readable.

import { canonicalize } from './canonicalJson.js';
import { bytesToHex, utf8 } from './hex.js';
import { rpo256, rpo256Tagged } from './rpo256.js';

const TAG_EMPTY_LEAF = 0x00;
const TAG_LEAF = 0x01;
const TAG_INNER = 0x02;
const MIN_PADDED_SIZE = 8;

export interface MerkleProofEntry {
  /** Sibling hash at this layer of the tree, 32 bytes. */
  readonly sibling: Uint8Array;
  /** True iff the sibling sits on the right of the current node. */
  readonly isRight: boolean;
}

/**
 * Spec primitive: leaf hash from two byte-encoded inputs.
 *
 * Computes `rpo256(0x01 ‖ rpo256(keyBytes) ‖ rpo256(valueBytes))`. Callers
 * pre-encode the key (UTF-8 of NFC-normalized string) and value (canonical
 * JSON bytes). Most callers want `claimLeafHash` instead.
 */
export function leafHash(keyBytes: Uint8Array, valueBytes: Uint8Array): Uint8Array {
  const kh = rpo256(keyBytes);
  const vh = rpo256(valueBytes);
  const buf = new Uint8Array(kh.length + vh.length);
  buf.set(kh, 0);
  buf.set(vh, kh.length);
  return rpo256Tagged(TAG_LEAF, buf);
}

/**
 * Convenience: leaf hash from a (key, value) claim pair. Handles NFC
 * normalization, UTF-8 encoding, and canonicalize() internally. Used by
 * every issuer/verifier/holder code path that operates on the (string,
 * unknown) claim shape.
 */
export function claimLeafHash(key: string, value: unknown): Uint8Array {
  const keyBytes = utf8(key.normalize('NFC'));
  const valueBytes = canonicalize(value);
  return leafHash(keyBytes, valueBytes);
}

/**
 * Empty-leaf hash for padded slot index `i`. Computes
 * `rpo256(0x00 ‖ u64BE(i))`.
 */
export function emptyLeafHash(index: number): Uint8Array {
  if (!Number.isInteger(index) || index < 0) {
    throw new RangeError(
      `emptyLeafHash: index must be a non-negative integer, got ${index}`,
    );
  }
  const buf = new Uint8Array(8);
  let n = BigInt(index);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return rpo256Tagged(TAG_EMPTY_LEAF, buf);
}

/**
 * Inner-node combinator: `rpo256(0x02 ‖ left ‖ right)`.
 */
function innerHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(left.length + right.length);
  buf.set(left, 0);
  buf.set(right, left.length);
  return rpo256Tagged(TAG_INNER, buf);
}

/**
 * Merkle tree over a list of (key, value) claim entries.
 *
 * Construction:
 *   1. For each entry, compute claimLeafHash(key, value).
 *   2. Pad with emptyLeafHash(i) up to next power of two, minimum 8.
 *   3. Build inner layers via innerHash(left, right).
 *
 * Callers that want spec's "lex sort by key" indexing must sort before
 * passing entries — see `sortClaimKeys`.
 */
export class MerkleTree {
  private readonly layers: readonly (readonly Uint8Array[])[];

  /** Number of leaves after padding (next power of 2, minimum 8). */
  public readonly paddedSize: number;

  constructor(entries: ReadonlyArray<readonly [string, unknown]>) {
    const leafCount = entries.length;
    let target = 1;
    while (target < Math.max(MIN_PADDED_SIZE, leafCount)) target <<= 1;

    const leaves: Uint8Array[] = new Array(target);
    for (let i = 0; i < leafCount; i++) {
      const [k, v] = entries[i] as readonly [string, unknown];
      leaves[i] = claimLeafHash(k, v);
    }
    for (let i = leafCount; i < target; i++) {
      leaves[i] = emptyLeafHash(i);
    }

    const layers: Uint8Array[][] = [leaves];
    let cur: Uint8Array[] = leaves;
    while (cur.length > 1) {
      const next: Uint8Array[] = new Array(cur.length >> 1);
      for (let i = 0; i < cur.length; i += 2) {
        next[i >> 1] = innerHash(cur[i] as Uint8Array, cur[i + 1] as Uint8Array);
      }
      layers.push(next);
      cur = next;
    }
    this.layers = layers;
    this.paddedSize = target;
  }

  /** Number of layers (root layer counted). */
  public get depth(): number {
    return this.layers.length;
  }

  /** Root, 32 bytes. */
  public get root(): Uint8Array {
    const top = this.layers[this.layers.length - 1] as readonly Uint8Array[];
    return top[0] as Uint8Array;
  }

  /** Root as a 64-char lowercase hex string (no 0x prefix). */
  public get rootHex(): string {
    return bytesToHex(this.root);
  }

  /**
   * Inclusion proof for the leaf at `index`. Returns sibling+isRight pairs
   * from leaf level upward (excluding the root).
   */
  public proof(index: number): readonly MerkleProofEntry[] {
    if (!Number.isInteger(index) || index < 0 || index >= this.paddedSize) {
      throw new RangeError(
        `MerkleTree.proof: index ${index} out of range [0, ${this.paddedSize})`,
      );
    }
    const entries: MerkleProofEntry[] = [];
    let i = index;
    for (let lvl = 0; lvl < this.layers.length - 1; lvl++) {
      const sib = i ^ 1;
      const layer = this.layers[lvl] as readonly Uint8Array[];
      entries.push({
        sibling: layer[sib] as Uint8Array,
        isRight: (i & 1) === 0,
      });
      i >>= 1;
    }
    return entries;
  }
}

/**
 * Verify an inclusion proof against an expected root.
 *
 * Walks from leaf to root, combining via innerHash(0x02, left, right) at
 * each level. Returns true iff the recomputed root equals `expectedRoot`.
 */
export function verifyMerkleProof(
  leaf: Uint8Array,
  proof: ReadonlyArray<MerkleProofEntry>,
  expectedRoot: Uint8Array,
): boolean {
  let h = leaf;
  for (const entry of proof) {
    h = entry.isRight ? innerHash(h, entry.sibling) : innerHash(entry.sibling, h);
  }
  if (h.length !== expectedRoot.length) return false;
  for (let i = 0; i < h.length; i++) {
    if (h[i] !== expectedRoot[i]) return false;
  }
  return true;
}
