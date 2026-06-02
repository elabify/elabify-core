import { describe, expect, it } from 'vitest';
import {
  MerkleTree,
  leafHash,
  claimLeafHash,
  emptyLeafHash,
  verifyMerkleProof,
} from '../src/merkle.js';
import { rpo256, rpo256Tagged } from '../src/rpo256.js';
import { canonicalize } from '../src/canonicalJson.js';
import { utf8 } from '../src/hex.js';

describe('Merkle — spec primitive leafHash(keyBytes, valueBytes)', () => {
  it('returns 32 bytes', () => {
    expect(leafHash(new Uint8Array([1]), new Uint8Array([2])).length).toBe(32);
  });

  it('matches rpo256(0x01 ‖ rpo256(keyBytes) ‖ rpo256(valueBytes)) manually', () => {
    const k = utf8('over18');
    const v = canonicalize(true);
    const expected = rpo256Tagged(
      0x01,
      new Uint8Array([...rpo256(k), ...rpo256(v)]),
    );
    expect(leafHash(k, v)).toEqual(expected);
  });

  it('different keys produce different leaves', () => {
    const v = canonicalize(1);
    expect(leafHash(utf8('a'), v)).not.toEqual(leafHash(utf8('b'), v));
  });

  it('different values produce different leaves', () => {
    const k = utf8('k');
    expect(leafHash(k, canonicalize(1))).not.toEqual(leafHash(k, canonicalize(2)));
  });
});

describe('Merkle — claimLeafHash(key, value) convenience', () => {
  it('returns same bytes as leafHash(utf8(nfc(k)), canonicalize(v))', () => {
    const k = 'givenName';
    const v = 'Fatima';
    expect(claimLeafHash(k, v)).toEqual(leafHash(utf8(k.normalize('NFC')), canonicalize(v)));
  });

  it('NFC-normalizes the key', () => {
    const composed = 'é';        // U+00E9
    const decomposed = 'é';     // U+0065 U+0301
    expect(claimLeafHash(composed, 1)).toEqual(claimLeafHash(decomposed, 1));
  });

  it('canonicalizes the value (NFC-equivalent strings produce same leaf)', () => {
    expect(claimLeafHash('k', 'é')).toEqual(claimLeafHash('k', 'é'));
  });

  it('is deterministic', () => {
    expect(claimLeafHash('k', 'v')).toEqual(claimLeafHash('k', 'v'));
  });
});

describe('Merkle — emptyLeafHash(index)', () => {
  it('returns 32 bytes', () => {
    expect(emptyLeafHash(0).length).toBe(32);
    expect(emptyLeafHash(7).length).toBe(32);
  });

  it('matches rpo256(0x00 ‖ u64BE(i)) manually', () => {
    const buf = new Uint8Array(8);
    buf[7] = 5; // u64BE of 5
    const expected = rpo256Tagged(0x00, buf);
    expect(emptyLeafHash(5)).toEqual(expected);
  });

  it('different indices produce different empty leaves (second-preimage resistance)', () => {
    expect(emptyLeafHash(0)).not.toEqual(emptyLeafHash(1));
    expect(emptyLeafHash(0)).not.toEqual(emptyLeafHash(7));
    expect(emptyLeafHash(127)).not.toEqual(emptyLeafHash(128));
  });

  it('rejects negative or non-integer indices', () => {
    expect(() => emptyLeafHash(-1)).toThrow(RangeError);
    expect(() => emptyLeafHash(1.5)).toThrow(RangeError);
  });
});

describe('Merkle — MerkleTree', () => {
  it('pads to minimum 8 leaves regardless of input size', () => {
    expect(new MerkleTree([['a', 1]]).paddedSize).toBe(8);
    expect(new MerkleTree([['a', 1], ['b', 2]]).paddedSize).toBe(8);
    expect(new MerkleTree(threeFiveEntries()).paddedSize).toBe(8);
  });

  it('pads to next power of 2 above 8 when needed', () => {
    const nine = Array.from({ length: 9 }, (_, i) => [`k${i}`, i] as const);
    expect(new MerkleTree(nine).paddedSize).toBe(16);
    const seventeen = Array.from({ length: 17 }, (_, i) => [`k${i}`, i] as const);
    expect(new MerkleTree(seventeen).paddedSize).toBe(32);
  });

  it('depth corresponds to log2(paddedSize) + 1', () => {
    expect(new MerkleTree([['a', 1]]).depth).toBe(4);             // 8 leaves → 3 inner layers + root
    expect(new MerkleTree(threeFiveEntries()).depth).toBe(4);
    const nine = Array.from({ length: 9 }, (_, i) => [`k${i}`, i] as const);
    expect(new MerkleTree(nine).depth).toBe(5);                   // 16 leaves
  });

  it('root is 32 bytes', () => {
    expect(new MerkleTree([['a', 1], ['b', 2]]).root.length).toBe(32);
  });

  it('proof length equals depth - 1', () => {
    const tree = new MerkleTree(threeFiveEntries());
    expect(tree.proof(0).length).toBe(tree.depth - 1);
    expect(tree.proof(4).length).toBe(tree.depth - 1);
    expect(tree.proof(7).length).toBe(tree.depth - 1);
  });

  it('proof.sibling entries are 32 bytes', () => {
    const tree = new MerkleTree([['a', 1], ['b', 2], ['c', 3]]);
    for (const entry of tree.proof(1)) {
      expect(entry.sibling.length).toBe(32);
      expect(typeof entry.isRight).toBe('boolean');
    }
  });

  it('proof rejects out-of-range indices', () => {
    const tree = new MerkleTree([['a', 1], ['b', 2]]);
    expect(() => tree.proof(-1)).toThrow(RangeError);
    expect(() => tree.proof(8)).toThrow(RangeError);
  });

  it('uses claimLeafHash at filled positions and emptyLeafHash at padded positions', () => {
    // Two real entries, six padded slots → reconstruct the tree manually.
    const entries: ReadonlyArray<readonly [string, unknown]> = [['a', 1], ['b', 2]];
    const tree = new MerkleTree(entries);
    const expectedLeaf0 = claimLeafHash('a', 1);
    const expectedLeaf7 = emptyLeafHash(7);
    // Verify the proof for index 0 uses leaf0 to reach root.
    const proof = tree.proof(0);
    expect(verifyMerkleProof(expectedLeaf0, proof, tree.root)).toBe(true);
    // Verify the proof for the padded slot 7 (synthesized empty leaf) reaches root.
    expect(verifyMerkleProof(expectedLeaf7, tree.proof(7), tree.root)).toBe(true);
  });
});

describe('Merkle — verifyMerkleProof', () => {
  it('verifies a valid proof for every real leaf', () => {
    const entries = threeFiveEntries();
    const tree = new MerkleTree(entries);
    for (let i = 0; i < entries.length; i++) {
      const [k, v] = entries[i] as readonly [string, unknown];
      expect(verifyMerkleProof(claimLeafHash(k, v), tree.proof(i), tree.root)).toBe(true);
    }
  });

  it('verifies a valid proof for every padded empty leaf', () => {
    const entries = threeFiveEntries(); // 5 real + 3 empty
    const tree = new MerkleTree(entries);
    for (let i = entries.length; i < tree.paddedSize; i++) {
      expect(verifyMerkleProof(emptyLeafHash(i), tree.proof(i), tree.root)).toBe(true);
    }
  });

  it('rejects a tampered leaf', () => {
    const tree = new MerkleTree([['a', 1], ['b', 2]]);
    const wrongLeaf = claimLeafHash('a', 999);
    expect(verifyMerkleProof(wrongLeaf, tree.proof(0), tree.root)).toBe(false);
  });

  it('rejects a tampered root', () => {
    const tree = new MerkleTree([['a', 1], ['b', 2]]);
    const leaf = claimLeafHash('a', 1);
    const wrongRoot = new Uint8Array(tree.root);
    wrongRoot[0] ^= 0xff;
    expect(verifyMerkleProof(leaf, tree.proof(0), wrongRoot)).toBe(false);
  });

  it('rejects a tampered proof sibling', () => {
    const tree = new MerkleTree([['a', 1], ['b', 2]]);
    const leaf = claimLeafHash('a', 1);
    const proof = tree.proof(0).map((p, idx) => {
      if (idx !== 0) return p;
      const sibling = new Uint8Array(p.sibling);
      sibling[0] ^= 0xff;
      return { sibling, isRight: p.isRight };
    });
    expect(verifyMerkleProof(leaf, proof, tree.root)).toBe(false);
  });

  it('rejects a proof against a root of the wrong length', () => {
    const tree = new MerkleTree([['a', 1], ['b', 2]]);
    const leaf = claimLeafHash('a', 1);
    const shortRoot = tree.root.slice(0, 31);
    expect(verifyMerkleProof(leaf, tree.proof(0), shortRoot)).toBe(false);
  });
});

function threeFiveEntries(): ReadonlyArray<readonly [string, unknown]> {
  // Five entries — pads to 8 leaves, depth 4 (3 inner layers + root).
  return [
    ['givenName', 'Fatima'],
    ['familyName', 'Al-Farsi'],
    ['nationality', 'AE'],
    ['dateOfBirth', '1990-04-12'],
    ['over18', true],
  ];
}
