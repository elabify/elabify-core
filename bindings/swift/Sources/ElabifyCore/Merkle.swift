// Merkle tree construction. Byte-equivalent with @elabify/core's src/merkle.ts.
// Pads to min 8 leaves, byte-level domain tags 0x00 (empty leaf) / 0x01 (leaf) /
// 0x02 (inner). See test-vectors/merkle.kat.json + claim-leaf-hash.kat.json
// + leaf-hash.kat.json + empty-leaf-hash.kat.json for the locked contract.

import Foundation

private let tagEmptyLeaf: UInt8 = 0x00
private let tagLeaf: UInt8 = 0x01
private let tagInner: UInt8 = 0x02
private let minPaddedSize = 8

public struct MerkleProofEntry: Equatable {
    public let sibling: Data
    public let isRight: Bool
    public init(sibling: Data, isRight: Bool) {
        self.sibling = sibling
        self.isRight = isRight
    }
}

/// Spec primitive: rpo256(0x01 ‖ rpo256(keyBytes) ‖ rpo256(valueBytes)).
public func leafHash(keyBytes: Data, valueBytes: Data) -> Data {
    let kh = rpo256(keyBytes)
    let vh = rpo256(valueBytes)
    var buf = Data(capacity: 64)
    buf.append(kh)
    buf.append(vh)
    return rpo256Tagged(tagLeaf, buf)
}

/// Convenience: leaf hash from a (key, value) claim pair. Handles NFC
/// + UTF-8 encoding for the key and canonicalize() for the value.
public func claimLeafHash(key: String, value: Any) throws -> Data {
    let keyBytes = utf8Bytes(key)
    let valueBytes = try canonicalize(value)
    return leafHash(keyBytes: keyBytes, valueBytes: valueBytes)
}

/// Empty-leaf hash for padded slot index `index`: rpo256(0x00 ‖ u64BE(index)).
public func emptyLeafHash(index: UInt64) -> Data {
    var buf = Data(count: 8)
    var n = index
    for i in stride(from: 7, through: 0, by: -1) {
        buf[i] = UInt8(n & 0xff)
        n >>= 8
    }
    return rpo256Tagged(tagEmptyLeaf, buf)
}

/// Merkle inner-node combinator: rpo256(0x02 ‖ left ‖ right).
private func innerHash(_ left: Data, _ right: Data) -> Data {
    var buf = Data(capacity: left.count + right.count)
    buf.append(left)
    buf.append(right)
    return rpo256Tagged(tagInner, buf)
}

public final class MerkleTree {
    public let paddedSize: Int
    public let depth: Int
    public let root: Data
    public var rootHex: String { return bytesToHex(root) }

    private let layers: [[Data]]

    /// Build a Merkle tree over a list of (key, value) claim entries.
    /// Pads with index-tagged empty leaves up to next power of two,
    /// minimum 8.
    public init(entries: [(key: String, value: Any)]) throws {
        let leafCount = entries.count
        var target = 1
        while target < max(minPaddedSize, leafCount) { target <<= 1 }

        var leaves = [Data]()
        leaves.reserveCapacity(target)
        for entry in entries {
            leaves.append(try claimLeafHash(key: entry.key, value: entry.value))
        }
        for i in leafCount..<target {
            leaves.append(emptyLeafHash(index: UInt64(i)))
        }

        var layers: [[Data]] = [leaves]
        var cur = leaves
        while cur.count > 1 {
            var next = [Data]()
            next.reserveCapacity(cur.count / 2)
            for i in stride(from: 0, to: cur.count, by: 2) {
                next.append(innerHash(cur[i], cur[i + 1]))
            }
            layers.append(next)
            cur = next
        }
        self.layers = layers
        self.paddedSize = target
        self.depth = layers.count
        self.root = layers.last![0]
    }

    public func proof(at index: Int) -> [MerkleProofEntry] {
        precondition(index >= 0 && index < paddedSize,
                     "MerkleTree.proof: index \(index) out of range [0, \(paddedSize))")
        var entries = [MerkleProofEntry]()
        entries.reserveCapacity(layers.count - 1)
        var i = index
        for lvl in 0..<(layers.count - 1) {
            let sib = i ^ 1
            entries.append(MerkleProofEntry(
                sibling: layers[lvl][sib],
                isRight: (i & 1) == 0
            ))
            i >>= 1
        }
        return entries
    }
}

/// Verify an inclusion proof against an expected root.
public func verifyMerkleProof(
    leaf: Data,
    proof: [MerkleProofEntry],
    expectedRoot: Data
) -> Bool {
    var h = leaf
    for entry in proof {
        h = entry.isRight ? innerHash(h, entry.sibling) : innerHash(entry.sibling, h)
    }
    return h == expectedRoot
}
