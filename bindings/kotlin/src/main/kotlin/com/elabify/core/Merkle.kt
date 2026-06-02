// Merkle tree construction. Byte-equivalent with @elabify/core's src/merkle.ts.
// Pads to min 8 leaves, byte-level domain tags 0x00 (empty leaf) / 0x01 (leaf)
// / 0x02 (inner). See test-vectors/merkle.kat.json plus the leaf-hash /
// claim-leaf-hash / empty-leaf-hash vectors for the locked contract.

package com.elabify.core

private const val TAG_EMPTY_LEAF: Int = 0x00
private const val TAG_LEAF: Int = 0x01
private const val TAG_INNER: Int = 0x02
private const val MIN_PADDED_SIZE = 8

data class MerkleProofEntry(val sibling: ByteArray, val isRight: Boolean) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MerkleProofEntry) return false
        return isRight == other.isRight && sibling.contentEquals(other.sibling)
    }
    override fun hashCode(): Int = 31 * sibling.contentHashCode() + isRight.hashCode()
}

/** Spec primitive: rpo256(0x01 ‖ rpo256(keyBytes) ‖ rpo256(valueBytes)). */
fun leafHash(keyBytes: ByteArray, valueBytes: ByteArray): ByteArray {
    val kh = rpo256(keyBytes)
    val vh = rpo256(valueBytes)
    val buf = ByteArray(kh.size + vh.size)
    System.arraycopy(kh, 0, buf, 0, kh.size)
    System.arraycopy(vh, 0, buf, kh.size, vh.size)
    return rpo256Tagged(TAG_LEAF, buf)
}

/** Convenience: leaf hash from a (key, value) claim pair. Handles NFC +
 *  UTF-8 encoding for the key and canonicalize() for the value. */
fun claimLeafHash(key: String, value: Any?): ByteArray {
    val keyBytes = utf8Bytes(key)
    val valueBytes = canonicalize(value)
    return leafHash(keyBytes, valueBytes)
}

/** Empty-leaf hash for padded slot index [index]: rpo256(0x00 ‖ u64BE(index)). */
fun emptyLeafHash(index: Long): ByteArray {
    require(index >= 0) { "emptyLeafHash: index must be non-negative, got $index" }
    val buf = ByteArray(8)
    var n = index
    for (i in 7 downTo 0) {
        buf[i] = (n and 0xff).toByte()
        n = n ushr 8
    }
    return rpo256Tagged(TAG_EMPTY_LEAF, buf)
}

/** Merkle inner-node combinator: rpo256(0x02 ‖ left ‖ right). */
private fun innerHash(left: ByteArray, right: ByteArray): ByteArray {
    val buf = ByteArray(left.size + right.size)
    System.arraycopy(left, 0, buf, 0, left.size)
    System.arraycopy(right, 0, buf, left.size, right.size)
    return rpo256Tagged(TAG_INNER, buf)
}

class MerkleTree(entries: List<Pair<String, Any?>>) {
    val paddedSize: Int
    val depth: Int
    val root: ByteArray
    val rootHex: String get() = bytesToHex(root)

    private val layers: List<List<ByteArray>>

    init {
        val leafCount = entries.size
        var target = 1
        while (target < maxOf(MIN_PADDED_SIZE, leafCount)) target = target shl 1

        val leaves = ArrayList<ByteArray>(target)
        for (entry in entries) {
            leaves.add(claimLeafHash(entry.first, entry.second))
        }
        for (i in leafCount until target) {
            leaves.add(emptyLeafHash(i.toLong()))
        }

        val builtLayers = ArrayList<List<ByteArray>>()
        builtLayers.add(leaves.toList())
        var cur: List<ByteArray> = leaves
        while (cur.size > 1) {
            val next = ArrayList<ByteArray>(cur.size / 2)
            var i = 0
            while (i < cur.size) {
                next.add(innerHash(cur[i], cur[i + 1]))
                i += 2
            }
            builtLayers.add(next)
            cur = next
        }
        this.layers = builtLayers
        this.paddedSize = target
        this.depth = builtLayers.size
        this.root = builtLayers.last()[0]
    }

    fun proof(index: Int): List<MerkleProofEntry> {
        require(index in 0 until paddedSize) { "MerkleTree.proof: index $index out of range [0, $paddedSize)" }
        val out = ArrayList<MerkleProofEntry>(layers.size - 1)
        var i = index
        for (lvl in 0 until layers.size - 1) {
            val sib = i xor 1
            out.add(MerkleProofEntry(layers[lvl][sib], (i and 1) == 0))
            i = i shr 1
        }
        return out
    }
}

/** Verify an inclusion proof against an expected root. */
fun verifyMerkleProof(leaf: ByteArray, proof: List<MerkleProofEntry>, expectedRoot: ByteArray): Boolean {
    var h = leaf
    for (entry in proof) {
        h = if (entry.isRight) innerHash(h, entry.sibling) else innerHash(entry.sibling, h)
    }
    return h.contentEquals(expectedRoot)
}
