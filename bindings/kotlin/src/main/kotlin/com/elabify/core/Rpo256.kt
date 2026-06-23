// RPO-256 sponge hash over the Goldilocks field. Byte-equivalent port of
// the TypeScript implementation in @elabify/core/src/rpo256.ts.
//
// Field: p = 2^64 - 2^32 + 1. Arithmetic is done in primitive unsigned 64-bit
// (Long) using the standard Goldilocks fast reduction (2^64 == 2^32 - 1 mod p,
// 2^96 == -1 mod p), matching the native 64-bit path the Swift port uses. An
// earlier revision used java.math.BigInteger for the same reduction; on-device
// that made a single Merkle-tree-plus-proofs presentation take ~8 seconds (the
// inverse S-box does ~63 squarings of ~128-bit values per lane per round). The
// Long path is the same field, byte-for-byte: validated against
// test-vectors/rpo256.kat.json (10 vectors) which guards cross-binding
// equivalence with iOS / TypeScript / the verifier-server.

package com.elabify.core

// p = 2^64 - 2^32 + 1, held as an unsigned Long (compare/sub via *Unsigned ops).
private val ORDER: Long = 0xFFFFFFFF00000001uL.toLong()

// 2^64 mod p = 2^32 - 1. The reduction constant.
private const val EPSILON: Long = 0xFFFFFFFFL

private const val ALPHA: Long = 7L
private val A_INV: Long = 10540996611094048183uL.toLong()

private val MDS: Array<LongArray> = arrayOf(
    longArrayOf( 7, 23,  8, 26, 20,  7,  1, 20,  4,  8,  1,  1),
    longArrayOf( 8,  7, 23,  8, 26, 20,  7,  1, 20,  4,  8,  1),
    longArrayOf( 1,  8,  7, 23,  8, 26, 20,  7,  1, 20,  4,  8),
    longArrayOf( 8,  1,  8,  7, 23,  8, 26, 20,  7,  1, 20,  4),
    longArrayOf( 4,  8,  1,  8,  7, 23,  8, 26, 20,  7,  1, 20),
    longArrayOf(20,  4,  8,  1,  8,  7, 23,  8, 26, 20,  7,  1),
    longArrayOf( 1, 20,  4,  8,  1,  8,  7, 23,  8, 26, 20,  7),
    longArrayOf( 7,  1, 20,  4,  8,  1,  8,  7, 23,  8, 26, 20),
    longArrayOf(20,  7,  1, 20,  4,  8,  1,  8,  7, 23,  8, 26),
    longArrayOf(26, 20,  7,  1, 20,  4,  8,  1,  8,  7, 23,  8),
    longArrayOf( 8, 26, 20,  7,  1, 20,  4,  8,  1,  8,  7, 23),
    longArrayOf(23,  8, 26, 20,  7,  1, 20,  4,  8,  1,  8,  7),
)

private val RC: LongArray = longArrayOf(
    7096123747201L, 3073462498391L, 5423984235601L, 1234987654321L,
    9876543210123L, 2345678901234L, 8765432109876L, 4567890123456L,
    6789012345678L, 9012345678901L, 1357924680135L, 2468013579246L,
    3141592653589L, 2718281828459L, 1618033988749L, 1414213562373L,
    1732050808567L, 2236067977499L, 2449489742783L, 2645751311064L,
    2828427124746L, 3000000000000L, 3141592653589L, 3316624790355L,
)

/** Reduce an arbitrary 64-bit value into the canonical range [0, p). Since
 *  2^64 < 2p, a single conditional subtract suffices. */
private fun reduce64(x: Long): Long =
    if (java.lang.Long.compareUnsigned(x, ORDER) >= 0) x - ORDER else x

/** Field addition of two canonical operands ([0, p)), returning canonical. */
private fun fmAdd(a: Long, b: Long): Long {
    var sum = a + b
    if (java.lang.Long.compareUnsigned(sum, a) < 0) {
        // Carry out of 64 bits: 2^64 == EPSILON (mod p). The result stays < p.
        sum += EPSILON
    } else if (java.lang.Long.compareUnsigned(sum, ORDER) >= 0) {
        sum -= ORDER
    }
    return sum
}

/** Reduce a 128-bit product (lo + hi * 2^64) to canonical [0, p). */
private fun reduce128(lo: Long, hi: Long): Long {
    val hiHi = hi ushr 32          // coefficient of 2^96 == -1 (mod p)
    val hiLo = hi and 0xFFFFFFFFL  // coefficient of 2^64 == EPSILON (mod p)

    var t0 = lo - hiHi
    if (java.lang.Long.compareUnsigned(lo, hiHi) < 0) {
        // Borrow: correct by EPSILON (the wrap is 2^64 == EPSILON mod p).
        t0 -= EPSILON
    }
    val t1 = hiLo * EPSILON         // < 2^32 * 2^32 == 2^64, no overflow
    var res = t0 + t1
    if (java.lang.Long.compareUnsigned(res, t0) < 0) {
        res += EPSILON
    }
    if (java.lang.Long.compareUnsigned(res, ORDER) >= 0) res -= ORDER
    return res
}

/** Field multiplication of two canonical operands, returning canonical. */
private fun fmMul(a: Long, b: Long): Long {
    // 64x64 -> 128 schoolbook on 32-bit halves (portable; no Math.multiplyHigh
    // dependency, which only exists from API 31).
    val aLo = a and 0xFFFFFFFFL
    val aHi = a ushr 32
    val bLo = b and 0xFFFFFFFFL
    val bHi = b ushr 32

    val ll = aLo * bLo
    val lh = aLo * bHi
    val hl = aHi * bLo
    val hh = aHi * bHi

    val cross = (ll ushr 32) + (lh and 0xFFFFFFFFL) + (hl and 0xFFFFFFFFL)
    val lo = (ll and 0xFFFFFFFFL) or (cross shl 32)
    val hi = hh + (lh ushr 32) + (hl ushr 32) + (cross ushr 32)
    return reduce128(lo, hi)
}

/** base^exp mod p. `exp` is treated as an unsigned 64-bit value. */
private fun fmPow(base: Long, exp: Long): Long {
    var r = 1L
    var b = base
    var e = exp
    while (e != 0L) {
        if (e and 1L == 1L) r = fmMul(r, b)
        b = fmMul(b, b)
        e = e ushr 1
    }
    return r
}

private fun mdsMul(s: LongArray): LongArray {
    val out = LongArray(12)
    for (i in 0..11) {
        var v = 0L
        for (j in 0..11) {
            v = fmAdd(v, fmMul(MDS[i][j], s[j]))
        }
        out[i] = v
    }
    return out
}

private fun rpoPermutation(state: LongArray): LongArray {
    var x = state.copyOf()
    for (r in 0..6) {
        for (i in 0..11) {
            x[i] = fmAdd(x[i], RC[(r * 24 + i) % RC.size])
        }
        for (i in 0..11) {
            x[i] = fmPow(x[i], ALPHA)
        }
        x = mdsMul(x)
        for (i in 0..11) {
            x[i] = fmAdd(x[i], RC[(r * 24 + 12 + i) % RC.size])
        }
        for (i in 0..11) {
            x[i] = fmPow(x[i], A_INV)
        }
        x = mdsMul(x)
    }
    return x
}

/** RPO-256 hash. Returns 32 bytes.
 *
 *  Sponge construction: rate=8 limbs (64 bytes), capacity=4 limbs.
 *  Padding: append 0x01 then zeros to a 64-byte boundary (always at least
 *  one full pad block). Squeeze 32 bytes from state[0..3] little-endian. */
fun rpo256(input: ByteArray): ByteArray {
    val padLen = 64 - (input.size % 64)
    val padded = ByteArray(input.size + padLen)
    System.arraycopy(input, 0, padded, 0, input.size)
    padded[input.size] = 0x01

    var state = LongArray(12)
    val blocks = padded.size / 64
    for (blk in 0 until blocks) {
        val base = blk * 64
        for (i in 0..7) {
            var v = 0L
            for (j in 0..7) {
                val byteVal = (padded[base + i * 8 + j].toInt() and 0xff).toLong()
                v = v or (byteVal shl (j * 8))
            }
            state[i] = fmAdd(state[i], reduce64(v))
        }
        state = rpoPermutation(state)
    }

    val out = ByteArray(32)
    for (i in 0..3) {
        var v = state[i]
        for (k in 0..7) {
            out[i * 8 + k] = (v and 0xff).toByte()
            v = v ushr 8
        }
    }
    return out
}

/** RPO-256 with a 1-byte domain-separation tag prepended. */
fun rpo256Tagged(tag: Int, content: ByteArray): ByteArray {
    require(tag in 0..255) { "rpo256Tagged: tag must be in [0, 255], got $tag" }
    val buf = ByteArray(1 + content.size)
    buf[0] = tag.toByte()
    System.arraycopy(content, 0, buf, 1, content.size)
    return rpo256(buf)
}
