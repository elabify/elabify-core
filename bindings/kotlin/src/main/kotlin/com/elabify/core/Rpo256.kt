// RPO-256 sponge hash over the Goldilocks field. Byte-equivalent port of
// the TypeScript implementation in @elabify/core/src/rpo256.ts.
//
// Field: p = 2^64 - 2^32 + 1. The TS source uses BigInt; Kotlin/JVM uses
// java.math.BigInteger for the same correctness-first reduction (the
// performance optimization with native 128-bit multiplication is deferred
// to M0-proper performance budgets, mirroring the Swift port).
//
// Cross-binding equivalence: test-vectors/rpo256.kat.json (10 vectors).

package com.elabify.core

import java.math.BigInteger

private val GOLD_P: BigInteger = BigInteger("18446744069414584321")   // 2^64 - 2^32 + 1
private val ALPHA: BigInteger  = BigInteger.valueOf(7)
private val A_INV: BigInteger  = BigInteger("10540996611094048183")

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

private fun fm(a: BigInteger): BigInteger {
    val r = a.mod(GOLD_P)
    return if (r.signum() < 0) r.add(GOLD_P) else r
}

private fun fmAdd(a: BigInteger, b: BigInteger): BigInteger = fm(a.add(b))
private fun fmMul(a: BigInteger, b: BigInteger): BigInteger = fm(a.multiply(b))

private fun fmPow(base: BigInteger, exp: BigInteger): BigInteger {
    var r = BigInteger.ONE
    var b = fm(base)
    var e = exp
    while (e.signum() > 0) {
        if (e.testBit(0)) r = fmMul(r, b)
        b = fmMul(b, b)
        e = e.shiftRight(1)
    }
    return r
}

private fun mdsMul(s: Array<BigInteger>): Array<BigInteger> {
    val out = Array(12) { BigInteger.ZERO }
    for (i in 0..11) {
        var v = BigInteger.ZERO
        for (j in 0..11) {
            v = fmAdd(v, fmMul(BigInteger.valueOf(MDS[i][j]), s[j]))
        }
        out[i] = v
    }
    return out
}

private fun rpoPermutation(state: Array<BigInteger>): Array<BigInteger> {
    var x = state.copyOf()
    for (r in 0..6) {
        for (i in 0..11) {
            x[i] = fmAdd(x[i], BigInteger.valueOf(RC[(r * 24 + i) % RC.size]))
        }
        for (i in 0..11) {
            x[i] = fmPow(x[i], ALPHA)
        }
        x = mdsMul(x)
        for (i in 0..11) {
            x[i] = fmAdd(x[i], BigInteger.valueOf(RC[(r * 24 + 12 + i) % RC.size]))
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

    var state = Array(12) { BigInteger.ZERO }
    val blocks = padded.size / 64
    for (blk in 0 until blocks) {
        val base = blk * 64
        for (i in 0..7) {
            var v = BigInteger.ZERO
            for (j in 0..7) {
                val byteVal = (padded[base + i * 8 + j].toInt() and 0xff).toLong()
                v = v.or(BigInteger.valueOf(byteVal).shiftLeft(j * 8))
            }
            state[i] = fmAdd(state[i], v)
        }
        state = rpoPermutation(state)
    }

    val out = ByteArray(32)
    for (i in 0..3) {
        var v = state[i]
        for (k in 0..7) {
            out[i * 8 + k] = v.and(BigInteger.valueOf(0xff)).toByte()
            v = v.shiftRight(8)
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
