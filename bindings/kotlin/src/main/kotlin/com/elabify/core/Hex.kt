// Hex encoding helpers. Cross-binding-equivalent with @elabify/core's
// src/hex.ts (lowercase hex, no 0x prefix on output, tolerant of 0x prefix
// on input).

package com.elabify.core

import java.text.Normalizer

internal fun bytesToHex(bytes: ByteArray): String {
    val out = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xff
        out.append(HEX_ALPHABET[v ushr 4])
        out.append(HEX_ALPHABET[v and 0x0f])
    }
    return out.toString()
}

internal fun hexToBytes(hexIn: String): ByteArray {
    var hex = hexIn
    if (hex.startsWith("0x") || hex.startsWith("0X")) hex = hex.substring(2)
    require(hex.length % 2 == 0) { "hexToBytes: hex string must have even length, got ${hex.length}" }
    val out = ByteArray(hex.length / 2)
    for (i in out.indices) {
        val hi = digit(hex[i * 2])
        val lo = digit(hex[i * 2 + 1])
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

private val HEX_ALPHABET = "0123456789abcdef".toCharArray()

private fun digit(c: Char): Int {
    return when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> error("non-hex character: $c")
    }
}

/** UTF-8 bytes of the NFC-normalized form of [s]. */
internal fun utf8Bytes(s: String): ByteArray {
    return Normalizer.normalize(s, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8)
}
