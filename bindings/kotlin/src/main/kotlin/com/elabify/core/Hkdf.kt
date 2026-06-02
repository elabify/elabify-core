// HKDF-SHA-256 per RFC 5869. Implemented in terms of javax.crypto.Mac
// with HmacSHA256 (always present on the JVM). No third-party crypto
// dependency in the library itself.
//
// Cross-binding equivalence: test-vectors/hkdf-sha256.kat.json pins the
// three RFC 5869 cases + an Elabify-specific challenge-derivation case.

package com.elabify.core

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private const val HASH_LEN = 32 // SHA-256 output bytes

fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    require(length > 0) { "hkdfSha256: length must be positive, got $length" }
    require(length <= 255 * HASH_LEN) {
        "hkdfSha256: length $length exceeds RFC 5869 maximum of 255·HashLen = ${255 * HASH_LEN} bytes for SHA-256"
    }

    // Per RFC 5869 §2.2: when salt is empty, substitute a zero-string of
    // HashLen bytes.
    val effectiveSalt = if (salt.isEmpty()) ByteArray(HASH_LEN) else salt

    // Extract: PRK = HMAC-SHA256(salt, IKM)
    val prk = hmacSha256(key = effectiveSalt, data = ikm)

    // Expand: T(0) = empty; T(i) = HMAC-SHA256(PRK, T(i-1) || info || byte(i))
    val output = ByteArray(length)
    var written = 0
    var prev = ByteArray(0)
    var counter = 1
    while (written < length) {
        val concat = ByteArray(prev.size + info.size + 1)
        System.arraycopy(prev, 0, concat, 0, prev.size)
        System.arraycopy(info, 0, concat, prev.size, info.size)
        concat[concat.size - 1] = counter.toByte()
        val t = hmacSha256(key = prk, data = concat)
        val takeLen = minOf(HASH_LEN, length - written)
        System.arraycopy(t, 0, output, written, takeLen)
        written += takeLen
        prev = t
        counter++
    }
    return output
}

private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    return mac.doFinal(data)
}
