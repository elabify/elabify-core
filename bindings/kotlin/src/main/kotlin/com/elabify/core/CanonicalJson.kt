// Canonical JSON serialization, byte-equivalent with @elabify/core's
// src/canonicalJson.ts. NFC-normalized strings + keys, sorted keys,
// integer-only numbers, depth ≤ 32, strings ≤ 64 KiB UTF-8.
//
// Cross-binding equivalence: test-vectors/canonicalize.kat.json (26 vectors
// covering primitives, NFC equivalence, sorted-key behaviour, and every
// CanonicalizeError code).
//
// Accepted runtime types (analogous to TS `unknown`):
//   - null                                → null
//   - Boolean                             → true / false
//   - Int / Long / java.math.BigInteger   → integer literal
//   - Double / Float (integer-valued)     → integer literal; rejects floats
//   - String                              → NFC + JSON-escape
//   - List<Any?> / Array<Any?>            → JSON array
//   - Map<String, Any?>                   → JSON object, sorted (NFC) keys
//
// Anything else throws CanonicalizeError.NAN_OR_INF with a type-hint
// message (matches TS behaviour for unsupported value types).

package com.elabify.core

import java.text.Normalizer
import java.util.IdentityHashMap

private const val DEPTH_LIMIT = 32
private const val STRING_BYTE_LIMIT = 64 * 1024 // 64 KiB UTF-8

enum class CanonicalizeErrorCode {
    FLOAT,
    CYCLE,
    DEPTH,
    STRING_TOO_LONG,
    NAN_OR_INF,
}

class CanonicalizeError(
    val code: CanonicalizeErrorCode,
    message: String,
) : RuntimeException(message)

/** Canonical JSON of [value] as UTF-8 bytes. */
fun canonicalize(value: Any?): ByteArray {
    return canonicalJsonString(value).toByteArray(Charsets.UTF_8)
}

/** Canonical JSON of [value] as a UTF-8 String (for debugging). */
fun canonicalJsonString(value: Any?): String {
    return emit(value, depth = 0, pathSet = IdentityHashMap())
}

private fun emit(value: Any?, depth: Int, pathSet: IdentityHashMap<Any, Boolean>): String {
    if (depth > DEPTH_LIMIT) throw CanonicalizeError(CanonicalizeErrorCode.DEPTH, "canonicalize: nesting depth exceeds $DEPTH_LIMIT")

    if (value == null) return "null"

    when (value) {
        is Boolean -> return if (value) "true" else "false"
        is String  -> return emitString(value)
    }

    // Integer types.
    if (value is Int)    return value.toString()
    if (value is Long)   return value.toString()
    if (value is Short)  return value.toString()
    if (value is Byte)   return value.toString()
    if (value is java.math.BigInteger) return value.toString()

    if (value is Double) {
        if (!value.isFinite()) throw CanonicalizeError(CanonicalizeErrorCode.NAN_OR_INF, "canonicalize: numeric value is not finite ($value)")
        if (value != Math.floor(value)) throw CanonicalizeError(CanonicalizeErrorCode.FLOAT, "canonicalize: non-integer numeric value $value")
        // Integer-valued double; emit as Long if it fits.
        if (value >= Long.MIN_VALUE.toDouble() && value <= Long.MAX_VALUE.toDouble()) {
            return value.toLong().toString()
        }
        throw CanonicalizeError(CanonicalizeErrorCode.FLOAT, "canonicalize: integer-valued double exceeds Long range: $value")
    }
    if (value is Float) {
        if (!value.isFinite()) throw CanonicalizeError(CanonicalizeErrorCode.NAN_OR_INF, "canonicalize: numeric value is not finite ($value)")
        if (value != kotlin.math.floor(value)) throw CanonicalizeError(CanonicalizeErrorCode.FLOAT, "canonicalize: non-integer numeric value $value")
        if (value >= Int.MIN_VALUE.toFloat() && value <= Int.MAX_VALUE.toFloat()) {
            return value.toInt().toString()
        }
        throw CanonicalizeError(CanonicalizeErrorCode.FLOAT, "canonicalize: integer-valued float exceeds Int range: $value")
    }

    if (value is List<*>) {
        if (pathSet.containsKey(value)) throw CanonicalizeError(CanonicalizeErrorCode.CYCLE, "canonicalize: cyclic reference in list")
        pathSet[value] = true
        return try {
            value.joinToString(separator = ",", prefix = "[", postfix = "]") { emit(it, depth + 1, pathSet) }
        } finally {
            pathSet.remove(value)
        }
    }
    if (value is Array<*>) {
        if (pathSet.containsKey(value)) throw CanonicalizeError(CanonicalizeErrorCode.CYCLE, "canonicalize: cyclic reference in array")
        pathSet[value] = true
        return try {
            value.joinToString(separator = ",", prefix = "[", postfix = "]") { emit(it, depth + 1, pathSet) }
        } finally {
            pathSet.remove(value)
        }
    }

    if (value is Map<*, *>) {
        if (pathSet.containsKey(value)) throw CanonicalizeError(CanonicalizeErrorCode.CYCLE, "canonicalize: cyclic reference in map")
        pathSet[value] = true
        return try {
            emitObject(value, depth, pathSet)
        } finally {
            pathSet.remove(value)
        }
    }

    throw CanonicalizeError(
        CanonicalizeErrorCode.NAN_OR_INF,
        "canonicalize: unsupported value type ${value::class.simpleName}",
    )
}

private fun emitObject(obj: Map<*, *>, depth: Int, pathSet: IdentityHashMap<Any, Boolean>): String {
    val normalized = obj.entries.map { entry ->
        val keyStr = entry.key as? String
            ?: throw CanonicalizeError(CanonicalizeErrorCode.NAN_OR_INF, "canonicalize: non-string key in map: ${entry.key}")
        Triple(keyStr, Normalizer.normalize(keyStr, Normalizer.Form.NFC), entry.value)
    }.sortedBy { it.second }

    val parts = ArrayList<String>(normalized.size)
    for ((_, nfcKey, value) in normalized) {
        val keyJson = emitString(nfcKey)
        val valueJson = emit(value, depth + 1, pathSet)
        parts.add("$keyJson:$valueJson")
    }
    return parts.joinToString(separator = ",", prefix = "{", postfix = "}")
}

private fun emitString(s: String): String {
    val nfc = Normalizer.normalize(s, Normalizer.Form.NFC)
    val byteLen = nfc.toByteArray(Charsets.UTF_8).size
    if (byteLen > STRING_BYTE_LIMIT) {
        throw CanonicalizeError(CanonicalizeErrorCode.STRING_TOO_LONG, "canonicalize: string exceeds $STRING_BYTE_LIMIT-byte UTF-8 limit")
    }
    return jsonEscape(nfc)
}

/** RFC 8259 minimal JSON string escape, matching JavaScript JSON.stringify. */
private fun jsonEscape(s: String): String {
    val out = StringBuilder(s.length + 2)
    out.append('"')
    for (c in s) {
        when (val code = c.code) {
            0x22 -> out.append("\\\"")
            0x5C -> out.append("\\\\")
            0x08 -> out.append("\\b")
            0x09 -> out.append("\\t")
            0x0A -> out.append("\\n")
            0x0C -> out.append("\\f")
            0x0D -> out.append("\\r")
            in 0x00..0x1f -> out.append("\\u%04x".format(code))
            else -> out.append(c)
        }
    }
    out.append('"')
    return out.toString()
}
