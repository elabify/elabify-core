// Credential ID derivation. Byte-equivalent with @elabify/core's
// src/deriveCid.ts. See test-vectors/derive-cid.kat.json.
//
//   cid = rpo256(0x04 ‖ canonicalize({...header, cid:""}) ‖ u64BE(iat))

package com.elabify.core

private const val CID_DOMAIN_TAG: Int = 0x04

/** Derive a 32-byte credential ID from a header (without `cid`) and the
 *  issued-at timestamp. */
fun deriveCid(headerWithoutCid: Map<String, Any?>, iat: Long): ByteArray {
    require(iat >= 0) { "deriveCid: iat must be non-negative, got $iat" }
    val headerCopy = LinkedHashMap<String, Any?>(headerWithoutCid)
    headerCopy["cid"] = ""
    val headerBytes = canonicalize(headerCopy)

    val total = ByteArray(1 + headerBytes.size + 8)
    total[0] = CID_DOMAIN_TAG.toByte()
    System.arraycopy(headerBytes, 0, total, 1, headerBytes.size)

    var n = iat
    for (i in 7 downTo 0) {
        total[1 + headerBytes.size + i] = (n and 0xff).toByte()
        n = n ushr 8
    }
    return rpo256(total)
}

/** Sort claim-set keys lexicographically by code-unit comparison. */
fun sortClaimKeys(claims: Map<String, Any?>): List<String> {
    return claims.keys.sorted()
}
