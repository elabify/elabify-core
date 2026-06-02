// did:elabify parsing and formatting. Byte-equivalent with @elabify/core's
// src/did.ts. Grammar (exactly five colon-separated components):
//
//   did:elabify:<network>:<entityType>:<identifier>
//
// Cross-binding equivalence: test-vectors/did.kat.json pins happy-path
// round-trips + every DIDError code.

package com.elabify.core

data class DID(val network: String, val entityType: String, val identifier: String)

enum class DIDErrorCode {
    MALFORMED,
    EXTRA_COLONS,
    EMPTY_COMPONENT,
}

class DIDError(val code: DIDErrorCode, message: String) : RuntimeException(message)

fun parseDID(s: String): DID {
    val parts = s.split(":")
    if (parts.size > 5) {
        throw DIDError(DIDErrorCode.EXTRA_COLONS, "parseDID: too many colons in \"$s\"")
    }
    if (parts.size != 5) {
        throw DIDError(DIDErrorCode.MALFORMED, "parseDID: \"$s\" is not a did:elabify DID")
    }
    if (parts[0] != "did" || parts[1] != "elabify") {
        throw DIDError(DIDErrorCode.MALFORMED, "parseDID: \"$s\" must start with did:elabify:")
    }
    val network = parts[2]
    val entityType = parts[3]
    val identifier = parts[4]
    if (network.isEmpty() || entityType.isEmpty() || identifier.isEmpty()) {
        throw DIDError(DIDErrorCode.EMPTY_COMPONENT, "parseDID: \"$s\" has an empty component")
    }
    return DID(network, entityType, identifier)
}

fun formatDID(did: DID): String = "did:elabify:${did.network}:${did.entityType}:${did.identifier}"
