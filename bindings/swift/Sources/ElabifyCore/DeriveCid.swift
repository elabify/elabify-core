// Credential ID derivation. Byte-equivalent with @elabify/core's
// src/deriveCid.ts. See test-vectors/derive-cid.kat.json.
//
//   cid = rpo256(0x04 ‖ canonicalize({...header, cid:""}) ‖ u64BE(iat))

import Foundation

private let cidDomainTag: UInt8 = 0x04

/// Derive a 32-byte credential ID from a header (without `cid`) and the
/// issued-at timestamp.
public func deriveCid(headerWithoutCid: [String: Any], iat: UInt64) throws -> Data {
    var headerCopy = headerWithoutCid
    headerCopy["cid"] = ""
    let headerBytes = try canonicalize(headerCopy)

    var total = Data(capacity: 1 + headerBytes.count + 8)
    total.append(cidDomainTag)
    total.append(headerBytes)

    // u64 big-endian of iat
    var n = iat
    var iatBytes = Data(count: 8)
    for i in stride(from: 7, through: 0, by: -1) {
        iatBytes[i] = UInt8(n & 0xff)
        n >>= 8
    }
    total.append(iatBytes)

    return rpo256(total)
}

/// Sort claim-set keys lexicographically by code-unit comparison.
public func sortClaimKeys(_ claims: [String: Any]) -> [String] {
    return claims.keys.sorted()
}
