// HKDF-SHA-256 per RFC 5869. Implemented in terms of Apple CryptoKit's
// HKDF<SHA256> (available on iOS 14+ / macOS 11+, well below our floor).
//
// Cross-binding equivalence: test-vectors/hkdf-sha256.kat.json pins the
// three RFC 5869 vectors + an Elabify-specific challenge-derivation case.

import Foundation
import CryptoKit

public func hkdfSha256(ikm: Data, salt: Data, info: Data, length: Int) -> Data {
    precondition(length > 0, "hkdfSha256: length must be positive")
    precondition(length <= 255 * 32,
                 "hkdfSha256: length \(length) exceeds RFC 5869 maximum of 255·HashLen = 8160 bytes for SHA-256")

    let key = SymmetricKey(data: ikm)
    let derived = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: key,
        salt: salt,
        info: info,
        outputByteCount: length
    )
    return derived.withUnsafeBytes { Data($0) }
}
