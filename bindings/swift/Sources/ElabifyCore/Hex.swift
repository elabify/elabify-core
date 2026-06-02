// Hex encoding helpers. Cross-binding-equivalent with @elabify/core's
// src/hex.ts (lowercase hex, no 0x prefix, accepts upper- or lower-case
// on decode).

import Foundation

internal func bytesToHex(_ bytes: Data) -> String {
    var s = String()
    s.reserveCapacity(bytes.count * 2)
    let alphabet: [Character] = Array("0123456789abcdef")
    for byte in bytes {
        s.append(alphabet[Int(byte >> 4)])
        s.append(alphabet[Int(byte & 0x0f)])
    }
    return s
}

internal func hexToBytes(_ hex: String) -> Data {
    var s = hex
    if s.hasPrefix("0x") || s.hasPrefix("0X") {
        s = String(s.dropFirst(2))
    }
    precondition(s.count.isMultiple(of: 2), "hexToBytes: hex string must have even length, got \(s.count)")
    var out = Data(count: s.count / 2)
    let chars = Array(s)
    for i in stride(from: 0, to: chars.count, by: 2) {
        guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else {
            preconditionFailure("hexToBytes: non-hex character in \"\(hex)\"")
        }
        out[i / 2] = UInt8((hi << 4) | lo)
    }
    return out
}

internal func utf8Bytes(_ s: String) -> Data {
    return Data(s.precomposedStringWithCanonicalMapping.utf8)
}
