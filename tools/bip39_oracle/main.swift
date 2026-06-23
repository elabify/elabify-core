// BIP-39 ground-truth oracle. Compiles the ACTUAL iOS BIP39.swift +
// PBKDF2.swift (plus a tiny LogStore shim) and emits a vector set so the
// Kotlin port (elabify-core Bip39.kt) is proven byte-identical to iOS,
// including iOS's NFKC normalization choice.
//
// Build + run (writes the corpus):
//   swiftc -O -o /tmp/bip39oracle \
//     elabify-core/tools/bip39_oracle/main.swift \
//     ios-app-maknoon/Maknoon/BIP39.swift \
//     ios-app-maknoon/Maknoon/PBKDF2.swift
//   /tmp/bip39oracle > elabify-core/bindings/kotlin/src/test/resources/bip39.kat.json

import Foundation

// --- Shim for the one app symbol BIP39.swift references. ---
final class LogStore {
    static let shared = LogStore()
    func error(_ category: String, _ message: String) {
        FileHandle.standardError.write(Data("[\(category)] \(message)\n".utf8))
    }
}

func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }
func bytes(_ hex: String) -> Data {
    var out = Data(); var i = hex.startIndex
    while i < hex.endIndex {
        let j = hex.index(i, offsetBy: 2)
        out.append(UInt8(hex[i..<j], radix: 16)!); i = j
    }
    return out
}

// Deterministic 32-byte entropies x passphrases (incl. a unicode one to
// pin NFKC behaviour).
let entropies = [
    String(repeating: "00", count: 32),
    String(repeating: "07", count: 32),
    (0..<32).map { String(format: "%02x", $0) }.joined(),
    String(repeating: "ff", count: 32),
]
let passphrases = ["", "TREZOR", "ünïcödé🔑"]

var vectors: [[String: Any]] = []
for ent in entropies {
    let entropy = bytes(ent)
    let words = BIP39.mnemonicFromSeed(entropy)
    // Round-trip sanity in the oracle itself.
    let back = try! BIP39.seedFromMnemonic(words)
    precondition(back == entropy, "entropy round-trip failed")
    for pass in passphrases {
        let full = try! BIP39.derivedSeed(mnemonic: words.joined(separator: " "), passphrase: pass)
        vectors.append([
            "entropyHex": ent,
            "mnemonic": words.joined(separator: " "),
            "passphrase": pass,
            "bip39SeedHex": hex(full),
            "masterSeedHex": hex(full.prefix(32)),
        ])
    }
}

let out: [String: Any] = [
    "algorithm": "BIP-39 (24-word) + master-seed = PBKDF2-HMAC-SHA512[0..32]",
    "source": "iOS BIP39.swift + PBKDF2.swift (NFKC, c=2048)",
    "vectors": vectors,
]
let data = try JSONSerialization.data(withJSONObject: out, options: [.prettyPrinted, .sortedKeys])
FileHandle.standardOutput.write(data)
FileHandle.standardOutput.write(Data("\n".utf8))
