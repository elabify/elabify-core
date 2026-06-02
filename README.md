# elabify-core

The cross-platform cryptographic core for the Maknoon identity stack. One algorithm
contract, three native implementations that produce **byte-identical** output,
validated against a frozen known-answer-test (KAT) corpus.

## What's in here

- **RPO-256**: the Rescue-Prime Optimized sponge hash (and tagged variants).
- **Merkle**: tree construction plus inclusion-proof verification over claim leaves.
- **Canonical JSON**: deterministic JSON-to-bytes serialization (JCS-style).
- **CID derivation**: content-ID derivation for credential headers.
- **DID**: `did:elabify` parsing and formatting.
- **HKDF-SHA256**, plus ML-DSA-65 helpers on platforms that provide it.

## Implementations

| Target | Path | Notes |
|--------|------|-------|
| TypeScript (canonical) | `src/` | The reference implementation. |
| Swift | `bindings/swift/` | Pure Swift SwiftPM package; iOS 26+ (CryptoKit-native ML-DSA-65). Self-contained, no runtime dependency on the TS core. |
| Kotlin | `bindings/kotlin/` | Android port. |

All three are validated against the JSON vectors in **`test-vectors/`**. That corpus
is the cross-platform contract: any port must reproduce its outputs exactly.

## Build & test

```sh
# TypeScript (canonical)
npm install && npm test

# Swift binding (runs the KAT corpus through the Swift port)
cd bindings/swift && swift test
```

## License

Dual-licensed Apache-2.0 OR MIT, see [`LICENSE.md`](LICENSE.md).
