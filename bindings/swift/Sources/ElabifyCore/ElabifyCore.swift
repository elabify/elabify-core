// ElabifyCore — Swift port of the @elabify/core TypeScript canonical
// implementation. Cross-binding equivalence is enforced by the KAT corpus
// in ../../test-vectors/ (read at test time by ElabifyCoreTests/KatRunner).
//
// Public surface (top-level, idiomatic Swift):
//   - rpo256(_:)                hashing
//   - rpo256Tagged(_:_:)
//   - leafHash(keyBytes:valueBytes:)
//   - claimLeafHash(key:value:)
//   - emptyLeafHash(index:)
//   - MerkleTree                 type
//   - verifyMerkleProof(leaf:proof:expectedRoot:)
//   - canonicalize(_:)           canonical JSON → bytes
//   - canonicalJsonString(_:)    canonical JSON → string
//   - CanonicalizeError          enum with cases matching @elabify/core
//   - deriveCid(headerWithoutCid:iat:)
//   - sortClaimKeys(_:)
//   - hkdfSha256(ikm:salt:info:length:)
//   - DID                        struct
//   - parseDID(_:) / formatDID(_:)
//   - DIDError
//
// The spec in elabify-core/README.md §4.2 names a `public enum
// ElabifyCore { ... }` namespace facade. We deviate: top-level symbols
// are the idiomatic Swift module shape, and the cross-binding contract
// is the KAT corpus, not the namespace prefix. Adopters who want
// disambiguation can `import ElabifyCore` and call `ElabifyCore.rpo256(_:)`
// would have been overkill given Swift's per-module namespacing.

import Foundation

// (The actual symbols are exported by the sibling .swift files in this
// module: Rpo256.swift, CanonicalJson.swift, Merkle.swift, DeriveCid.swift,
// Hkdf.swift, Did.swift. This file is the module's documentation anchor.)
