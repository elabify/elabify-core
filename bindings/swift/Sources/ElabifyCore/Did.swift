// did:elabify parsing and formatting. Byte-equivalent with @elabify/core's
// src/did.ts. Grammar (exactly five colon-separated components):
//
//   did:elabify:<network>:<entityType>:<identifier>
//
// Cross-binding equivalence: test-vectors/did.kat.json pins happy-path
// round-trips + every DIDError code.

import Foundation

public struct DID: Equatable, Hashable {
    public let network: String
    public let entityType: String
    public let identifier: String
    public init(network: String, entityType: String, identifier: String) {
        self.network = network
        self.entityType = entityType
        self.identifier = identifier
    }
}

public enum DIDError: Error, Equatable {
    case malformed
    case extraColons
    case emptyComponent
}

public func parseDID(_ s: String) throws -> DID {
    let parts = s.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
    if parts.count > 5 { throw DIDError.extraColons }
    if parts.count != 5 { throw DIDError.malformed }
    if parts[0] != "did" || parts[1] != "elabify" { throw DIDError.malformed }
    let network = parts[2]
    let entityType = parts[3]
    let identifier = parts[4]
    if network.isEmpty || entityType.isEmpty || identifier.isEmpty {
        throw DIDError.emptyComponent
    }
    return DID(network: network, entityType: entityType, identifier: identifier)
}

public func formatDID(_ did: DID) -> String {
    return "did:elabify:" + did.network + ":" + did.entityType + ":" + did.identifier
}
