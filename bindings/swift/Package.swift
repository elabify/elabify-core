// swift-tools-version: 6.2
//
// ElabifyCore — pure-Swift port of the @elabify/core TypeScript canonical
// implementation. Cross-binding equivalence is enforced by the KAT corpus
// in ../../test-vectors/, which the test target reads at runtime and
// validates byte-for-byte.
//
// Deployment target: iOS 26 / macOS 26 minimum so the Musnad iOS holder
// can use CryptoKit's native ML-DSA-65 verify (shipped WWDC25). See the
// project's iOS-26 memory + ADR-0017 for the language pivot rationale.

import PackageDescription

let package = Package(
    name: "ElabifyCore",
    platforms: [
        .iOS(.v26),
        .macOS(.v26),
    ],
    products: [
        .library(name: "ElabifyCore", targets: ["ElabifyCore"]),
    ],
    targets: [
        .target(
            name: "ElabifyCore",
            path: "Sources/ElabifyCore"
        ),
        .testTarget(
            name: "ElabifyCoreTests",
            dependencies: ["ElabifyCore"],
            path: "Tests/ElabifyCoreTests"
            // test-vectors/ is located at runtime via #file relative to
            // KatRunnerTests.swift — see locateVectorDir(). Avoids
            // SwiftPM resource-bundle path drama with the symlink to
            // ../../test-vectors and works under both `swift test` and
            // Xcode-driven test runs.
        ),
    ]
)
