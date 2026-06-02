// Cross-binding KAT runner — drives the same test-vectors/*.kat.json corpus
// that the TypeScript reference passes, and asserts byte-equivalence for
// every vector against the Swift implementation.
//
// If even one vector fails, the Swift port disagrees with the TS reference
// on the wire. That's the gate that makes a Swift change "M0-safe" before
// it can ship.

import XCTest
@testable import ElabifyCore
import Foundation

final class KatRunnerTests: XCTestCase {

    func testFullCorpus() throws {
        let dir = try locateVectorDir()
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
            .filter { $0.hasSuffix(".kat.json") }
            .sorted()

        XCTAssertGreaterThan(files.count, 0, "no .kat.json files found under \(dir.path)")

        var totalPass = 0
        var totalFail = 0
        var failures: [String] = []

        for filename in files {
            let url = dir.appendingPathComponent(filename)
            let data = try Data(contentsOf: url)
            let body = try JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
            let function = body["function"] as! String
            let vectors = body["vectors"] as! [[String: Any]]

            var filePass = 0
            var fileFail = 0
            for v in vectors {
                let name = v["name"] as! String
                let input = v["input"] as! [String: Any]
                let expected = v["expected"] as! [String: Any]
                let err = run(function: function, input: input, expected: expected)
                if err == nil {
                    filePass += 1
                } else {
                    fileFail += 1
                    failures.append("\(filename)::\(name) — \(err!)")
                }
            }
            totalPass += filePass
            totalFail += fileFail
            let mark = fileFail == 0 ? "✓" : "✗"
            print("  \(mark) \(filename.padding(toLength: 34, withPad: " ", startingAt: 0)) \(filePass)/\(vectors.count)")
        }

        print("\nSwift KAT: \(totalPass) passed, \(totalFail) failed (\(totalPass + totalFail) vectors).")
        for failure in failures {
            print("  \(failure)")
        }
        XCTAssertEqual(totalFail, 0, "Swift KAT corpus mismatch — see stdout for failing vectors")
    }

    // MARK: -- dispatch

    private func run(function: String, input: [String: Any], expected: [String: Any]) -> String? {
        switch function {
        case "rpo256":
            return runRpo256(input, expected)
        case "rpo256Tagged":
            return runRpo256Tagged(input, expected)
        case "canonicalize":
            return runCanonicalize(input, expected)
        case "claimLeafHash":
            return runClaimLeafHash(input, expected)
        case "leafHash":
            return runLeafHash(input, expected)
        case "emptyLeafHash":
            return runEmptyLeafHash(input, expected)
        case "MerkleTree":
            return runMerkle(input, expected)
        case "deriveCid":
            return runDeriveCid(input, expected)
        case "hkdfSha256":
            return runHkdf(input, expected)
        case "parseDID":
            return runParseDid(input, expected)
        default:
            return "no Swift runner for function \"\(function)\""
        }
    }

    // MARK: -- per-function runners

    private func runRpo256(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let hex = input["hex"] as! String
        let got = bytesToHex(rpo256(hexToBytes(hex)))
        return matchHex(got: got, expected: expected["hex"] as! String)
    }

    private func runRpo256Tagged(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let tag = UInt8(input["tag"] as! Int)
        let content = hexToBytes(input["contentHex"] as! String)
        let got = bytesToHex(rpo256Tagged(tag, content))
        return matchHex(got: got, expected: expected["hex"] as! String)
    }

    private func runCanonicalize(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let value = reconstructCanonicalizeInput(input)
        do {
            let bytes = try canonicalize(value as Any)
            let got = bytesToHex(bytes)
            if let expectedError = expected["error"] as? String {
                return "expected error \"\(expectedError)\", got success \(got)"
            }
            return matchHex(got: got, expected: expected["hex"] as! String)
        } catch let e as CanonicalizeError {
            let code = canonicalizeErrorCode(e)
            if let expectedError = expected["error"] as? String {
                return code == expectedError ? nil : "expected error \"\(expectedError)\", got \"\(code)\""
            }
            return "unexpected CanonicalizeError \"\(code)\""
        } catch {
            return "unexpected error: \(error)"
        }
    }

    private func runClaimLeafHash(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let key = input["key"] as! String
        let value = input["value"] as Any
        do {
            let got = bytesToHex(try claimLeafHash(key: key, value: value))
            return matchHex(got: got, expected: expected["hex"] as! String)
        } catch {
            return "claimLeafHash threw: \(error)"
        }
    }

    private func runLeafHash(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let kh = hexToBytes(input["keyHex"] as! String)
        let vh = hexToBytes(input["valueHex"] as! String)
        let got = bytesToHex(leafHash(keyBytes: kh, valueBytes: vh))
        return matchHex(got: got, expected: expected["hex"] as! String)
    }

    private func runEmptyLeafHash(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let index = UInt64(input["index"] as! Int)
        let got = bytesToHex(emptyLeafHash(index: index))
        return matchHex(got: got, expected: expected["hex"] as! String)
    }

    private func runMerkle(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let entries = (input["entries"] as! [[String: Any]]).map { e -> (key: String, value: Any) in
            (key: e["key"] as! String, value: e["value"] as Any)
        }
        do {
            let tree = try MerkleTree(entries: entries)
            let expectedPadded = expected["paddedSize"] as! Int
            if tree.paddedSize != expectedPadded {
                return "paddedSize: \(tree.paddedSize) ≠ \(expectedPadded)"
            }
            let expectedDepth = expected["depth"] as! Int
            if tree.depth != expectedDepth {
                return "depth: \(tree.depth) ≠ \(expectedDepth)"
            }
            let expectedRootHex = expected["rootHex"] as! String
            if tree.rootHex != expectedRootHex {
                return "rootHex:\n      got      \(tree.rootHex)\n      expected \(expectedRootHex)"
            }
            let expectedProofs = expected["proofs"] as! [[String: Any]]
            for i in 0..<tree.paddedSize {
                let actual = tree.proof(at: i)
                let exp = expectedProofs[i]["sibling"] as! [[String: Any]]
                if actual.count != exp.count {
                    return "proof[\(i)] length: \(actual.count) ≠ \(exp.count)"
                }
                for j in 0..<actual.count {
                    let a = actual[j]
                    let eSib = exp[j]["siblingHex"] as! String
                    let eRight = exp[j]["isRight"] as! Bool
                    if bytesToHex(a.sibling) != eSib || a.isRight != eRight {
                        return "proof[\(i)][\(j)] mismatch"
                    }
                }
            }
            return nil
        } catch {
            return "MerkleTree threw: \(error)"
        }
    }

    private func runDeriveCid(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let header = input["headerWithoutCid"] as! [String: Any]
        let iat = UInt64(input["iat"] as! Int)
        do {
            let got = bytesToHex(try deriveCid(headerWithoutCid: header, iat: iat))
            return matchHex(got: got, expected: expected["hex"] as! String)
        } catch {
            return "deriveCid threw: \(error)"
        }
    }

    private func runHkdf(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let ikm = hexToBytes(input["ikmHex"] as! String)
        let salt = hexToBytes(input["saltHex"] as! String)
        let info = hexToBytes(input["infoHex"] as! String)
        let length = input["length"] as! Int
        let got = bytesToHex(hkdfSha256(ikm: ikm, salt: salt, info: info, length: length))
        return matchHex(got: got, expected: expected["hex"] as! String)
    }

    private func runParseDid(_ input: [String: Any], _ expected: [String: Any]) -> String? {
        let s = input["did"] as! String
        do {
            let parsed = try parseDID(s)
            if let expectedError = expected["error"] as? String {
                return "expected error \"\(expectedError)\", got success \(parsed)"
            }
            let expNet = expected["network"] as! String
            let expEnt = expected["entityType"] as! String
            let expId  = expected["identifier"] as! String
            if parsed.network != expNet || parsed.entityType != expEnt || parsed.identifier != expId {
                return "parsed mismatch: \(parsed) ≠ {network:\(expNet), entityType:\(expEnt), identifier:\(expId)}"
            }
            let round = formatDID(parsed)
            if round != s { return "round-trip: \(round) ≠ \(s)" }
            return nil
        } catch let e as DIDError {
            let code = didErrorCode(e)
            if let expectedError = expected["error"] as? String {
                return code == expectedError ? nil : "expected error \"\(expectedError)\", got \"\(code)\""
            }
            return "unexpected DIDError \"\(code)\""
        } catch {
            return "unexpected error: \(error)"
        }
    }

    // MARK: -- helpers

    private func matchHex(got: String, expected: String) -> String? {
        return got == expected ? nil : "hex mismatch:\n      got      \(got)\n      expected \(expected)"
    }

    private func canonicalizeErrorCode(_ e: CanonicalizeError) -> String {
        switch e {
        case .float: return "float"
        case .cycle: return "cycle"
        case .depthExceeded: return "depth"
        case .stringTooLong: return "string-too-long"
        case .nanOrInf: return "nan-or-inf"
        }
    }

    private func didErrorCode(_ e: DIDError) -> String {
        switch e {
        case .malformed: return "malformed"
        case .extraColons: return "extra-colons"
        case .emptyComponent: return "empty-component"
        }
    }

    /// Mirror of the TS runner's reconstructCanonicalizeInput: rebuild
    /// inputs that can't round-trip through JSON (cycles, NaN, Infinity,
    /// huge synthesized strings, depth-N nesting).
    private func reconstructCanonicalizeInput(_ input: [String: Any]) -> Any? {
        if let s = input["synthesize"] as? String {
            switch s {
            case "cycle-self":
                let dict = NSMutableDictionary()
                dict["name"] = "cycle"
                dict["self"] = dict
                return dict
            case "depth":
                let levels = input["levels"] as! Int
                var deep: Any = "leaf"
                for _ in 0..<levels {
                    deep = ["n": deep]
                }
                return deep
            case "long-string":
                let bytes = input["utf8Bytes"] as! Int
                return String(repeating: "a", count: bytes)
            default:
                fatalError("Unknown synthesize tag \(s)")
            }
        }
        if let nonJson = input["nonJsonable"] as? String {
            switch nonJson {
            case "NaN":       return Double.nan
            case "Infinity":  return Double.infinity
            case "-Infinity": return -Double.infinity
            case "undefined": return Optional<Any>.none as Any
            default: fatalError("Unknown nonJsonable tag \(nonJson)")
            }
        }
        // JSONSerialization decodes numbers as NSNumber. We need to
        // preserve booleans separately from integers since NSNumber
        // overloads both. The "json" field can be any value type
        // including null (NSNull).
        return input["json"]
    }

    /// Find the test-vectors directory by walking up from this source
    /// file's compile-time location. Resolves under `swift test`, under
    /// Xcode-driven test runs, and under CI containers identically — the
    /// source path is baked in by the compiler.
    ///
    /// Layout:
    ///   {repo}/elabify-core/test-vectors/
    ///   {repo}/elabify-core/bindings/swift/Tests/ElabifyCoreTests/KatRunnerTests.swift
    /// So we go up 4 directory levels and append `test-vectors`.
    private func locateVectorDir(file: StaticString = #filePath) throws -> URL {
        // String-based path math sidesteps URL's trailing-slash semantics.
        // From {repo}/elabify-core/bindings/swift/Tests/ElabifyCoreTests/KatRunnerTests.swift
        // we need to walk to {repo}/elabify-core/ — that's the parent
        // of the bindings/ directory, 5 path-component steps up from the
        // .swift file itself.
        let filePath = String(describing: file)
        var components = filePath.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        for _ in 0..<5 {
            guard !components.isEmpty else { break }
            components.removeLast()
        }
        let dir = URL(fileURLWithPath: "/" + components.joined(separator: "/"))
        let candidate = dir.appendingPathComponent("test-vectors", isDirectory: true)
        guard FileManager.default.fileExists(atPath: candidate.path) else {
            throw NSError(
                domain: "KatRunner",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "test-vectors/ not found at \(candidate.path)"]
            )
        }
        return candidate
    }
}
