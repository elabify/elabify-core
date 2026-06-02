// Canonical JSON serialization, byte-equivalent with @elabify/core's
// src/canonicalJson.ts. NFC-normalized strings + keys, sorted keys,
// integer-only numbers, depth ≤ 32, strings ≤ 64 KiB UTF-8.
//
// Cross-binding equivalence is enforced by test-vectors/canonicalize.kat.json
// (26 vectors covering primitives, NFC equivalence, sorted-key behaviour,
// and every CanonicalizeError code).
//
// Implementation note: this canonicalizer accepts Swift `Any` values — the
// TS canonicalize takes `unknown`. Swift's type system doesn't quite line
// up with JSON's open type discipline, so we walk via dynamic checks. The
// supported runtime types are:
//   - NSNull / Optional<Any>.none → null
//   - Bool                        → true / false
//   - Int, Int64, UInt, UInt64    → integer literal
//   - Double, Float               → integer-valued only; else throws
//   - String                      → NFC-normalized + JSON-escaped string
//   - [Any]                       → JSON array
//   - [String: Any]               → JSON object with sorted (NFC) keys
// Anything else throws CanonicalizeError.nanOrInf with a type hint in
// the error message.

import Foundation

private let depthLimit = 32
private let stringByteLimit = 64 * 1024 // 64 KiB UTF-8

public enum CanonicalizeError: Error, Equatable {
    case float
    case cycle
    case depthExceeded
    case stringTooLong
    case nanOrInf
}

/// Canonical JSON of `value` as UTF-8 bytes.
public func canonicalize(_ value: Any) throws -> Data {
    let s = try emit(value, depth: 0, pathSet: NSHashTable<AnyObject>.weakObjects())
    return Data(s.utf8)
}

/// Canonical JSON of `value` as a UTF-8 string (for debugging / diffing).
public func canonicalJsonString(_ value: Any) throws -> String {
    return try emit(value, depth: 0, pathSet: NSHashTable<AnyObject>.weakObjects())
}

// MARK: -- internals

private func emit(_ value: Any, depth: Int, pathSet: NSHashTable<AnyObject>) throws -> String {
    if depth > depthLimit { throw CanonicalizeError.depthExceeded }

    // Unwrap Optional.some(Optional.none) etc. once.
    let unwrapped = unwrapOptional(value)
    if unwrapped is NSNull { return "null" }

    if let s = unwrapped as? String {
        return try emitString(s)
    }

    // NSNumber bridges to multiple Swift types: Bool, Int, Double all match
    // via `as?` because of the implicit Objective-C number conversion. To
    // distinguish Bool from a numeric 0/1 we have to consult the underlying
    // ObjC type tag (CFBooleanGetTypeID) — otherwise JSON `1` and `true`
    // collide.
    if let n = unwrapped as? NSNumber {
        if CFGetTypeID(n) == CFBooleanGetTypeID() {
            return n.boolValue ? "true" : "false"
        }
        let d = n.doubleValue
        if !d.isFinite { throw CanonicalizeError.nanOrInf }
        if d.rounded() != d { throw CanonicalizeError.float }
        // The number is integer-valued. Use the int64 representation for
        // emission to match JSON.stringify's "no trailing zero" form for
        // integers. NSNumber's int64Value handles the range safely for
        // values within UInt64 — beyond that we'd need bigint, which is
        // out of scope.
        return String(n.int64Value)
    }

    // Native Swift Bool that didn't bridge to NSNumber (rare, but covers
    // direct Swift callers passing a true literal as Any).
    if let b = unwrapped as? Bool { return b ? "true" : "false" }

    // Native Swift integer / float types (when not bridged through
    // NSNumber). The branches below match direct Swift callers.
    if let i = unwrapped as? Int    { return String(i) }
    if let i = unwrapped as? Int64  { return String(i) }
    if let u = unwrapped as? UInt64 { return String(u) }
    if let d = unwrapped as? Double {
        if !d.isFinite { throw CanonicalizeError.nanOrInf }
        if d.rounded() != d { throw CanonicalizeError.float }
        if d >= Double(Int64.min) && d <= Double(Int64.max) {
            return String(Int64(d))
        }
        throw CanonicalizeError.float
    }

    if let arr = unwrapped as? [Any] {
        if let ref = boxedReference(arr) {
            if pathSet.contains(ref) { throw CanonicalizeError.cycle }
            pathSet.add(ref)
            defer { pathSet.remove(ref) }
            let parts = try arr.map { try emit($0, depth: depth + 1, pathSet: pathSet) }
            return "[" + parts.joined(separator: ",") + "]"
        } else {
            let parts = try arr.map { try emit($0, depth: depth + 1, pathSet: pathSet) }
            return "[" + parts.joined(separator: ",") + "]"
        }
    }

    if let obj = unwrapped as? [String: Any] {
        if let ref = boxedReference(obj) {
            if pathSet.contains(ref) { throw CanonicalizeError.cycle }
            pathSet.add(ref)
            defer { pathSet.remove(ref) }
            return try emitObject(obj, depth: depth, pathSet: pathSet)
        } else {
            return try emitObject(obj, depth: depth, pathSet: pathSet)
        }
    }

    // Unsupported type — bigint, function, etc. Map to nan-or-inf per spec
    // (TS canonicalize uses the same code for "unsupported value type").
    throw CanonicalizeError.nanOrInf
}

private func emitObject(_ obj: [String: Any], depth: Int, pathSet: NSHashTable<AnyObject>) throws -> String {
    // NFC-normalize keys, then sort by code-unit comparison (matches
    // JavaScript's default string sort + the TS implementation).
    let normalized: [(raw: String, nfc: String)] = obj.keys.map { raw in
        (raw: raw, nfc: raw.precomposedStringWithCanonicalMapping)
    }.sorted { a, b in a.nfc < b.nfc }

    var parts: [String] = []
    parts.reserveCapacity(normalized.count)
    for entry in normalized {
        let keyStr = try emitString(entry.nfc)
        let val = try emit(obj[entry.raw] as Any, depth: depth + 1, pathSet: pathSet)
        parts.append(keyStr + ":" + val)
    }
    return "{" + parts.joined(separator: ",") + "}"
}

private func emitString(_ s: String) throws -> String {
    let nfc = s.precomposedStringWithCanonicalMapping
    if nfc.utf8.count > stringByteLimit { throw CanonicalizeError.stringTooLong }
    return jsonEscape(nfc)
}

/// RFC 8259 minimal JSON string escape. Matches JavaScript's
/// JSON.stringify behaviour for the BMP.
private func jsonEscape(_ s: String) -> String {
    var out = "\""
    out.reserveCapacity(s.count + 2)
    for scalar in s.unicodeScalars {
        switch scalar.value {
        case 0x22: out += "\\\""
        case 0x5C: out += "\\\\"
        case 0x08: out += "\\b"
        case 0x09: out += "\\t"
        case 0x0A: out += "\\n"
        case 0x0C: out += "\\f"
        case 0x0D: out += "\\r"
        case 0x00...0x1F:
            out += String(format: "\\u%04x", scalar.value)
        default:
            out.append(Character(scalar))
        }
    }
    out += "\""
    return out
}

private func unwrapOptional(_ v: Any) -> Any {
    let mirror = Mirror(reflecting: v)
    if mirror.displayStyle == .optional {
        if let child = mirror.children.first {
            return unwrapOptional(child.value)
        }
        return NSNull()
    }
    return v
}

/// Returns an AnyObject reference for arrays / dicts of class type or
/// containers backed by NSArray/NSDictionary — sufficient for cycle
/// detection when the test inputs use NSMutableDictionary/Array (which
/// is what synthesized cycles in the runner produce). Pure value-type
/// Swift dictionaries are copy-on-write and cannot form cycles.
///
/// `Any as AnyObject` always succeeds in Swift (value types get boxed),
/// so the conditional cast is unconditional. The unconditional `as`
/// form is correct here because we want any concrete object reference,
/// and the boxing of value types is precisely what we use to detect
/// "is this the same NSDictionary instance" via ===.
private func boxedReference(_ v: Any) -> AnyObject? {
    return v as AnyObject
}
