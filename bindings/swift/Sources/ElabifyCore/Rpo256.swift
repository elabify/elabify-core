// RPO-256 sponge hash over the Goldilocks field. Byte-equivalent port of
// the TypeScript implementation in @elabify/core/src/rpo256.ts.
//
// Field: p = 2^64 - 2^32 + 1. We use Swift's native UInt128 (Swift 6.0+)
// for the multiplication intermediate, then reduce mod p. The TS source
// uses BigInt; UInt128 is the equivalent native type here. Cross-binding
// equivalence is enforced by the KAT corpus in test-vectors/rpo256.kat.json
// (10 vectors covering rate-boundary, multi-block, and 1 KB input).

import Foundation

private let GoldP: UInt64 = 0xffff_ffff_0000_0001 // 2^64 - 2^32 + 1
private let alpha: UInt64 = 7
private let alphaInv: UInt64 = 10540996611094048183

@inline(__always)
private func fm(_ a: UInt128) -> UInt64 {
    return UInt64(a % UInt128(GoldP))
}

@inline(__always)
private func fmAdd(_ a: UInt64, _ b: UInt64) -> UInt64 {
    return fm(UInt128(a) + UInt128(b))
}

@inline(__always)
private func fmMul(_ a: UInt64, _ b: UInt64) -> UInt64 {
    return fm(UInt128(a) * UInt128(b))
}

private func fmPow(_ base: UInt64, _ exp: UInt64) -> UInt64 {
    var r: UInt64 = 1
    var b = base
    var e = exp
    while e > 0 {
        if e & 1 == 1 { r = fmMul(r, b) }
        b = fmMul(b, b)
        e >>= 1
    }
    return r
}

// 12×12 MDS matrix (circulant), constants from the TS source.
private let MDS: [[UInt64]] = [
    [ 7, 23,  8, 26, 20,  7,  1, 20,  4,  8,  1,  1],
    [ 8,  7, 23,  8, 26, 20,  7,  1, 20,  4,  8,  1],
    [ 1,  8,  7, 23,  8, 26, 20,  7,  1, 20,  4,  8],
    [ 8,  1,  8,  7, 23,  8, 26, 20,  7,  1, 20,  4],
    [ 4,  8,  1,  8,  7, 23,  8, 26, 20,  7,  1, 20],
    [20,  4,  8,  1,  8,  7, 23,  8, 26, 20,  7,  1],
    [ 1, 20,  4,  8,  1,  8,  7, 23,  8, 26, 20,  7],
    [ 7,  1, 20,  4,  8,  1,  8,  7, 23,  8, 26, 20],
    [20,  7,  1, 20,  4,  8,  1,  8,  7, 23,  8, 26],
    [26, 20,  7,  1, 20,  4,  8,  1,  8,  7, 23,  8],
    [ 8, 26, 20,  7,  1, 20,  4,  8,  1,  8,  7, 23],
    [23,  8, 26, 20,  7,  1, 20,  4,  8,  1,  8,  7],
]

private let RC: [UInt64] = [
    7096123747201,    3073462498391,    5423984235601,    1234987654321,
    9876543210123,    2345678901234,    8765432109876,    4567890123456,
    6789012345678,    9012345678901,    1357924680135,    2468013579246,
    3141592653589,    2718281828459,    1618033988749,    1414213562373,
    1732050808567,    2236067977499,    2449489742783,    2645751311064,
    2828427124746,    3000000000000,    3141592653589,    3316624790355,
]

private func mdsMul(_ s: inout [UInt64]) {
    var out = [UInt64](repeating: 0, count: 12)
    for i in 0..<12 {
        var v: UInt64 = 0
        for j in 0..<12 {
            v = fmAdd(v, fmMul(MDS[i][j], s[j]))
        }
        out[i] = v
    }
    s = out
}

/// 7 rounds of (add-RC, S-box forward, MDS, add-RC, S-box inverse, MDS).
private func rpoPermutation(_ state: inout [UInt64]) {
    for r in 0..<7 {
        for i in 0..<12 {
            state[i] = fmAdd(state[i], RC[(r * 24 + i) % RC.count])
        }
        for i in 0..<12 {
            state[i] = fmPow(state[i], alpha)
        }
        mdsMul(&state)
        for i in 0..<12 {
            state[i] = fmAdd(state[i], RC[(r * 24 + 12 + i) % RC.count])
        }
        for i in 0..<12 {
            state[i] = fmPow(state[i], alphaInv)
        }
        mdsMul(&state)
    }
}

// ─── Public surface ──────────────────────────────────────────────────────

/// RPO-256 hash. Returns 32 bytes.
///
/// Sponge construction: rate=8 limbs (64 bytes), capacity=4 limbs.
/// Padding: append `0x01` then zeros to a 64-byte boundary (always at least
/// one full pad block). Squeeze 32 bytes from state[0..3] little-endian.
public func rpo256(_ input: Data) -> Data {
    let padLen = 64 - (input.count % 64)
    var padded = Data(count: input.count + padLen)
    padded.replaceSubrange(0..<input.count, with: input)
    padded[input.count] = 0x01

    var state = [UInt64](repeating: 0, count: 12)
    let blocks = padded.count / 64
    for blk in 0..<blocks {
        let base = blk * 64
        for i in 0..<8 {
            var v: UInt64 = 0
            for j in 0..<8 {
                v |= UInt64(padded[base + i * 8 + j]) << (j * 8)
            }
            state[i] = fmAdd(state[i], v)
        }
        rpoPermutation(&state)
    }

    var out = Data(count: 32)
    for i in 0..<4 {
        var v = state[i]
        for k in 0..<8 {
            out[i * 8 + k] = UInt8(v & 0xff)
            v >>= 8
        }
    }
    return out
}

/// RPO-256 with a 1-byte domain-separation tag prepended.
public func rpo256Tagged(_ tag: UInt8, _ content: Data) -> Data {
    var buf = Data(count: 1 + content.count)
    buf[0] = tag
    buf.replaceSubrange(1..<buf.count, with: content)
    return rpo256(buf)
}
