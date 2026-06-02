// Public types for @elabify/core. The shape mirrors the spec API in
// elabify-core/README.md §4.1 with Phase 0 omissions noted at each
// re-export site (see merkle.ts, canonicalJson.ts, rpo256.ts).

export type Bytes = Uint8Array;

/** A claim entry: lexicographically-sortable key, JSON-serializable value. */
export type ClaimEntry = readonly [key: string, value: unknown];
