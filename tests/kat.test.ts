// KAT corpus regression gate. Runs the full bundled test-vectors/*.kat.json
// suite via the shared runKat() and fails the workspace test if any vector
// mismatches.
//
// This makes the corpus a first-class CI gate: any change to merkle.ts /
// canonicalize.ts / rpo256.ts / hkdf.ts / did.ts that affects byte output
// surfaces here before it can ship.
//
// The corpus is FROZEN as of @elabify/core 0.1.0. Updating any vector
// requires a major version bump (see elabify-core/README.md §4.1
// and ADR-0017).

import { describe, expect, it } from 'vitest';
import { runKat } from '../src/cli/runKat.js';

describe('KAT corpus regression gate', () => {
  it('every vector in test-vectors/ matches the current build', () => {
    const result = runKat();
    expect(result.failures, 'KAT corpus mismatch — see stdout above for failing vectors').toBe(0);
    expect(result.totalPass).toBeGreaterThan(0);
    expect(result.files).toBeGreaterThan(0);
  });
});
