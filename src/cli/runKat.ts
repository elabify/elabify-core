// Shared KAT runner. Used both by the bundled CLI (`elabify-core kat-run`)
// and by the dev npm script (`npm run kat:run`).
//
// Reads ../../test-vectors/*.kat.json at runtime (relative to this file's
// location — works both pre-build under tsx and post-build under
// node dist/cli/runKat.js because the test-vectors/ directory is shipped
// at the package root and the directory layout is preserved).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  bytesToHex,
  canonicalize,
  CanonicalizeError,
  claimLeafHash,
  deriveCid,
  DIDError,
  emptyLeafHash,
  formatDID,
  hexToBytes,
  hkdfSha256,
  leafHash,
  MerkleTree,
  parseDID,
  rpo256,
  rpo256Tagged,
} from '../index.js';

interface Vector {
  readonly name: string;
  readonly description?: string;
  readonly input: any;
  readonly expected: any;
}
interface VectorFile {
  readonly $schema: string;
  readonly function: string;
  readonly description: string;
  readonly vectors: readonly Vector[];
}

type Runner = (input: any, expected: any) => string | null;

const RUNNERS: Record<string, Runner> = {
  rpo256: ({ hex }, expected) => assertHex(bytesToHex(rpo256(hexToBytes(hex))), expected.hex),

  rpo256Tagged: ({ tag, contentHex }, expected) =>
    assertHex(bytesToHex(rpo256Tagged(tag, hexToBytes(contentHex))), expected.hex),

  canonicalize: (input, expected) => {
    const value = reconstructCanonicalizeInput(input);
    try {
      const out = bytesToHex(canonicalize(value.value));
      if ('error' in expected) return `expected error "${expected.error}", canonicalize succeeded with ${out}`;
      return assertHex(out, expected.hex);
    } catch (e) {
      if (e instanceof CanonicalizeError) {
        if ('error' in expected && e.code === expected.error) return null;
        return `expected ${'error' in expected ? `error "${expected.error}"` : `hex ${expected.hex}`}, got CanonicalizeError code "${e.code}"`;
      }
      throw e;
    }
  },

  claimLeafHash: ({ key, value }, expected) =>
    assertHex(bytesToHex(claimLeafHash(key, value)), expected.hex),

  leafHash: ({ keyHex, valueHex }, expected) =>
    assertHex(bytesToHex(leafHash(hexToBytes(keyHex), hexToBytes(valueHex))), expected.hex),

  emptyLeafHash: ({ index }, expected) =>
    assertHex(bytesToHex(emptyLeafHash(index)), expected.hex),

  MerkleTree: ({ entries }, expected) => {
    const tree = new MerkleTree(entries.map((e: any) => [e.key, e.value]));
    if (tree.paddedSize !== expected.paddedSize) return `paddedSize: ${tree.paddedSize} ≠ ${expected.paddedSize}`;
    if (tree.depth !== expected.depth) return `depth: ${tree.depth} ≠ ${expected.depth}`;
    if (tree.rootHex !== expected.rootHex) return `rootHex:\n      got      ${tree.rootHex}\n      expected ${expected.rootHex}`;
    for (let i = 0; i < tree.paddedSize; i++) {
      const actual = tree.proof(i).map((e) => ({ siblingHex: bytesToHex(e.sibling), isRight: e.isRight }));
      const exp = expected.proofs[i].sibling;
      if (actual.length !== exp.length) return `proof[${i}] length: ${actual.length} ≠ ${exp.length}`;
      for (let j = 0; j < actual.length; j++) {
        const a = actual[j] as { siblingHex: string; isRight: boolean };
        const e = exp[j] as { siblingHex: string; isRight: boolean };
        if (a.siblingHex !== e.siblingHex || a.isRight !== e.isRight) {
          return `proof[${i}][${j}]: ${JSON.stringify(a)} ≠ ${JSON.stringify(e)}`;
        }
      }
    }
    return null;
  },

  deriveCid: ({ headerWithoutCid, iat }, expected) =>
    assertHex(bytesToHex(deriveCid(headerWithoutCid, iat)), expected.hex),

  hkdfSha256: ({ ikmHex, saltHex, infoHex, length }, expected) =>
    assertHex(
      bytesToHex(hkdfSha256(hexToBytes(ikmHex), hexToBytes(saltHex), hexToBytes(infoHex), length)),
      expected.hex,
    ),

  parseDID: ({ did }, expected) => {
    try {
      const parsed = parseDID(did);
      if ('error' in expected) return `expected error "${expected.error}", parseDID succeeded`;
      if (parsed.network !== expected.network || parsed.entityType !== expected.entityType || parsed.identifier !== expected.identifier) {
        return `parsed mismatch: ${JSON.stringify(parsed)} ≠ ${JSON.stringify(expected)}`;
      }
      const round = formatDID(parsed);
      if (round !== did) return `round-trip mismatch: ${round} ≠ ${did}`;
      return null;
    } catch (e) {
      if (e instanceof DIDError) {
        if ('error' in expected && e.code === expected.error) return null;
        return `expected ${'error' in expected ? `error "${expected.error}"` : 'success'}, got DIDError code "${e.code}"`;
      }
      throw e;
    }
  },
};

function assertHex(actual: string, expected: string): string | null {
  return actual === expected ? null : `hex mismatch:\n      got      ${actual}\n      expected ${expected}`;
}

function reconstructCanonicalizeInput(input: any): { value: unknown } {
  if (input?.synthesize === 'cycle-self') {
    const a: any = { name: 'cycle' };
    a.self = a;
    return { value: a };
  }
  if (input?.synthesize === 'depth') {
    let deep: unknown = 'leaf';
    for (let i = 0; i < input.levels; i++) deep = { n: deep };
    return { value: deep };
  }
  if (input?.synthesize === 'long-string') {
    return { value: 'a'.repeat(input.utf8Bytes) };
  }
  if (input?.nonJsonable === 'NaN') return { value: NaN };
  if (input?.nonJsonable === 'Infinity') return { value: Infinity };
  if (input?.nonJsonable === '-Infinity') return { value: -Infinity };
  if (input?.nonJsonable === 'undefined') return { value: undefined };
  return { value: input.json };
}

function locateVectorDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  // Two candidate roots: pre-build (src/cli/) and post-build (dist/cli/).
  // Walk up looking for a test-vectors/ sibling of the package root.
  const candidates = [
    path.join(here, '..', '..', 'test-vectors'),         // src/cli → ../../
    path.join(here, '..', '..', '..', 'test-vectors'),   // dist/cli → ../../../
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  throw new Error(`runKat: test-vectors/ not found. Tried ${candidates.join(', ')}`);
}

export interface KatResult {
  readonly totalPass: number;
  readonly failures: number;
  readonly files: number;
}

export function runKat(): KatResult {
  const dir = locateVectorDir();
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.kat.json')).sort();
  if (files.length === 0) {
    process.stderr.write(`No KAT files found in ${dir}\n`);
    return { totalPass: 0, failures: 0, files: 0 };
  }
  process.stdout.write(`Running KAT vectors from ${path.relative(process.cwd(), dir)}/\n\n`);

  let totalPass = 0;
  let totalFail = 0;
  const failures: string[] = [];

  for (const filename of files) {
    const body: VectorFile = JSON.parse(fs.readFileSync(path.join(dir, filename), 'utf8'));
    const runner = RUNNERS[body.function];
    if (!runner) {
      process.stderr.write(`  \x1b[31m✗\x1b[0m ${filename}: no runner for "${body.function}"\n`);
      totalFail += body.vectors.length;
      continue;
    }
    let filePass = 0;
    let fileFail = 0;
    for (const v of body.vectors) {
      const err = runner(v.input, v.expected);
      if (err === null) filePass++;
      else {
        fileFail++;
        failures.push(`${filename}::${v.name}\n    ${err}`);
      }
    }
    totalPass += filePass;
    totalFail += fileFail;
    const mark = fileFail === 0 ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
    process.stdout.write(`  ${mark} ${filename.padEnd(34)} ${filePass}/${body.vectors.length}\n`);
  }

  process.stdout.write(`\nTotal: ${totalPass} passed, ${totalFail} failed (${totalPass + totalFail} vectors).\n`);
  if (totalFail > 0) {
    process.stderr.write('\nFailures:\n');
    for (const f of failures) process.stderr.write(`  ${f}\n`);
  }

  return { totalPass, failures: totalFail, files: files.length };
}
