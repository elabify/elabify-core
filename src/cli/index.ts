#!/usr/bin/env node
//
// @elabify/core CLI — `npx elabify-core <subcommand>`. Two stdin→stdout
// filters and a kat-run delegate.
//
// Subcommands:
//
//   compute-root           Read a claims JSON object from stdin, build the
//                          Merkle tree over its (key, value) pairs in
//                          sorted-key order, print the root hex (no 0x
//                          prefix, no trailing newline tweaks). Used by
//                          Foundry tests in M3 via `vm.ffi(...)`.
//
//   canonicalize           Read a JSON value from stdin, print its canonical
//                          form as hex (UTF-8 bytes of the canonical
//                          string). Useful for debugging cross-platform
//                          serialization mismatches.
//
//   kat-run                Run the bundled KAT corpus against this build of
//                          @elabify/core. Fails non-zero on any mismatch.
//                          The corpus ships with the package (see
//                          package.json files[].test-vectors).
//
//   version | --version    Print the package version + RPO-256 sponge
//                          construction note.
//
// Examples:
//   echo '{"a":1,"b":"two"}' | npx elabify-core compute-root
//   echo '{"a":1}'           | npx elabify-core canonicalize
//   npx elabify-core kat-run

import { readFileSync } from 'node:fs';

import { bytesToHex, canonicalize, MerkleTree } from '../index.js';
import { runKat } from './runKat.js';

const SUBCOMMANDS = ['compute-root', 'canonicalize', 'kat-run', 'version', '--version', '-h', '--help'];

function readStdin(): string {
  // Node's readFileSync(0, ...) reads from fd 0 (stdin). Synchronous, fine
  // for a one-shot CLI filter.
  return readFileSync(0, 'utf8');
}

function usage(): never {
  process.stderr.write(`Usage: elabify-core <subcommand>

Subcommands:
  compute-root    Read claims JSON from stdin, print Merkle root hex.
  canonicalize    Read JSON from stdin, print canonical form as UTF-8 hex.
  kat-run         Run the bundled KAT corpus against this build.
  version         Print the package version.

`);
  process.exit(2);
}

function main(): void {
  const sub = process.argv[2];
  if (!sub || !SUBCOMMANDS.includes(sub)) usage();

  if (sub === '-h' || sub === '--help') usage();

  if (sub === 'version' || sub === '--version') {
    // package.json sits two dirs up from dist/cli/index.js in the shipped
    // tree, and three dirs up at dev time (src/cli/). Use a try-list.
    const candidates = ['../../package.json', '../../../package.json'];
    for (const rel of candidates) {
      try {
        const pkg = JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8')) as { version: string };
        process.stdout.write(`@elabify/core ${pkg.version} — RPO-256 sponge (post-ADR-0020), M0 wire format\n`);
        return;
      } catch {
        /* try next */
      }
    }
    process.stdout.write('@elabify/core (version unknown)\n');
    return;
  }

  if (sub === 'compute-root') {
    const claims = JSON.parse(readStdin()) as Record<string, unknown>;
    if (typeof claims !== 'object' || claims === null || Array.isArray(claims)) {
      process.stderr.write('compute-root: stdin must be a JSON object of (key → value) claims.\n');
      process.exit(1);
    }
    const sortedEntries = Object.keys(claims).sort().map((k) => [k, claims[k]] as const);
    const tree = new MerkleTree(sortedEntries);
    process.stdout.write(tree.rootHex);
    return;
  }

  if (sub === 'canonicalize') {
    const value = JSON.parse(readStdin()) as unknown;
    process.stdout.write(bytesToHex(canonicalize(value)));
    return;
  }

  if (sub === 'kat-run') {
    const result = runKat();
    process.exit(result.failures === 0 ? 0 : 1);
  }
}

main();
