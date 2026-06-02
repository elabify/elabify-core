// KAT (known-answer-test) vector generator for @elabify/core.
//
// Runs every public function over a deterministic set of inputs and writes
// the input → output pairs as JSON to ../../test-vectors/. The committed
// vectors are the cross-binding wire-format contract — the Swift port
// (bindings/swift) and the Kotlin port (bindings/kotlin) each implement a
// runner that consumes these same files and asserts byte-equivalence.
//
// Run:    npm run -w @elabify/core kat:gen
// Verify: npm run -w @elabify/core kat:run
//
// Vectors are FROZEN once committed. Changing any vector requires bumping
// @elabify/core's major version (see ADR-0017 + the elabify-core README).
//
// Schema (per vector file):
//   {
//     "$schema":     "https://elabify.org/kat/v1.json",
//     "function":    "<canonical function name>",
//     "description": "<one-line summary + pointer at spec section>",
//     "vectors":     [ { "name", "input", "expected" }, ... ]
//   }
//
// `input` and `expected` are shape-free; each function's vector body uses
// whichever shape lets the runner round-trip cleanly (bytes as hex strings,
// strings verbatim, JSON values as JSON values, errors as { code }).

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
  utf8,
} from '../../src/index.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.join(HERE, '..', '..', 'test-vectors');
fs.mkdirSync(OUT_DIR, { recursive: true });

interface Vector {
  readonly name: string;
  readonly description?: string;
  readonly input: unknown;
  readonly expected: unknown;
}
interface VectorFile {
  readonly $schema: string;
  readonly function: string;
  readonly description: string;
  readonly vectors: readonly Vector[];
}

let totalVectors = 0;
const written: string[] = [];

function writeVectorFile(filename: string, body: VectorFile): void {
  const text = JSON.stringify(body, null, 2) + '\n';
  const full = path.join(OUT_DIR, filename);
  fs.writeFileSync(full, text, 'utf8');
  totalVectors += body.vectors.length;
  written.push(`${filename}  ${body.vectors.length.toString().padStart(3)} vectors  ${(text.length / 1024).toFixed(1)} KB`);
}

const SCHEMA_URL = 'https://elabify.org/kat/v1.json';

// ─── rpo256 ──────────────────────────────────────────────────────────
function genRpo256(): void {
  const inputs: { name: string; description?: string; hex: string }[] = [
    { name: 'empty',           description: 'Empty input — exercises 10* padding alone.', hex: '' },
    { name: 'single-byte',     description: 'Single 0x42 byte.', hex: '42' },
    { name: 'hello-world',     description: 'UTF-8 "hello world" (11 bytes).', hex: bytesToHex(utf8('hello world')) },
    { name: 'rate-minus-one',  description: '63 zero bytes (one byte under the 64-byte rate).', hex: '00'.repeat(63) },
    { name: 'rate-exact',      description: '64 zero bytes (one rate-block before padding).', hex: '00'.repeat(64) },
    { name: 'rate-plus-one',   description: '65 zero bytes (forces a second absorption block).', hex: '00'.repeat(65) },
    { name: 'two-blocks',      description: '128 zero bytes — exactly two rate blocks before padding.', hex: '00'.repeat(128) },
    { name: 'two-blocks-plus', description: '129 zero bytes — three blocks total.', hex: '00'.repeat(129) },
    { name: 'patterned-1k',    description: '1024 bytes of 0x5a — large input regression.', hex: '5a'.repeat(1024) },
    { name: 'unicode-nfc',     description: 'UTF-8 of NFC-normalized "café" (5 bytes).', hex: bytesToHex(utf8('café'.normalize('NFC'))) },
  ];
  writeVectorFile('rpo256.kat.json', {
    $schema: SCHEMA_URL,
    function: 'rpo256',
    description: 'RPO-256 sponge hash over Goldilocks field. Returns 32 bytes. See wire-formats.md §5 and ADR-0020.',
    vectors: inputs.map(({ name, description, hex }) => ({
      name,
      ...(description ? { description } : {}),
      input: { hex },
      expected: { hex: bytesToHex(rpo256(hexToBytes(hex))) },
    })),
  });
}

// ─── rpo256Tagged ────────────────────────────────────────────────────
function genRpo256Tagged(): void {
  type T = { name: string; description?: string; tag: number; contentHex: string };
  const inputs: T[] = [
    { name: 'tag-empty-leaf-idx-0', description: 'Domain tag 0x00 + u64BE(0). Empty-leaf hash for index 0.', tag: 0x00, contentHex: '0000000000000000' },
    { name: 'tag-empty-leaf-idx-7', description: 'Domain tag 0x00 + u64BE(7). Empty-leaf hash for index 7.', tag: 0x00, contentHex: '0000000000000007' },
    { name: 'tag-leaf-64',          description: 'Domain tag 0x01 + 64 bytes (typical leaf-hash input: keyH ‖ valH).', tag: 0x01, contentHex: 'aa'.repeat(32) + 'bb'.repeat(32) },
    { name: 'tag-inner-64',         description: 'Domain tag 0x02 + 64 bytes (typical Merkle inner-node combine).', tag: 0x02, contentHex: '11'.repeat(32) + '22'.repeat(32) },
    { name: 'tag-user-id-pk',       description: 'Domain tag 0x03 + 32-byte pubkey (user-identifier derivation per wire-formats.md §2.2).', tag: 0x03, contentHex: '5e'.repeat(32) },
    { name: 'tag-cid-derivation',   description: 'Domain tag 0x04 + 41 bytes (header-shaped CID derivation prefix).', tag: 0x04, contentHex: '7b227622'.repeat(10) + '00' },
    { name: 'tag-0xff-empty',       description: 'Domain tag 0xff (boundary) with empty content.', tag: 0xff, contentHex: '' },
  ];
  writeVectorFile('rpo256-tagged.kat.json', {
    $schema: SCHEMA_URL,
    function: 'rpo256Tagged',
    description: 'Domain-tagged RPO-256: rpo256([tag, ...content]). Tags 0x00-0x04 reserved per wire-formats.md §3.',
    vectors: inputs.map(({ name, description, tag, contentHex }) => ({
      name,
      ...(description ? { description } : {}),
      input: { tag, contentHex },
      expected: { hex: bytesToHex(rpo256Tagged(tag, hexToBytes(contentHex))) },
    })),
  });
}

// ─── canonicalize ────────────────────────────────────────────────────
function genCanonicalize(): void {
  type Ok = { name: string; description?: string; input: unknown };
  type Err = { name: string; description?: string; input: unknown; errorCode: string };

  const happy: Ok[] = [
    { name: 'null',          input: null },
    { name: 'true',          input: true },
    { name: 'false',         input: false },
    { name: 'zero',          input: 0 },
    { name: 'positive-int',  input: 42 },
    { name: 'negative-int',  input: -7 },
    { name: 'empty-string',  input: '' },
    { name: 'ascii-string',  input: 'hello' },
    { name: 'string-quotes', input: 'a"b' },
    { name: 'string-newline', input: 'a\nb' },
    { name: 'string-nfc-equivalent', description: 'NFC-decomposed input is normalized to the composed form.', input: 'é' /* é decomposed */ },
    { name: 'empty-array',   input: [] },
    { name: 'empty-object',  input: {} },
    { name: 'sorted-flat',   description: 'Object keys sort lexicographically.', input: { b: 1, a: 2, c: 3 } },
    { name: 'nested',        input: { z: { y: 1, x: 2 }, a: 1 } },
    { name: 'array-of-objs', input: [{ b: 2 }, { a: 1 }] },
    { name: 'mixed-array',   input: [1, 'two', true, null, [3]] },
    { name: 'integer-float-equivalent', description: '1.0 is an integer-valued float and is accepted.', input: 1.0 },
  ];

  const errors: Err[] = [
    { name: 'reject-nan',      input: NaN,        errorCode: 'nan-or-inf' },
    { name: 'reject-infinity', input: Infinity,   errorCode: 'nan-or-inf' },
    { name: 'reject-neg-inf',  input: -Infinity,  errorCode: 'nan-or-inf' },
    { name: 'reject-float',    input: 1.5,        errorCode: 'float' },
    // NB: JS undefined has no cross-language equivalent (Swift Optional.none
    // bridges to NSNull and serializes as `null`). The TS reference still
    // throws on undefined, but we don't pin that behaviour in the corpus
    // because there's no portable way to construct the input from JSON.
  ];

  // Build the cycle case at vector-generation time but encode the INPUT as
  // a flag (we can't serialize a cyclic JS object to JSON for the vector
  // file). The runner reconstructs by interpreting the flag.
  const happyVectors: Vector[] = happy.map(({ name, description, input }) => ({
    name,
    ...(description ? { description } : {}),
    input: { json: input as never },
    expected: { hex: bytesToHex(canonicalize(input)) },
  }));

  const errorVectors: Vector[] = errors.map(({ name, description, input, errorCode }) => {
    let actualCode: string;
    try {
      canonicalize(input);
      throw new Error(`canonicalize was supposed to throw on ${name}`);
    } catch (e) {
      if (!(e instanceof CanonicalizeError)) throw e;
      actualCode = e.code;
    }
    if (actualCode !== errorCode) {
      throw new Error(`Mismatch for ${name}: expected code ${errorCode}, got ${actualCode}`);
    }
    return {
      name,
      ...(description ? { description } : {}),
      // Serializing NaN/Infinity/undefined: we encode them as a tag.
      input: encodeNonJsonable(input, name),
      expected: { error: errorCode },
    };
  });

  // Special-case error: cycle. Build via a runner-reconstructible spec.
  const cycleVector: Vector = {
    name: 'reject-cycle',
    description: 'Self-referential object — canonicalize throws CanonicalizeError with code "cycle".',
    input: { synthesize: 'cycle-self' },
    expected: { error: 'cycle' },
  };

  // Depth: a synthesized 33-level-nested object. Encode via "depth-n" spec.
  const depthVector: Vector = {
    name: 'reject-depth',
    description: '33 levels of object nesting — canonicalize throws CanonicalizeError with code "depth".',
    input: { synthesize: 'depth', levels: 33 },
    expected: { error: 'depth' },
  };

  // String-too-long: 64 KiB + 1 of single-byte UTF-8.
  const longStringVector: Vector = {
    name: 'reject-string-too-long',
    description: '65 537 single-byte UTF-8 characters — canonicalize throws CanonicalizeError with code "string-too-long".',
    input: { synthesize: 'long-string', utf8Bytes: 64 * 1024 + 1 },
    expected: { error: 'string-too-long' },
  };

  writeVectorFile('canonicalize.kat.json', {
    $schema: SCHEMA_URL,
    function: 'canonicalize',
    description: 'M0 strict-mode canonical JSON: NFC, sorted keys, integers only, depth ≤ 32, strings ≤ 64 KiB UTF-8.',
    vectors: [...happyVectors, ...errorVectors, cycleVector, depthVector, longStringVector],
  });
}

function encodeNonJsonable(input: unknown, name: string): { json?: unknown; nonJsonable?: string } {
  if (Number.isNaN(input as number)) return { nonJsonable: 'NaN' };
  if (input === Infinity) return { nonJsonable: 'Infinity' };
  if (input === -Infinity) return { nonJsonable: '-Infinity' };
  if (input === undefined) return { nonJsonable: 'undefined' };
  if (typeof input === 'number' && !Number.isInteger(input as number)) return { json: input as never };
  return { json: input as never };
}

// ─── leafHash + claimLeafHash ─────────────────────────────────────────
function genLeafHash(): void {
  type T = { name: string; description?: string; key: string; value: unknown };
  const claims: T[] = [
    { name: 'string-claim',      key: 'givenName',  value: 'Fatima' },
    { name: 'boolean-claim',     key: 'over18',     value: true },
    { name: 'integer-claim',     key: 'yearOfBirth', value: 1990 },
    { name: 'null-claim',        key: 'middleName', value: null },
    { name: 'nested-claim',      key: 'address',    value: { street: '1 Sample Rd', city: 'Abu Dhabi' } },
    { name: 'array-claim',       key: 'aliases',    value: ['Fati', 'Fa'] },
    { name: 'unicode-key',       description: 'Key is NFC-normalized before encoding.', key: 'café', value: 'value' },
  ];
  writeVectorFile('claim-leaf-hash.kat.json', {
    $schema: SCHEMA_URL,
    function: 'claimLeafHash',
    description: 'Convenience leaf-hash for (key:string, value:unknown) — exercises NFC + canonicalize + leafHash spec primitive.',
    vectors: claims.map(({ name, description, key, value }) => ({
      name,
      ...(description ? { description } : {}),
      input: { key, value },
      expected: { hex: bytesToHex(claimLeafHash(key, value)) },
    })),
  });

  // Spec primitive: leafHash(keyBytes, valueBytes). Independent of NFC +
  // canonicalize — pure byte function.
  type LH = { name: string; keyHex: string; valueHex: string };
  const primitives: LH[] = [
    { name: 'small-bytes', keyHex: '6b', valueHex: '76' /* 'k' and 'v' */ },
    { name: 'long-bytes',  keyHex: '00'.repeat(64), valueHex: 'ff'.repeat(64) },
    { name: 'empty-key',   keyHex: '',   valueHex: '42' },
    { name: 'empty-value', keyHex: '42', valueHex: '' },
  ];
  writeVectorFile('leaf-hash.kat.json', {
    $schema: SCHEMA_URL,
    function: 'leafHash',
    description: 'Spec primitive leafHash(keyBytes, valueBytes): rpo256(0x01 ‖ rpo256(keyBytes) ‖ rpo256(valueBytes)).',
    vectors: primitives.map(({ name, keyHex, valueHex }) => ({
      name,
      input: { keyHex, valueHex },
      expected: { hex: bytesToHex(leafHash(hexToBytes(keyHex), hexToBytes(valueHex))) },
    })),
  });
}

// ─── emptyLeafHash ────────────────────────────────────────────────────
function genEmptyLeaf(): void {
  const indices = [0, 1, 2, 7, 8, 15, 16, 31, 127, 1023];
  writeVectorFile('empty-leaf-hash.kat.json', {
    $schema: SCHEMA_URL,
    function: 'emptyLeafHash',
    description: 'Index-tagged empty-leaf hash: rpo256Tagged(0x00, u64BE(index)). Used to pad Merkle trees to power-of-2 size.',
    vectors: indices.map((index) => ({
      name: `index-${index}`,
      input: { index },
      expected: { hex: bytesToHex(emptyLeafHash(index)) },
    })),
  });
}

// ─── Merkle trees ─────────────────────────────────────────────────────
function genMerkle(): void {
  const trees: { name: string; entries: ReadonlyArray<readonly [string, unknown]> }[] = [
    { name: 'one-entry-padded-to-8',
      entries: [['only', 1]] },
    { name: 'two-entries-padded-to-8',
      entries: [['a', 1], ['b', 2]] },
    { name: 'five-entries-padded-to-8',
      entries: [
        ['givenName', 'Fatima'],
        ['familyName', 'Al-Farsi'],
        ['nationality', 'AE'],
        ['dateOfBirth', '1990-04-12'],
        ['over18', true],
      ] },
    { name: 'eight-entries-no-padding',
      entries: Array.from({ length: 8 }, (_, i) => [`k${i}`, i] as const) },
    { name: 'seventeen-entries-padded-to-32',
      entries: Array.from({ length: 17 }, (_, i) => [`k${i.toString().padStart(2, '0')}`, i] as const) },
  ];

  const vectors: Vector[] = trees.map(({ name, entries }) => {
    const tree = new MerkleTree(entries);
    const proofs = [];
    for (let i = 0; i < tree.paddedSize; i++) {
      proofs.push({
        index: i,
        sibling: tree.proof(i).map((e) => ({ siblingHex: bytesToHex(e.sibling), isRight: e.isRight })),
      });
    }
    return {
      name,
      input: { entries: entries.map(([k, v]) => ({ key: k, value: v })) },
      expected: {
        paddedSize: tree.paddedSize,
        depth: tree.depth,
        rootHex: tree.rootHex,
        proofs,
      },
    };
  });

  writeVectorFile('merkle.kat.json', {
    $schema: SCHEMA_URL,
    function: 'MerkleTree',
    description: 'Merkle tree root + inclusion proofs. Min 8 leaves, byte-level domain tags 0x01 (leaf), 0x02 (inner), 0x00 (empty).',
    vectors,
  });
}

// ─── deriveCid ────────────────────────────────────────────────────────
function genDeriveCid(): void {
  const cases: { name: string; description?: string; headerWithoutCid: Record<string, unknown>; iat: number }[] = [
    { name: 'minimal-header',
      headerWithoutCid: { iss: 'did:elabify:sepolia:issuer:test', sub: 'did:elabify:sepolia:holder:alice' },
      iat: 1735689600 /* 2025-01-01T00:00:00Z */ },
    { name: 'full-header',
      headerWithoutCid: {
        v: 2,
        iss: 'did:elabify:sepolia:issuer:examplecorp',
        sub: 'did:elabify:sepolia:holder:alice-demo',
        schema: 'elabify://schema/global/corporateOfficer/v1',
        root: '0x' + 'ab'.repeat(32),
        exp: 1893456000,
        kid: 'key-2026-01',
      },
      iat: 1768348800 /* 2026-01-14T00:00:00Z */ },
  ];
  writeVectorFile('derive-cid.kat.json', {
    $schema: SCHEMA_URL,
    function: 'deriveCid',
    description: 'Credential ID = rpo256(0x04 ‖ canonicalize({...header, cid:""}) ‖ u64BE(iat)). See wire-formats.md §4.3.',
    vectors: cases.map(({ name, description, headerWithoutCid, iat }) => ({
      name,
      ...(description ? { description } : {}),
      input: { headerWithoutCid, iat },
      expected: { hex: bytesToHex(deriveCid(headerWithoutCid, iat)) },
    })),
  });
}

// ─── hkdfSha256 ───────────────────────────────────────────────────────
function genHkdf(): void {
  // RFC 5869 test cases 1, 2, 3 + a few Elabify-shaped derivations.
  type V = { name: string; description?: string; ikmHex: string; saltHex: string; infoHex: string; length: number };
  const vectors: V[] = [
    { name: 'rfc5869-case-1',
      description: 'RFC 5869 Test Case 1 — basic SHA-256 derivation.',
      ikmHex:  '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      saltHex: '000102030405060708090a0b0c',
      infoHex: 'f0f1f2f3f4f5f6f7f8f9',
      length:  42 },
    { name: 'rfc5869-case-2',
      description: 'RFC 5869 Test Case 2 — longer IKM/salt/info, 82-byte OKM.',
      ikmHex:
        '000102030405060708090a0b0c0d0e0f' +
        '101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f' +
        '303132333435363738393a3b3c3d3e3f' +
        '404142434445464748494a4b4c4d4e4f',
      saltHex:
        '606162636465666768696a6b6c6d6e6f' +
        '707172737475767778797a7b7c7d7e7f' +
        '808182838485868788898a8b8c8d8e8f' +
        '909192939495969798999a9b9c9d9e9f' +
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      infoHex:
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
        'c0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
        'e0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      length: 82 },
    { name: 'rfc5869-case-3',
      description: 'RFC 5869 Test Case 3 — empty salt + info.',
      ikmHex: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
      saltHex: '',
      infoHex: '',
      length: 42 },
    { name: 'elabify-challenge-derivation',
      description: 'Verifier challenge derivation (32-byte challenge) — Elabify-shaped salt + info.',
      ikmHex: '5e'.repeat(32),
      saltHex: bytesToHex(utf8('elabify:challenge:salt:v1')),
      infoHex: bytesToHex(utf8('elabify:challenge:info:v1')),
      length: 32 },
  ];
  writeVectorFile('hkdf-sha256.kat.json', {
    $schema: SCHEMA_URL,
    function: 'hkdfSha256',
    description: 'RFC 5869 HKDF-SHA-256. Cases 1-3 are the RFC vectors; the Elabify case pins our challenge-derivation salt+info.',
    vectors: vectors.map(({ name, description, ikmHex, saltHex, infoHex, length }) => ({
      name,
      ...(description ? { description } : {}),
      input: { ikmHex, saltHex, infoHex, length },
      expected: { hex: bytesToHex(hkdfSha256(hexToBytes(ikmHex), hexToBytes(saltHex), hexToBytes(infoHex), length)) },
    })),
  });
}

// ─── DID round-trip + errors ──────────────────────────────────────────
function genDid(): void {
  const happy: { name: string; did: string }[] = [
    { name: 'issuer-registrar', did: 'did:elabify:adgm:issuer:bank-of-abu-dhabi' },
    { name: 'user-hex',         did: 'did:elabify:adgm:user:0x1a2b3c4d5e6f7890abcdef0123456789abcdef01' },
    { name: 'verifier-uniswap', did: 'did:elabify:eth:verifier:uniswap-v4-hook-0x1234' },
    { name: 'sepolia-issuer',   did: 'did:elabify:sepolia:issuer:dev' },
    { name: 'local-corporate',  did: 'did:elabify:local:issuer:corporate' },
  ];
  const happyVectors: Vector[] = happy.map(({ name, did }) => {
    const parsed = parseDID(did);
    const round = formatDID(parsed);
    if (round !== did) throw new Error(`Round-trip mismatch for ${did}: got ${round}`);
    return { name, input: { did }, expected: parsed };
  });

  type Err = { name: string; did: string; code: 'malformed' | 'extra-colons' | 'empty-component' };
  const errs: Err[] = [
    { name: 'too-few-colons',     did: 'did:elabify:adgm:issuer',                  code: 'malformed' },
    { name: 'extra-colons',       did: 'did:elabify:adgm:user:foo:bar',            code: 'extra-colons' },
    { name: 'wrong-scheme',       did: 'urn:elabify:adgm:issuer:dev',              code: 'malformed' },
    { name: 'wrong-method',       did: 'did:other:adgm:issuer:dev',                code: 'malformed' },
    { name: 'mixed-case-method',  did: 'DID:Elabify:adgm:issuer:dev',              code: 'malformed' },
    { name: 'empty-network',      did: 'did:elabify::issuer:dev',                  code: 'empty-component' },
    { name: 'empty-entity-type',  did: 'did:elabify:adgm::dev',                    code: 'empty-component' },
    { name: 'empty-identifier',   did: 'did:elabify:adgm:issuer:',                 code: 'empty-component' },
  ];
  const errVectors: Vector[] = errs.map(({ name, did, code }) => {
    try {
      parseDID(did);
      throw new Error(`parseDID was supposed to throw on ${name}`);
    } catch (e) {
      if (!(e instanceof DIDError)) throw e;
      if (e.code !== code) {
        throw new Error(`DIDError code mismatch for ${name}: expected ${code}, got ${e.code}`);
      }
    }
    return { name, input: { did }, expected: { error: code } };
  });

  writeVectorFile('did.kat.json', {
    $schema: SCHEMA_URL,
    function: 'parseDID',
    description: 'did:elabify parsing + round-trip per ADR-0021. Error codes pinned: malformed | extra-colons | empty-component.',
    vectors: [...happyVectors, ...errVectors],
  });
}

// ─── main ─────────────────────────────────────────────────────────────
function main(): void {
  console.log(`Generating KAT vectors → ${path.relative(process.cwd(), OUT_DIR)}/`);
  genRpo256();
  genRpo256Tagged();
  genCanonicalize();
  genLeafHash();
  genEmptyLeaf();
  genMerkle();
  genDeriveCid();
  genHkdf();
  genDid();
  console.log();
  for (const line of written) console.log(`  ${line}`);
  console.log(`\nTotal: ${totalVectors} vectors across ${written.length} files.`);
}

main();
