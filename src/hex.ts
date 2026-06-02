// Hex encoding / decoding helpers. Lowercase hex without `0x` prefix is the
// internal representation; consumers that want `0x`-prefixed strings prepend at
// the boundary. Matches the demo's bytesToHex / hexToBytes (lines 964-965).

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i] as number).toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  let h = hex;
  if (h.startsWith('0x') || h.startsWith('0X')) h = h.slice(2);
  if (h.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex string (${h.length} chars)`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(h.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`hexToBytes: invalid hex at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
