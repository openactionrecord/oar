import canonicalize from 'canonicalize';

const encoder = new TextEncoder();

/** RFC 8785 canonical JSON. Throws on values JSON cannot represent (undefined, functions, NaN, Infinity). */
export function canonicalJson(value: unknown): string {
  assertJsonSafe(value, '$');
  const out = canonicalize(value);
  if (out === undefined) throw new TypeError('Value cannot be canonicalized');
  return out;
}

export function canonicalBytes(value: unknown): Uint8Array {
  return encoder.encode(canonicalJson(value));
}

function assertJsonSafe(value: unknown, path: string): void {
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new TypeError(`${path}: non-finite number cannot be canonicalized`);
  }
  if (value === undefined || typeof value === 'function' || typeof value === 'symbol' || typeof value === 'bigint') {
    throw new TypeError(`${path}: ${typeof value} cannot be canonicalized`);
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertJsonSafe(item, `${path}[${i}]`));
  } else if (value !== null && typeof value === 'object' && typeof (value as { toJSON?: unknown }).toJSON !== 'function') {
    for (const [key, item] of Object.entries(value)) {
      // Optional fields left undefined are dropped, matching JSON.stringify.
      if (item !== undefined) assertJsonSafe(item, `${path}.${key}`);
    }
  }
}
