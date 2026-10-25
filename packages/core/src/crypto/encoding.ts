export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

export function hexToBytes(hex: string, expectedLength?: number): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) throw new TypeError('Invalid hex string');
  const bytes = new Uint8Array(Buffer.from(hex, 'hex'));
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new TypeError(`Expected ${expectedLength} bytes, got ${bytes.length}`);
  }
  return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

export function base64UrlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw new TypeError('Invalid base64url string');
  return new Uint8Array(Buffer.from(value, 'base64url'));
}
