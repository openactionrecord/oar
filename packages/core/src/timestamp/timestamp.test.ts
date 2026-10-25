import { describe, expect, it } from 'vitest';
import { anchorDigest, verifyTimestampToken } from './timestamp.js';
import { createTestTsa } from '../testing/tsa.js';
import { TSA_ROOTS } from './tsa-roots.js';

const CP = { count: 4, head_digest: `sha256:${'ab'.repeat(32)}`, at: '2026-10-18T14:00:00.000Z', sealer_kid: 'k', sig: 'cd'.repeat(64) };
const AT = new Date('2026-10-18T14:10:00Z');

function flip(token: string, index: number): string {
  const bytes = Buffer.from(token, 'base64');
  bytes[index] = bytes[index]! ^ 0x01;
  return bytes.toString('base64');
}

describe.each(['RSA', 'ECDSA'] as const)('RFC 3161 timestamp tokens (%s)', (algorithm) => {
  it('verifies a token over the checkpoint digest', async () => {
    const tsa = await createTestTsa({ algorithm });
    const token = await tsa.issue(anchorDigest(CP), AT, 12345n);
    expect(verifyTimestampToken(token, anchorDigest(CP), tsa.roots)).toEqual({ ok: true, genTime: AT.toISOString(), tsa: tsa.name, root: 'OAR Test TSA Root' });
  });

  it('refuses a token for another checkpoint, an untrusted root, or a changed byte', async () => {
    const tsa = await createTestTsa({ algorithm });
    const token = await tsa.issue(anchorDigest(CP), AT);
    expect(verifyTimestampToken(token, anchorDigest({ ...CP, count: 5 }), tsa.roots)).toMatchObject({ ok: false, reason: 'The timestamp is for a different checkpoint.' });
    expect(verifyTimestampToken(token, anchorDigest(CP), TSA_ROOTS)).toMatchObject({ ok: false, reason: "The authority's certificate does not chain to a recognised root." });
    expect(verifyTimestampToken(token, anchorDigest(CP), (await createTestTsa({ algorithm })).roots)).toMatchObject({ ok: false });
    // Change one byte in the genTime area of the TSTInfo and in the signature at the end.
    const bytes = Buffer.from(token, 'base64');
    const timeAt = bytes.indexOf(Buffer.from('20261018141000Z'));
    expect(verifyTimestampToken(flip(token, timeAt + 3), anchorDigest(CP), tsa.roots)).toMatchObject({ ok: false });
    expect(verifyTimestampToken(flip(token, bytes.length - 3), anchorDigest(CP), tsa.roots)).toMatchObject({ ok: false });
    expect(verifyTimestampToken('not a token', anchorDigest(CP), tsa.roots)).toMatchObject({ ok: false });
  });
});

describe('anchor digest', () => {
  it('covers the sealer signature', () => {
    expect(anchorDigest(CP)).toMatch(/^[0-9a-f]{64}$/);
    expect(anchorDigest({ ...CP, sig: 'ef'.repeat(64) })).not.toBe(anchorDigest(CP));
  });
});
