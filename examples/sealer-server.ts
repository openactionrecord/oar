// A separate sealing service over HTTP, and a recorder that uses it. Run the service with its own key, on
// infrastructure the issuer cannot change, and records become "sealed": the issuer can no longer rewrite them alone.
// Run: npx tsx examples/sealer-server.ts
import { createServer, type Server } from 'node:http';
import {
  createLocalSealer,
  createRecorder,
  generateSigningKey,
  verifyBundle,
  type Jwks,
  type Seal,
  type SealingService,
  type SignedCheckpoint,
} from '@openactionrecord/core';

/** The service: POST /v1/seal { digest } → seal; GET /.well-known/aar-keys.json; GET /v1/checkpoints. */
export function startSealer(port = 0): Promise<{ server: Server; url: string }> {
  // In production: load the key from a secret, persist the log and checkpoints, and anchor checkpoints with
  // sealer.anchor() every few minutes for an outside timestamp.
  const sealer = createLocalSealer({ key: generateSigningKey('sealer-2026') });
  const server = createServer(async (req, res) => {
    const send = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    };
    if (req.method === 'GET' && req.url === '/.well-known/aar-keys.json') return send(200, sealer.keys());
    if (req.method === 'GET' && req.url === '/v1/checkpoints') return send(200, { checkpoints: sealer.checkpoints() });
    if (req.method === 'POST' && req.url === '/v1/seal') {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const { digest } = JSON.parse(raw) as { digest?: string };
      if (!digest || !/^sha256:[0-9a-f]{64}$/.test(digest)) return send(400, { error: 'expected { "digest": "sha256:<hex>" }' });
      return send(200, sealer.seal(digest));
    }
    send(404, { error: 'not found' });
  });
  return new Promise((resolve) => server.listen(port, () => {
    const address = server.address();
    resolve({ server, url: `http://127.0.0.1:${typeof address === 'object' && address ? address.port : port}` });
  }));
}

/** The client side: a SealingService backed by the HTTP service. */
export function remoteSealer(url: string): SealingService {
  const json = async <T>(path: string, init?: RequestInit) => {
    const res = await fetch(`${url}${path}`, init);
    if (!res.ok) throw new Error(`Sealing service answered ${res.status}`);
    return (await res.json()) as T;
  };
  return {
    seal: (digest) => json<Seal>('/v1/seal', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ digest }) }),
    keys: () => json<Jwks>('/.well-known/aar-keys.json'),
    checkpoints: async () => (await json<{ checkpoints: SignedCheckpoint[] }>('/v1/checkpoints')).checkpoints,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { server, url } = await startSealer();
  const oar = createRecorder({ issuer: generateSigningKey('my-agent-2026'), org: 'acme', agent: 'ops-bot', sealer: remoteSealer(url) });
  await oar.run({ type: 'db.delete', target: 'postgres', params: { table: 'sessions', olderThanDays: 30 }, execute: () => ({ deleted: 1204 }) });
  const report = verifyBundle(await oar.bundle());
  console.log(`${report.messages[0]} (sealing service at ${url})`);
  server.close();
}
