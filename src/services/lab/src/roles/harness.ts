// One-shot security harness, run INSIDE a client container by the controller (`docker exec -i ... node dist/harness.mjs`).
// It exists for scenarios whose credentials must cross processes (theft, reset) or be created before a real fault. Input is
// one JSON object on stdin, output one JSON object on stdout; it has no listener, writes no file and logs nothing.
// Tokens it prints go to the controller's private pipe only. This is the documented quarantined-fixture exception: there is
// no EXPORT_TOKEN control command, and the ordinary client role never reveals a token.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PROTOCOL, decodeBase64Url, encodeBase64Url, validateManifest } from '../../../../contracts/lib/index.ts';
import { LabClient } from '../client/client.ts';
import { ClientVouchers } from '../client/vouchers.ts';

const MAX_INPUT = 1024 * 1024;
const chunks: Buffer[] = []; let total = 0;
for await (const c of process.stdin) { total += (c as Buffer).length; if (total > MAX_INPUT) { process.stdout.write('{"error":"harness-failed"}\n'); process.exit(1); } chunks.push(c as Buffer); }

async function main(): Promise<unknown> {
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { op: string; manifest: unknown; vouchers?: string[]; tokens?: string[] };
  const manifest = validateManifest(input.manifest);
  const proxy = new URL(manifest.endpoints.proxy_http);
  const vouchers = new ClientVouchers(manifest.limits.client.inventory_max);
  if (input.op === 'issue') {
    const list = input.vouchers ?? [];
    if (list.length < 1 || list.length > PROTOCOL.provision_batch_max) throw new Error('bad-input');
    vouchers.provision({ batch_id: 'f'.repeat(32), batch_index: 0, expected_total: list.length, final_batch: true, items: list });
    vouchers.lock();
  }
  const caPem = readFileSync(join(process.env['PS024_SECRETS_DIR'] ?? '/run/secrets', 'ca.crt'), 'utf8');
  const client = new LabClient({ manifest, proxy: { host: proxy.hostname, port: Number(proxy.port) }, caPem, vouchers });
  try {
    if (input.op === 'issue') {
      const parsed = await client.fetchChallenge();
      const tokens: string[] = [];
      for (let i = 0; i < (input.vouchers ?? []).length; i++) tokens.push(encodeBase64Url(await client.issueWire(parsed.challenge)));
      return { tokens };
    }
    if (input.op === 'present') {
      const results: { status: number; label: string | null }[] = [];
      for (const t of input.tokens ?? []) {
        const r = await client.redeemWire(decodeBase64Url(t, PROTOCOL.token_bytes)).catch(() => ({ status: 0, label: null as string | null }));
        results.push({ status: r.status, label: r.label });
      }
      return { results };
    }
    throw new Error('bad-op');
  } finally { client.close(); }
}
try { process.stdout.write(JSON.stringify(await main()) + '\n'); process.exit(0); }
catch { process.stdout.write('{"error":"harness-failed"}\n'); process.exit(1); }
