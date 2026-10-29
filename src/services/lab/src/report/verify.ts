// verify-report: a report file is accepted only if it parses, matches the frozen schema and PASS rules, and carries
// nothing that looks like token, voucher, key or address material outside the few fields that legitimately hold
// hexadecimal identifiers. The privacy scan is deliberately paranoid: it reads every string.
import { readFileSync, statSync } from 'node:fs';
import { validateReport } from '../../../../contracts/lib/index.ts';

const MAX_BYTES = 1024 * 1024;
const HEX64 = /(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])/;
const B64ISH = /[A-Za-z0-9_-]{43,}/;
const IPV4 = /(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/;
const IPV6 = /(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F]{0,4}/;
const PEM = /-----BEGIN [A-Z ]+-----/;
// Paths (array indexes normalised to *) allowed to hold a 64-hex identifier or a long opaque string.
const ALLOWED_HEX = new Set(['runs[*].config_digest', 'runs[*].token_key_id']);
const ALLOWED_DIGEST = /^software\.image_digests\[\*\]$/;
const ALLOWED_DOTTED = new Set(['environment.os', 'environment.docker_version', 'software.node_version']);

export type Verdict = { ok: boolean; status: string | null; problems: string[] };

function walk(value: unknown, path: string, out: string[]): void {
  if (typeof value === 'string') {
    const p = path.replace(/\[\d+\]/g, '[*]');
    const idLike = ALLOWED_HEX.has(p) || ALLOWED_DIGEST.test(p);
    if (HEX64.test(value) && !idLike) out.push(`${p}: 64-hex value`);
    if (B64ISH.test(value) && !idLike) out.push(`${p}: long opaque string`);
    if (IPV4.test(value) && !ALLOWED_DOTTED.has(p)) out.push(`${p}: address-like value`);
    if (IPV6.test(value)) out.push(`${p}: address-like value`);
    if (PEM.test(value)) out.push(`${p}: key material marker`);
  } else if (Array.isArray(value)) value.forEach((v, i) => walk(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) walk(v, path ? `${path}.${k}` : k, out);
}

export function privacyProblems(report: unknown): string[] {
  const out: string[] = [];
  walk(report, '', out);
  return out;
}

export function verifyReportText(text: string): Verdict {
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { return { ok: false, status: null, problems: ['not valid JSON'] }; }
  try { validateReport(doc); } catch (e) { return { ok: false, status: null, problems: [`schema or evidence rule failed: ${(e as Error).message}`] }; }
  const problems = privacyProblems(doc);
  return { ok: problems.length === 0, status: (doc as { overall_status: string }).overall_status, problems };
}

export function verifyReportFile(path: string): Verdict {
  try {
    if (statSync(path).size > MAX_BYTES) return { ok: false, status: null, problems: ['file larger than 1 MiB'] };
    return verifyReportText(readFileSync(path, 'utf8'));
  } catch { return { ok: false, status: null, problems: ['unreadable file'] }; }
}
