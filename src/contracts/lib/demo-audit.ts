import { appendFileSync, existsSync, statSync } from 'node:fs';

export const DEMO_AUDIT_MARKER = '/run/ps024/demo-audit-enabled';
export const DEMO_AUDIT_PATH = '/run/ps024/demo-audit.jsonl';
export const DEMO_AUDIT_MAX_BYTES = 262144;
const services = ['issuer', 'gateway', 'origin'] as const;
const events = ['issuance_granted', 'issuance_refused', 'identity_verified', 'proof_verified', 'proof_refused',
  'claim_accepted', 'claim_refused', 'origin_forward_started', 'response_sent',
  'resource_received', 'resource_served', 'resource_refused'] as const;
type Service = typeof services[number];
type Event = typeof events[number];
type Fields = { run_id: string; profile?: string; status?: number; count?: number; reason?: string };
export type DemoAuditRow = Fields & { schema: 'tf-demo-audit-1'; at: string; pid: number; service: Service; event: Event };

/** Strict allowlist: raw input, credentials, addresses and arbitrary error messages have no field. */
export function validateDemoAuditRow(value: unknown): value is DemoAuditRow {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  if (Object.keys(r).some(k => !['schema','at','pid','service','event','run_id','profile','status','count','reason'].includes(k))) return false;
  return r.schema === 'tf-demo-audit-1' && typeof r.at === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.at)
    && Number.isFinite(Date.parse(r.at)) && Number.isSafeInteger(r.pid) && (r.pid as number) > 0
    && services.includes(r.service as Service) && events.includes(r.event as Event)
    && typeof r.run_id === 'string' && /^[0-9a-f]{32}$/.test(r.run_id)
    && (r.profile === undefined || ['ip','type2-bearer','arc','type2-holder'].includes(r.profile as string))
    && (r.reason === undefined || ['limit-reached','already-spent','nonce-expired','window-closed'].includes(r.reason as string))
    && (r.status === undefined || Number.isInteger(r.status) && (r.status as number) >= 100 && (r.status as number) <= 599)
    && (r.count === undefined || Number.isSafeInteger(r.count) && (r.count as number) >= 0 && (r.count as number) <= 65535);
}
export function formatDemoAudit(service: Service, event: Event, fields: Fields, at = new Date().toISOString(), pid = process.pid): string | null {
  const row = { ...fields, schema: 'tf-demo-audit-1' as const, at, pid, service, event };
  return validateDemoAuditRow(row) ? JSON.stringify(row) + '\n' : null;
}

/** Diagnostics only: opt-in marker, bounded tmpfs file, and no effect on authorization if writing fails. */
export function demoAudit(service: Service, event: Event, fields: Fields): void {
  try {
    if (!existsSync(DEMO_AUDIT_MARKER)) return;
    const line = formatDemoAudit(service, event, fields);
    if (!line || Buffer.byteLength(line) > 1024) return;
    const size = existsSync(DEMO_AUDIT_PATH) ? statSync(DEMO_AUDIT_PATH).size : 0;
    if (size + Buffer.byteLength(line) > DEMO_AUDIT_MAX_BYTES) return;
    appendFileSync(DEMO_AUDIT_PATH, line, { encoding: 'utf8', mode: 0o600 });
  } catch { /* An unavailable/full diagnostic sink must not change a claim or refund a use. */ }
}

export function parseDemoAudit(text: string, tail = 20): DemoAuditRow[] {
  if (Buffer.byteLength(text) > DEMO_AUDIT_MAX_BYTES + 4096 || !Number.isInteger(tail) || tail < 1 || tail > 100) throw Error('audit-unavailable');
  const lines = text.split('\n').filter(Boolean);
  const rows: DemoAuditRow[] = [];
  for (const line of lines) {
    if (Buffer.byteLength(line) > 1024) throw Error('audit-unavailable');
    let row: unknown;
    try { row = JSON.parse(line); } catch { throw Error('audit-unavailable'); }
    if (!validateDemoAuditRow(row)) throw Error('audit-unavailable');
    rows.push(row);
  }
  return rows.slice(-tail);
}
