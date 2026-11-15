import { join } from 'node:path';
import { DEMO_AUDIT_PATH, parseDemoAudit, type DemoAuditRow } from '../../../../contracts/lib/demo-audit.ts';
import { DockerProject, realDocker, type DockerCli } from './docker.ts';

/** Fixed read-only services/path; no arbitrary Docker command or container selector. */
export async function readDemoLogs(root: string, service: string, tail = 20, docker: DockerCli = realDocker): Promise<DemoAuditRow[]> {
  if (!['issuer','gateway','origin'].includes(service) || !Number.isInteger(tail) || tail < 1 || tail > 100) throw Error('audit-options-invalid');
  const project = new DockerProject(docker, join(root,'infra','compose.yaml'));
  const instance = await project.instance(service as 'issuer'|'gateway'|'origin');
  const result = await docker.run(['exec','-i',instance.container_id,'node','--input-type=module','-'], {
    input: `import{readFileSync}from'node:fs';process.stdout.write(readFileSync(${JSON.stringify(DEMO_AUDIT_PATH)},'utf8'));\n`, timeoutMs:10000,
  });
  if (result.status !== 0 || result.failed || result.timedOut) throw Error('audit-unavailable');
  const rows = parseDemoAudit(result.stdout,tail);
  if (rows.some(row => row.service !== service)) throw Error('audit-unavailable');
  return rows;
}
