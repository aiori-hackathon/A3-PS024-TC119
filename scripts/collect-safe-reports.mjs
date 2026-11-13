// CI artifacts contain only fixed report paths that pass both schema/evidence and privacy validation.
import { existsSync, mkdirSync, copyFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
mkdirSync('sanitized-reports',{recursive:true});
for(const name of ['demo-report.json','security-report.json','benchmark-smoke.json']) {
  const file=`artifacts/${name}`;
  if(!existsSync(file))continue;
  const r=spawnSync(process.execPath,['src/services/lab/src/controller/cli.ts','verify-report','--file',file],{stdio:'inherit',shell:false,timeout:20_000});
  if(r.status===0)copyFileSync(file,`sanitized-reports/${name}`);
}
