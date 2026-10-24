import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
if(Number(process.versions.node.split('.')[0])!==24)throw Error('G0 requires Node 24');
function run(args,cwd=root) {
  const r=spawnSync(process.execPath,args,{cwd,stdio:'inherit',shell:false});
  if(r.error)throw r.error;
  if(r.status!==0)process.exit(r.status??1);
}
run(['scripts/generate-contract-schemas.mjs','--check']);
const gateway=fileURLToPath(new URL('../src/services/gateway/',import.meta.url));
run(['node_modules/typescript/bin/tsc','--noEmit'],gateway);
run(['--test','test/contracts.test.ts','test/crypto.test.ts'],gateway);
run(['scripts/build.mjs'],gateway);
run(['dist/bootstrap.mjs'],gateway);
console.log('PASS: Krish G0 candidate checks. G0 is NOT closed: Mihir consumer/review and full integration remain pending.');
