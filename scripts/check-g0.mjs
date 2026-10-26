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
const lab=fileURLToPath(new URL('../src/services/lab/',import.meta.url));
run(['node_modules/typescript/bin/tsc','--noEmit'],gateway);
run(['--test','test/contracts.test.ts','test/crypto.test.ts','test/token-verifier.test.ts','test/http-auth.test.ts'],gateway);
run(['scripts/build.mjs'],gateway);
run(['--test','test/token-verifier-bundle.test.ts'],gateway);
run(['dist/bootstrap.mjs'],gateway);
run(['node_modules/typescript/bin/tsc','--noEmit'],lab);
run(['--test','test/fixture.test.ts','test/crypto.test.ts','test/controller-contract.test.ts'],lab);
run(['scripts/build.mjs'],lab);
run(['--test','test/bundle.test.ts'],lab);
function metadata(cwd) {
  const r=spawnSync(process.execPath,['dist/bootstrap.mjs'],{cwd,encoding:'utf8',shell:false,timeout:60000});
  if(r.error||r.status!==0)throw Error('Bootstrap metadata check failed');
  return JSON.parse(r.stdout);
}
const gatewayMetadata=metadata(gateway),labMetadata=metadata(lab);
if(gatewayMetadata.contract_version!==labMetadata.contract_version||gatewayMetadata.profiles_digest!==labMetadata.profiles_digest||labMetadata.verified!==true) {
  throw Error('Consumers disagree on contract/profile metadata or crypto verification');
}
console.log('PASS: both G0 consumers, independent fixture derivation, crypto interoperability, bundles and profile agreement. Runtime service/security integration remains G1 onward.');
