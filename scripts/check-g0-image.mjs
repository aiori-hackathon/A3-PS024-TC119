import {spawnSync} from 'node:child_process';
const image=process.argv[2]??'tokenforge-g0:local';
function docker(args,input) {
  const r=spawnSync('docker',args,{input,encoding:'utf8',shell:false,timeout:120000,maxBuffer:1024*1024});
  if(r.error||r.status!==0)throw Error('Docker G0 check failed: '+(r.stderr||r.error?.message||'nonzero exit'));
  return r.stdout.trim();
}
const config=JSON.parse(docker(['image','inspect',image]))[0].Config;
if(config.User!=='node'||config.ExposedPorts)throw Error('Image user/port boundary failed');
const restrictions=['--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--memory','128m','--pids-limit','64'];
const smoke=JSON.parse(docker(['run',...restrictions,image]));
if(smoke.node_major!==24||smoke.contract_version!=='TF-PS024-1.0.0')throw Error('Bootstrap mismatch');
const script=`
import {readdirSync,readFileSync,existsSync} from 'node:fs';
import {publicVerif,TokenChallenge} from '@cloudflare/privacypass-ts';
if(readdirSync('/app').some(p=>!['dist','node_modules'].includes(p)))throw Error('Unexpected app payload');
if(JSON.stringify(readdirSync('/app/dist'))!==JSON.stringify(['bootstrap.mjs']))throw Error('Unexpected build payload');
for(const p of ['typescript','esbuild','ajv'])if(existsSync('/app/node_modules/'+p))throw Error('Dev tool in runtime');
if(JSON.parse(readFileSync('/app/node_modules/sjcl/package.json','utf8')).version!=='1.0.9')throw Error('Patch missing');
const {BlindRSAMode,Client,Issuer,Origin,getPublicKeyBytes}=publicVerif;
const mode=BlindRSAMode.PSS;
const keys=await Issuer.generateKey(mode,{modulusLength:2048,publicExponent:Uint8Array.of(1,0,1)});
const client=new Client(mode);
const request=await client.createTokenRequest(new TokenChallenge(2,'issuer.lab.test',new Uint8Array(32),['origin.lab.test']),await getPublicKeyBytes(keys.publicKey));
const response=await new Issuer(mode,'issuer.lab.test',keys.privateKey,keys.publicKey).issue(request);
const token=await client.finalize(response);
const verified=await new Origin(mode).verify(token,keys.publicKey);
if(!verified||request.serialize().length!==259||response.serialize().length!==256||token.serialize().length!==354)throw Error('Linux crypto mismatch');
console.log(JSON.stringify({platform:process.platform,node:process.versions.node,request_bytes:259,response_bytes:256,token_bytes:354,verified,runtime_payload:'production-only'}));
`;
console.log(docker(['run',...restrictions,'-i',image,'node','--input-type=module','-'],script));
console.log('PASS: non-root/no-network/read-only G0 image, minimal app payload and fresh Linux blind-issuance roundtrip.');
