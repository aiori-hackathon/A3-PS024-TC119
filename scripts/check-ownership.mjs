import {spawnSync} from 'node:child_process';
const args=process.argv.slice(2);
const option=(name,fallback)=>{const i=args.indexOf(name);return i<0?fallback:args[i+1];};
const owner=option('--owner',null);
if(!['krish','mihir'].includes(owner))throw Error('Pass --owner krish or --owner mihir');
const base=option('--base','origin/main');
const git=(args)=>{
  const r=spawnSync('git',args,{encoding:'utf8',shell:false});
  if(r.status!==0)throw Error('Git diff inventory failed');return r.stdout.split('\0').filter(Boolean);
};
const files=new Set([...git(['diff','--name-only','-z',`${base}...HEAD`]),...git(['diff','--name-only','-z','HEAD']),...git(['ls-files','--others','--exclude-standard','-z'])]);
const krishRoots=new Set(['AGENTS.md','README.md','IMPLEMENTATION_PLAN.md','IMPLEMENTATION_REVIEW.md','KRISH_AGENT_HANDOFF.md','MIHIR_AGENT_HANDOFF.md','PS-024.pdf','.gitignore','.dockerignore','.editorconfig','.gitattributes','.node-version','.npmrc','package.json']);
const prefix=(path,roots)=>roots.some(root=>path.startsWith(root));
const allowed=(path)=>owner==='krish'
  ? krishRoots.has(path)||prefix(path,['.github/','config/','scripts/','src/contracts/','src/services/gateway/','src/security/','docs/implementation/','docs/security/'])
  : prefix(path,['src/services/lab/','infra/','docs/lab/','docs/demo/','docs/submission/']);
const bad=[...files].filter(path=>!allowed(path));
if(bad.length){console.error('Ownership violation:',bad.join(', '));process.exit(1);}
const sensitive=[...files].filter(p=>/(^|\/)(node_modules|\.runtime|artifacts|dist|coverage)(\/|$)|\.(pem|key|p12|pfx|heapsnapshot)$|(^|\/)\.env($|\.)/.test(p));
if(sensitive.length){console.error('Forbidden tracked/runtime paths:',sensitive.join(', '));process.exit(1);}
console.log(`PASS: ${files.size} changed/untracked paths are owned by ${owner}; no forbidden runtime paths.`);
