// Narrow accidental-credential check, not a comprehensive secret-detection claim.
import {spawnSync} from 'node:child_process';
import {readFileSync,existsSync} from 'node:fs';
const r=spawnSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{encoding:'utf8',shell:false});
if(r.status!==0)throw Error('Cannot inventory tracked files');
let checked=0;
for(const path of new Set(r.stdout.split('\0').filter(Boolean))) {
  if(/(^|\/)(node_modules|\.runtime|artifacts|dist|coverage)(\/|$)|\.(pem|key|p12|pfx|heapsnapshot)$|(^|\/)\.env($|\.)/.test(path))throw Error('Forbidden runtime/credential path: '+path);
  if(!existsSync(path)||! /\.(md|json|ts|mjs|py|yml)$/.test(path))continue;
  const text=readFileSync(path,'utf8');checked++;
  if(/-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/.test(text)||/\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})\b/.test(text))throw Error('Potential private credential in '+path);
}
console.log(`PASS: ${checked} text files checked for selected private-key/token signatures; no credential values printed.`);
