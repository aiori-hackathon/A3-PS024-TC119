import test from 'node:test';
import assert from 'node:assert/strict';
import { formatDemoAudit, parseDemoAudit, DEMO_AUDIT_PATH, DEMO_AUDIT_MAX_BYTES } from '../../../contracts/lib/demo-audit.ts';
import { readDemoLogs } from '../src/controller/demo-logs.ts';
import type { DockerCli } from '../src/controller/docker.ts';

const fields = {run_id:'a'.repeat(32),profile:'arc',count:1};
const line = () => formatDemoAudit('gateway','claim_accepted',fields,'2026-11-15T00:00:00.000Z',42)!;

test('audit accepts only fixed event fields and excludes raw credentials, addresses and errors', () => {
  assert.equal(parseDemoAudit(line())[0]!.event,'claim_accepted');
  for (const key of ['token','private_key','authorization','voucher','nonce','address','message']) {
    assert.equal(formatDemoAudit('gateway','claim_accepted',Object.assign({...fields},{[key]:'must-not-appear'})),null);
  }
  for (const change of [{run_id:'unsafe'}, {profile:'unknown'}, {count:-1}, {count:1.5}, {status:999}, {reason:'raw error text'}]) {
    assert.equal(formatDemoAudit('gateway','claim_accepted',{...fields,...change}),null);
  }
});

test('audit reader refuses malformed, oversized and unsafe records before exposing any data', () => {
  assert.equal(parseDemoAudit(line().repeat(5),2).length,2);
  for (const text of ['not json\n',JSON.stringify({...JSON.parse(line()),token:'must-not-appear'})+'\n','x'.repeat(DEMO_AUDIT_MAX_BYTES+4097)]) {
    assert.throws(()=>parseDemoAudit(text),{message:'audit-unavailable'});
  }
  for (const tail of [0,101,1.5]) assert.throws(()=>parseDemoAudit(line(),tail));
});

test('read-only logs command targets a fixed service and file and prints no unvalidated output', async () => {
  const calls:{args:string[];input:string|undefined}[]=[];
  let output=line();
  const id='b'.repeat(64);
  const docker: DockerCli = { spawn:()=>{throw Error('unused');}, run:async(args,options)=>{
    calls.push({args,input:options?.input});
    return {stdout:args[0]==='exec'?output:id,stderr:'',status:0,timedOut:false,failed:false};
  }};
  assert.equal((await readDemoLogs('D:/test','gateway',1,docker)).length,1);
  const read=calls.find(c=>c.args[0]==='exec')!;
  assert.deepEqual(read.args,['exec','-i',id,'node','--input-type=module','-']);
  assert.ok(read.input!.includes(DEMO_AUDIT_PATH));
  const before=calls.length;
  await assert.rejects(readDemoLogs('D:/test','../../other',1,docker));
  assert.equal(calls.length,before);
  output=JSON.stringify({...JSON.parse(line()),authorization:'must-not-appear'})+'\n';
  await assert.rejects(readDemoLogs('D:/test','gateway',1,docker),{message:'audit-unavailable'});
});
