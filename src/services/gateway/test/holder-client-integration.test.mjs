// Separate native consumer gate: requires Mihir's integrated client/issuer implementation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { Redis } from 'ioredis';
import { configurationDigest, encodeBase64Url, makeManifest, PROTOCOL, voucherDigest } from '../../../contracts/lib/index.ts';
import { REGIONAL, validateRegionalPolicy } from '../../../contracts/lib/regional.ts';
import { initializeStore, loadReplayScripts, parseRedisTime, REPLAY_SCRIPTS } from '../../../contracts/lib/replay.ts';
import { initializeRegionalStore, regionalGatewayAclArguments } from '../../../contracts/lib/regional-replay.ts';
import { prepareRegionalGateway } from '../src/regional-gateway.ts';
import { WorkerLease } from '../src/worker-lease.ts';
import { LabIssuer } from '../../lab/src/protocol.ts';
import { RegionalAdmission } from '../../lab/src/issuer/regional.ts';
import { VoucherStore } from '../../lab/src/issuer/vouchers.ts';
import { IssuanceService } from '../../lab/src/issuer/issuance.ts';
import { createIssuerServer } from '../../lab/src/issuer/server.ts';
import { RegionalClient } from '../../lab/src/client/regional.ts';
import { ClientVouchers } from '../../lab/src/client/vouchers.ts';
import { createPki } from '../../lab/src/pki.ts';
import { listen } from '../../lab/test/helpers/https.ts';
import { startProxy } from '../../lab/test/helpers/stubs.ts';

test('actual holder client enrolls through the issuer and consumes canonical gateway responses before real Redis claims', { timeout: 20000 }, async t=>{
  const admin=new Redis({host:'127.0.0.1',port:6379,lazyConnect:true,enableReadyCheck:false,disableClientInfo:true,retryStrategy:()=>null});
  admin.on('error',()=>{});await admin.connect();t.after(()=>admin.disconnect(false));
  const signer=await LabIssuer.generate(PROTOCOL.issuer_name),start=parseRedisTime(await admin.time())-1000;
  const manifest=makeManifest({run_id:randomBytes(16).toString('hex'),run_start_ms:start,inventory_total:5,
    token_key_spki_b64url:encodeBase64Url(signer.publicKeySpki),snapshot_script_sha1:REPLAY_SCRIPTS.snapshot.sha1,claim_script_sha1:REPLAY_SCRIPTS.claim.sha1});
  const policy=validateRegionalPolicy({contract_version:REGIONAL.contract_version,schema_version:1,run_id:manifest.run_id,
    baseline_config_digest:configurationDigest(manifest),profile:'type2-holder',window_start_ms:start,window_end_ms:start+REGIONAL.window_ms,
    quota:5,admitted_entitlements:5,resource_id:REGIONAL.resource_id,method:REGIONAL.method,url:REGIONAL.url,
    type2_key_id:manifest.token_key_id,arc_key_id:null,arc_implementation_revision:null,arc_tag_encoding:null},manifest);
  const io={call:(command,...args)=>admin.call(command,...args)};
  await loadReplayScripts(io);await initializeStore(io,manifest);await initializeRegionalStore(io,manifest,policy);
  const password=randomBytes(32).toString('hex');await io.call('ACL',...regionalGatewayAclArguments('tfr_consumer',password));
  const pki=createPki(),voucher=randomBytes(32),vouchers=new VoucherStore(5);
  vouchers.provision({batch_id:'a'.repeat(32),batch_index:0,expected_total:1,final_batch:true,items:[voucherDigest(voucher)]});vouchers.lock();
  const admission=new RegionalAdmission({policy,signer,vouchers});admission.setOpen(true);t.after(()=>admission.setOpen(false));
  const baseline=new IssuanceService(signer,vouchers,manifest.limits.issuer);
  const issuer=createIssuerServer(baseline,signer.publicKeySpki,pki.leaf(PROTOCOL.issuer_name),admission),issuerPort=await listen(issuer);
  t.after(()=>{issuer.closeAllConnections();issuer.close();});
  let arrivals=0;
  const origin=createServer((req,res)=>{
    arrivals++;assert.equal(req.headers['x-tokenforge-run'],manifest.run_id);assert.equal(req.url,'/resource');
    res.writeHead(200,{'content-length':'8'}).end('research');
  });await new Promise(resolve=>origin.listen(8080,'127.0.0.1',resolve));
  t.after(()=>{origin.closeAllConnections();origin.close();});
  const ids={worker_incarnation:'1'.repeat(32),supervisor_incarnation:'2'.repeat(32)},lease=WorkerLease.prepare(manifest,ids,()=>{});
  const gateway=await prepareRegionalGateway(manifest,policy,lease,{redis:{host:'127.0.0.1',port:6379,username:'tfr_consumer',password},
    tls:pki.leaf(PROTOCOL.origin_name),auth:{profile:'type2-holder',context_key:randomBytes(32),nonce_key:randomBytes(32)}});
  let sequence=0;const grant=()=>{const now=process.hrtime.bigint();return {version:1,run_id:manifest.run_id,config_digest:configurationDigest(manifest),...ids,
    sequence,issued_at_ns:String(now),expires_at_ns:String(now+3000000000n)};};
  assert.ok(lease.enable(grant()));const heartbeat=setInterval(()=>{sequence++;lease.heartbeat(grant());},500);
  t.after(async()=>{clearInterval(heartbeat);await gateway.gateway.close();});
  const port=(await gateway.gateway.listen('127.0.0.1',0)).port;
  const proxy=await startProxy({'issuer.lab.test:443':issuerPort,'origin.lab.test:443':port});t.after(()=>proxy.server.close());
  const inventory=new ClientVouchers(1);
  inventory.provision({batch_id:'b'.repeat(32),batch_index:0,expected_total:1,final_batch:true,items:[voucher.toString('base64url')]});inventory.lock();
  const client=new RegionalClient({manifest,policy,vouchers:inventory,proxy:{host:'127.0.0.1',port:proxy.port},caPem:pki.caPem});
  t.after(async()=>{client.close();await client.drain();});
  await client.acquire();assert.equal(client.issuedCredentials,5);assert.equal(admission.reservedEntitlements,1);assert.equal(arrivals,0);
  assert.equal((await client.attack()).status,403);assert.equal(arrivals,0);assert.equal(await admin.dbsize(),3);
  const owner=await client.access();assert.equal(owner.status,200);assert.equal(Buffer.from(owner.resource_b64url,'base64url').toString(),'research');assert.equal(arrivals,1);
  assert.equal((await client.copyAccess()).status,403);assert.equal(arrivals,1);
  const race=await client.race(20);assert.equal(race.filter(r=>r.status===200).length,1);assert.equal(arrivals,2);
  for(let i=0;i<3;i++)assert.equal((await client.access()).status,200);
  assert.equal(arrivals,5);assert.equal(gateway.coordinator.counters.claims_successful,5);
  await assert.rejects(client.access(),/no-token/);await assert.rejects(client.acquire(),/already-attempted/);
});
