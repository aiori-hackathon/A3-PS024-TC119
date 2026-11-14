import { Histogram } from '../../../contracts/lib/measurements.ts';
import { performance } from 'node:perf_hooks';
import { ContractError, configurationDigest, encodeBase64Url, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { REGIONAL, regionalContext, regionalPolicyDigest, validateRegionalPolicy, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { regionalType2Challenge, decodeRegionalPublicRequest, type RegionalPublicRoute } from '../../../contracts/lib/regional-wire.ts';
import { FlowAdmission, type FlowPermit } from './flow-admission.ts';
import { parseAuthorization, copyRawHeaders } from './http-auth.ts';
import type { RegionalReplayStore } from './regional-replay-store.ts';
import type { WorkerLease } from './worker-lease.ts';
import type { FixedOrigin } from './fixed-origin.ts';
import type { ArcVerification, RegionalClaimCandidate } from './arc-verifier-client.ts';
import type { RequestView, ResponseSink, CoordinatorResponse } from './request-coordinator.ts';

export interface RegionalProofVerifier {
  readonly binding:Readonly<{run_id:string;policy_digest:string}>;
  readonly status:Readonly<{closed:boolean}>;
  verifyRequest(body:Record<string,unknown>,nowMs:number,options:{signal?:AbortSignal;deadline_ms?:number}):Promise<ArcVerification>;
  consume(receipt:object):RegionalClaimCandidate|null;
  close():Promise<void>;
  challenge?(spki:string,nowMs:number):Record<string,unknown>;
  nonce?(tokenHash:string,spki:string,nowMs:number):Record<string,unknown>;
}
type Replay=Pick<RegionalReplayStore,'binding'|'status'|'signal'|'snapshot'|'claim'|'close'>;
type Origin=Pick<FixedOrigin,'binding'|'status'|'forwardAfterClaim'|'close'>;
const json=(status:number,value:unknown)=>{
  const body=JSON.stringify(value);
  return {status,headers:{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff','content-length':String(Buffer.byteLength(body))},body};
};
const failure=(status:number)=>json(status,{error:status===403?'authorization-refused':status===503?'authorization-unavailable':'request-malformed'});

/** Shared regional authorization pipeline. Transport parsing and controller activation are separate boundaries. */
export class RegionalCoordinator {
  readonly requestBodyLimit=REGIONAL.rpc_frame_max_bytes;
  readonly #m:Manifest;readonly #p:RegionalPolicy;readonly #lease:WorkerLease;readonly #replay:Replay;readonly #origin:Origin;
  readonly #verifier:RegionalProofVerifier;readonly #admission:FlowAdmission;
  readonly #onReplay:()=>void;
  readonly #started=performance.now();readonly #verification=new Histogram();readonly #authorization=new Histogram();
  readonly #counters={claims_successful:0,replays_rejected:0,requests_rejected:0,queue_rejected:0,transport_failures:0};
  get counters(){return {...this.#counters};}
  get measurements(){const elapsed=performance.now()-this.#started;return [this.#verification.summary('verification_ms',elapsed),this.#authorization.summary('authorization_ms',elapsed)];}
  #closed=false;#drain:Promise<void>|null=null;#verificationAttempts=0;
  private constructor(m:Manifest,p:RegionalPolicy,lease:WorkerLease,replay:Replay,origin:Origin,verifier:RegionalProofVerifier){
    this.#m=m;this.#p=p;this.#lease=lease;this.#replay=replay;this.#origin=origin;this.#verifier=verifier;
    this.#admission=FlowAdmission.prepare(m,lease);
    this.#onReplay=()=>{lease.requestClose(replay.status.fault??'dependency-lost');void this.close();};
    replay.signal.addEventListener('abort',this.#onReplay,{once:true});
  }
  static prepare(configuration:unknown,policy:unknown,lease:WorkerLease,replay:Replay,origin:Origin,verifier:RegionalProofVerifier):RegionalCoordinator{
    try{
      const m=validateManifest(structuredClone(configuration)),p=validateRegionalPolicy(policy,m),digest=configurationDigest(m),pd=regionalPolicyDigest(p);
      if(lease.status.state!=='PREPARED'||lease.status.run_id!==m.run_id||lease.status.config_digest!==digest
        ||replay.binding.run_id!==m.run_id||replay.binding.policy_digest!==pd||replay.binding.profile!==p.profile
        ||replay.status.state!=='ready'||replay.signal.aborted||origin.binding.run_id!==m.run_id||origin.binding.config_digest!==digest||origin.status.closed
        ||verifier.binding.run_id!==m.run_id||verifier.binding.policy_digest!==pd||verifier.status.closed
        ||(p.profile==='type2-holder'&&(!verifier.challenge||!verifier.nonce)))throw Error();
      const coordinator=new RegionalCoordinator(m,p,lease,replay,origin,verifier);
      if(!lease.markReady()){void coordinator.close();throw Error();}return coordinator;
    }catch{throw new ContractError('regional-coordinator-configuration');}
  }
  get binding(){return Object.freeze({run_id:this.#m.run_id,config_digest:configurationDigest(this.#m)});}
  get verificationAttempts(){return this.#verificationAttempts;}
  get status(){return this.#admission.status;}
  #fault():void{this.#lease.requestClose('unsafe-state');void this.close();}
  #route(view:RequestView,fields:string[]|null):RegionalPublicRoute|'resource'|null{
    if(['ip','type2-bearer'].includes(this.#p.profile)){
      if(!fields||view.method!=='GET'||view.target!=='/resource'||view.hasBody||(view.body?.length??0)!==0)return null;
      const values=(name:string)=>fields.filter((_,i)=>i%2===0&&fields[i]!.toLowerCase()===name).length;
      const hosts=fields.filter((_,i)=>i%2===1&&fields[i-1]!.toLowerCase()==='host');
      if(hosts.length!==1||![this.#m.origin_name,`${this.#m.origin_name}:443`].includes(hosts[0]!.toLowerCase())
        ||['transfer-encoding','expect','upgrade'].some(k=>values(k)>0)||values('content-length')>1
        ||fields.some((value,i)=>i%2===1&&fields[i-1]!.toLowerCase()==='connection'&&value.split(',').some(p=>p.trim().toLowerCase()==='upgrade'))
        ||(this.#p.profile==='ip'&&values('authorization')>0))return null;
      return 'resource';
    }
    if(!fields||view.method!=='POST'||!(view.body instanceof Uint8Array)||!view.body.length||view.body.length>this.requestBodyLimit)return null;
    const headers=new Map<string,string[]>();
    for(let i=0;i<fields.length;i+=2){const k=fields[i]!.toLowerCase();headers.set(k,[...(headers.get(k)??[]),fields[i+1]!]);}
    const host=headers.get('host'),ct=headers.get('content-type'),cl=headers.get('content-length');
    if(host?.length!==1||![this.#m.origin_name,`${this.#m.origin_name}:443`].includes(host[0]!.toLowerCase())
      ||ct?.length!==1||ct[0]!=='application/json'||cl?.length!==1||cl[0]!==String(view.body.length)
      ||['authorization','transfer-encoding','expect','upgrade'].some(k=>headers.has(k))
      ||headers.get('connection')?.some(v=>v.split(',').some(part=>part.trim().toLowerCase()==='upgrade')))return null;
    const routes:Record<string,RegionalPublicRoute>=this.#p.profile==='arc'?{'/regional/arc/redeem':'arc-redeem'}:
      {'/regional/holder/challenge':'holder-challenge','/regional/holder/nonce':'holder-nonce','/regional/holder/redeem':'holder-redeem'};
    return Object.hasOwn(routes,view.target)?routes[view.target]!:null;
  }
  async handle(view:RequestView,deliver:ResponseSink):Promise<void>{
    const started=performance.now(),signal=view.signal,check=view.checkActive,remaining=view.remainingMs;
    const owned=view.body instanceof Uint8Array&&view.body.length<=this.requestBodyLimit?Uint8Array.from(view.body):undefined;
    const fields=copyRawHeaders(view.rawHeaders),remoteAddress=view.remoteAddress;
    const request:RequestView={...view,rawHeaders:fields,...(owned?{body:owned}:{})};
    const route=this.#route(request,fields);
    const live=()=>!this.#closed&&!signal.aborted&&performance.now()<started+this.#m.limits.gateway.request_timeout_ms
      &&(check?check():true)&&this.#lease.checkActive();
    let permit:FlowPermit|null=null,sent=false,authorized=false;
    const send=async(response:CoordinatorResponse)=>{
      if(sent||signal.aborted)return;
      if(response.status===200&&(!permit||!permit.checkActive()))return;
      if(response.status>=400)this.#counters.requests_rejected++;
      sent=true;await deliver(response,permit?.signal??signal);
    };
    try{
      if(!live())return;
      const admitted=await this.#admission.acquire(signal);
      if(admitted.kind==='canceled')return;
      if(admitted.kind==='rejected'){this.#counters.queue_rejected++;await send(failure(503));return;}
      const raw=admitted.permit;
      permit=Object.freeze({signal:raw.signal,release:()=>raw.release(),checkActive:()=>live()&&raw.checkActive()});
      if(!permit.checkActive())return;
      if(!route||(route!=='resource'&&!owned)){await send(failure(400));return;}
      let body:Record<string,unknown>;
      try{
        if(route==='resource')body=this.#p.profile==='ip'?{remote_address:remoteAddress}:{};
        else body=decodeRegionalPublicRequest(route,owned!,this.#p);
      }catch{await send(failure(400));return;}
      const first=await this.#replay.snapshot();if(!permit.checkActive())return;
      if(first.kind!=='snapshot'){if(first.kind==='unavailable')this.#fault();await send(failure(first.kind==='rejected'?403:503));return;}
      const bearerRefusal=()=>{const response=json(401,{error:'authorization-refused'});return {...response,headers:{...response.headers,'www-authenticate':`PrivateToken challenge="${encodeBase64Url(regionalType2Challenge(regionalContext(this.#p)),false)}", token-key="${this.#m.token_key_spki_b64url}"`}};};
      if(this.#p.profile==='type2-bearer'){
        const auth=parseAuthorization(fields);
        if(auth.kind!=='token'){await send(auth.kind==='rejected'?failure(400):bearerRefusal());return;}
        body={token_b64url:encodeBase64Url(auth.wire,false)};auth.wire.fill(0);
      }
      if(route==='holder-challenge'||route==='holder-nonce'){
        try{
          const spki=body['public_key_spki_b64url'] as string;
          const output=route==='holder-challenge'?this.#verifier.challenge!(spki,first.now_ms):this.#verifier.nonce!(body['token_hash'] as string,spki,first.now_ms);
          if(permit.checkActive())await send(json(200,output));
        }catch{this.#fault();await send(failure(503));}return;
      }
      if(this.#verificationAttempts===Number.MAX_SAFE_INTEGER){this.#fault();return;}this.#verificationAttempts++;
      const remainingMs=remaining?remaining():this.#m.limits.gateway.request_timeout_ms-(performance.now()-started);
      if(!Number.isFinite(remainingMs)||remainingMs<=0)return;
      const verificationStart=performance.now();
      const result=await this.#verifier.verifyRequest(body,first.now_ms,{signal:permit.signal,deadline_ms:performance.now()+remainingMs});
      if(result.kind==='verified')this.#verification.add(performance.now()-verificationStart);else this.#verification.fail();
      if(!permit.checkActive())return;
      if(result.kind!=='verified'){
        if(result.kind==='unavailable')this.#fault();
        if(result.kind!=='canceled')await send(result.kind==='rejected'&&this.#p.profile==='type2-bearer'?bearerRefusal():failure(result.kind==='rejected'?403:503));return;
      }
      const fresh=await this.#replay.snapshot();if(!permit.checkActive())return;
      if(fresh.kind!=='snapshot'){if(fresh.kind==='unavailable')this.#fault();await send(failure(fresh.kind==='rejected'?403:503));return;}
      const candidate=this.#verifier.consume(result.receipt);
      if(!candidate){this.#fault();return;}
      const claim=await this.#replay.claim(candidate);
      // Confirmed consumption is counted even if delivery/deadline is lost immediately afterward.
      if(claim.kind==='claimed')this.#counters.claims_successful++;
      if(claim.kind==='unavailable')this.#counters.transport_failures++;
      if(claim.kind==='rejected'&&claim.reason==='already-spent')this.#counters.replays_rejected++;
      if(!permit.checkActive())return;
      if(claim.kind!=='claimed'){if(claim.kind==='unavailable')this.#fault();await send(failure(claim.kind==='rejected'?(claim.reason==='limit-reached'?429:403):503));return;}
      authorized=true;this.#authorization.add(performance.now()-started);
      const response=await this.#origin.forwardAfterClaim(permit);if(!permit.checkActive())return;
      if(response.kind==='response'||response.kind==='upstream-error')await send(response);
      else if(response.kind!=='canceled'){if(response.kind==='unavailable')this.#fault();await send(failure(503));}
    }catch{
      // A response write failure may be partial; never produce a second response or refund a spend.
      if(!sent){this.#fault();try{await send(failure(503));}catch{/* terminal partial delivery */}}
    }finally{if(!authorized)this.#authorization.fail();fields?.fill('');owned?.fill(0);permit?.release();}
  }
  close():Promise<void>{
    if(!this.#drain){
      let done!:()=>void,failed!:(error:Error)=>void;
      this.#drain=new Promise((resolve,reject)=>{done=resolve;failed=reject;});this.#drain.catch(()=>{});this.#closed=true;
      this.#replay.signal.removeEventListener('abort',this.#onReplay);
      const work:Promise<unknown>[]=[];let error=false;
      try{this.#lease.fence();}catch{error=true;}
      try{this.#replay.close();}catch{error=true;}
      for(const close of [()=>this.#verifier.close(),()=>this.#origin.close(),()=>this.#admission.close()]){
        try{work.push(Promise.resolve(close()));}catch{error=true;}
      }
      Promise.allSettled(work).then(results=>{if(error||results.some(r=>r.status==='rejected'))failed(new ContractError('regional-coordinator-close'));else done();});
    }
    return this.#drain;
  }
}
