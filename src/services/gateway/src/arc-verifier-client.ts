import { createConnection, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ContractError } from '../../../contracts/lib/index.ts';
import { REGIONAL, arcRpcMacInput, arcSpendId, encodeRegionalFrame, regionalPolicyDigest,
  validateArcRequest, validateRegionalPolicy, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { authenticateArcResponse, regionalMac, validateArcBootstrap, validateRegionalPublicRequest, type ArcBootstrap } from '../../../contracts/lib/regional-wire.ts';

export type ArcVerification={kind:'verified';receipt:object}|{kind:'rejected'}|{kind:'busy'}|{kind:'unavailable'}|{kind:'canceled'};
export type RegionalClaimCandidate={kind:'regional-claim-candidate';spend_id:string;not_after_ms:number};

/** Verify-only private RPC client. Prepared configuration is trusted, never taken from an HTTP request. */
export class ArcVerifierClient {
  readonly #policy:RegionalPolicy;readonly #bootstrap:ArcBootstrap;
  readonly #endpoint:{host:string;port:number};readonly #key:Uint8Array;
  readonly #limit:number;readonly #onFault:()=>void;
  readonly #sockets=new Set<Socket>();readonly #receipts=new WeakMap<object,string>();
  #active=0;#closed=false;#drain:Promise<void>|null=null;#resolveDrain:(()=>void)|null=null;
  private constructor(p:RegionalPolicy,b:ArcBootstrap,endpoint:{host:string;port:number},key:Uint8Array,limit:number,onFault:()=>void){
    this.#policy=p;this.#bootstrap=b;this.#endpoint={...endpoint};this.#key=Uint8Array.from(key);this.#limit=limit;this.#onFault=onFault;
  }
  static prepare(policy:unknown,bootstrap:unknown,endpoint:{host:string;port:number},verifyKey:Uint8Array,
    maxConcurrent:1|2,onFault:()=>void):ArcVerifierClient{
    try{
      const p=validateRegionalPolicy(policy);
      if(p.profile!=='arc'||!p.arc_implementation_revision)throw Error();
      const b=validateArcBootstrap(bootstrap,{run_id:p.run_id,arc_implementation_revision:p.arc_implementation_revision});
      if(b.arc_key_id!==p.arc_key_id||!endpoint||typeof endpoint.host!=='string'||!/^[A-Za-z0-9.:-]{1,253}$/.test(endpoint.host)
        ||!Number.isInteger(endpoint.port)||endpoint.port<1||endpoint.port>65535
        ||!(verifyKey instanceof Uint8Array)||verifyKey.length!==32||![1,2].includes(maxConcurrent))throw Error();
      return new ArcVerifierClient(p,b,endpoint,verifyKey,maxConcurrent,onFault);
    }catch{throw new ContractError('arc-verifier-configuration');}
  }
  get status(){return Object.freeze({closed:this.#closed,active:this.#active});}
  get binding(){return Object.freeze({run_id:this.#policy.run_id,policy_digest:regionalPolicyDigest(this.#policy),service_incarnation:this.#bootstrap.service_incarnation});}
  #settled():void{if(this.#closed&&this.#active===0&&this.#sockets.size===0)this.#resolveDrain?.();}
  close():Promise<void>{
    if(!this.#drain){
      this.#drain=new Promise(resolve=>{this.#resolveDrain=resolve;});this.#closed=true;this.#key.fill(0);
      for(const socket of this.#sockets)socket.destroy();this.#settled();
    }
    return this.#drain;
  }
  #fault():void{
    if(this.#closed)return;void this.close();try{this.#onFault();}catch{/* closure precedes callback */}
  }
  #exchange(frame:Uint8Array,signal:AbortSignal|undefined,deadline:number):Promise<Uint8Array>{
    return new Promise((resolve,reject)=>{
      const socket=createConnection(this.#endpoint);this.#sockets.add(socket);
      let result:Uint8Array|undefined,failed=false,total=0;const chunks:Buffer[]=[];
      const stop=()=>{failed=true;socket.destroy();};
      const timer=setTimeout(stop,Math.max(1,deadline-performance.now()));
      const connectTimer=setTimeout(stop,Math.max(1,Math.min(REGIONAL.arc_rpc_connect_timeout_ms,deadline-performance.now())));
      const abort=()=>stop();signal?.addEventListener('abort',abort,{once:true});
      socket.on('error',stop);
      socket.once('connect',()=>{
        clearTimeout(connectTimer);
        if(this.#closed||signal?.aborted||performance.now()>=deadline){stop();return;}
        socket.write(frame);
      });
      socket.on('data',(chunk:Buffer)=>{
        if(failed||result)return;
        total+=chunk.length;
        if(total>REGIONAL.rpc_frame_max_bytes||this.#closed||performance.now()>=deadline){stop();return;}
        chunks.push(Buffer.from(chunk));
        const index=chunk.indexOf(10);
        if(index!==-1){
          if(index!==chunk.length-1){stop();return;}
          result=Uint8Array.from(Buffer.concat(chunks,total));socket.destroy();
        }
      });
      socket.once('end',()=>{if(!result)stop();});
      socket.once('close',()=>{
        clearTimeout(timer);clearTimeout(connectTimer);signal?.removeEventListener('abort',abort);this.#sockets.delete(socket);
        const accepted=!failed&&!!result&&!this.#closed&&!signal?.aborted&&performance.now()<deadline;
        if(accepted)resolve(result!);else reject(new ContractError('arc-verifier-unavailable'));
        this.#settled();
      });
      if(this.#closed||signal?.aborted)stop();
    });
  }
  async verify(presentation:Uint8Array,options:{signal?:AbortSignal;deadline_ms?:number}={}):Promise<ArcVerification>{
    if(this.#closed)return {kind:'unavailable'};
    if(options.signal?.aborted)return {kind:'canceled'};
    if(this.#active>=this.#limit)return {kind:'busy'};
    if(!(presentation instanceof Uint8Array)||presentation.length===0||presentation.length>REGIONAL.arc_blob_max_bytes)return {kind:'rejected'};
    const deadline=Math.min(performance.now()+REGIONAL.arc_rpc_timeout_ms,options.deadline_ms??Infinity);
    if(!Number.isFinite(deadline)||performance.now()>=deadline)return {kind:'canceled'};
    const request=validateArcRequest({contract_version:REGIONAL.contract_version,run_id:this.#policy.run_id,
      policy_digest:regionalPolicyDigest(this.#policy),request_id:randomBytes(16).toString('hex'),service_incarnation:this.#bootstrap.service_incarnation,
      operation:'verify',presentation_b64url:Buffer.from(presentation).toString('base64url')},this.#policy);
    const frame=encodeRegionalFrame(request,regionalMac(this.#key,arcRpcMacInput('request','verify',request)));
    this.#active++;
    try{
      const wire=await this.#exchange(frame,options.signal,deadline);
      if(this.#closed||options.signal?.aborted)return {kind:options.signal?.aborted?'canceled':'unavailable'};
      const reply=authenticateArcResponse(wire,request,this.#policy,this.#key);
      if(reply.status==='refused'){
        if(reply.code==='invalid-proof'||reply.code==='invalid-input'||reply.code==='window-closed')return {kind:'rejected'};
        this.#fault();return {kind:'unavailable'};
      }
      if(reply.status!=='verified'){this.#fault();return {kind:'unavailable'};}
      const receipt=Object.freeze({});this.#receipts.set(receipt,arcSpendId(this.#policy,reply.spend_tag_b64url));
      return {kind:'verified',receipt};
    }catch{
      if(options.signal?.aborted&&!this.#closed)return {kind:'canceled'};
      this.#fault();return {kind:'unavailable'};
    }finally{this.#active--;this.#settled();}
  }
  verifyRequest(body:Record<string,unknown>,_nowMs:number,options:{signal?:AbortSignal;deadline_ms?:number}={}):Promise<ArcVerification>{
    try{
      const value=validateRegionalPublicRequest('arc-redeem',body,this.#policy);
      return this.verify(Uint8Array.from(Buffer.from(value['presentation_b64url'] as string,'base64url')),options);
    }catch{return Promise.resolve({kind:'rejected'});}
  }
  /** Instance-owned, single-use receipt. Never accept a public tag or request field here. */
  consume(receipt:object):RegionalClaimCandidate|null{
    const id=this.#receipts.get(receipt);this.#receipts.delete(receipt);
    return !this.#closed&&id?{kind:'regional-claim-candidate',spend_id:id,not_after_ms:0}:null;
  }
}
