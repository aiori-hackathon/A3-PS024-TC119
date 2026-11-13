import { performance } from 'node:perf_hooks';
import { ContractError, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { regionalPolicyDigest, validateRegionalPolicy, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { parseRegionalClaim, parseRegionalSnapshot, regionalClaimCommand, regionalReplayIdentity,
  regionalSnapshotCommand, verifyRegionalStoreReady } from '../../../contracts/lib/regional-replay.ts';
import type { ReplayConnection, ReplayFault } from './replay-store.ts';

const unavailable=Object.freeze({kind:'unavailable'} as const),busy=Object.freeze({kind:'busy'} as const);
type Unavailable=typeof unavailable|typeof busy;
export type RegionalReplayClaim=Unavailable|{kind:'claimed';expiry_ms:number}|
  {kind:'rejected';reason:'window-closed'|'nonce-expired'|'already-spent'};
export type RegionalReplaySnapshot=Unavailable|{kind:'snapshot';now_ms:number}|{kind:'rejected';reason:'window-closed'};
type Slot={connection:ReplayConnection;busy:boolean};

/** Bounded transport for trusted, cryptographically verified spend candidates.
 * This component does not verify ARC/holder proofs and is not connected to HTTP yet.
 * A successful claim still needs current lease/deadline checks before origin send.
 */
export class RegionalReplayStore {
  readonly #manifest:Manifest;
  readonly #policy:RegionalPolicy;
  readonly #slots:Slot[];
  readonly #onFault:(reason:ReplayFault)=>void;
  readonly #abort=new AbortController();
  #state:'preparing'|'ready'|'closed'='preparing';
  #fault:ReplayFault|null=null;

  private constructor(m:Manifest,p:RegionalPolicy,connections:ReplayConnection[],onFault:(reason:ReplayFault)=>void){
    this.#manifest=m;this.#policy=p;this.#slots=connections.map(connection=>({connection,busy:false}));this.#onFault=onFault;
    for(const {connection} of this.#slots)connection.onLoss(()=>this.#fail('dependency-lost'));
  }
  static async prepare(configuration:unknown,policy:unknown,connections:ReplayConnection[],onFault:(reason:ReplayFault)=>void):Promise<RegionalReplayStore>{
    let m:Manifest,p:RegionalPolicy;
    try{
      m=validateManifest(structuredClone(configuration));p=validateRegionalPolicy(policy,m);
      regionalReplayIdentity(m,p);
      if(connections.length!==m.limits.gateway.redis_connections_per_worker||new Set(connections).size!==connections.length)throw Error();
    }catch{
      for(const c of connections){try{c.close();}catch{/* close all supplied connections */}}
      throw new ContractError('regional-replay-configuration');
    }
    let store:RegionalReplayStore|undefined;
    try{
      store=new RegionalReplayStore(m,p,connections,onFault);const prepared=store;
      await Promise.all(prepared.#slots.map(async slot=>{
        await prepared.#bounded(()=>slot.connection.connect(),m.limits.gateway.redis_connect_timeout_ms);
        await verifyRegionalStoreReady({call:(command,...args)=>prepared.#read(slot,command,...args)},m,p);
      }));
      if(prepared.#state==='closed')throw Error();
      prepared.#state='ready';return prepared;
    }catch{
      if(store)store.#fail('unsafe-state');
      for(const c of connections){try{c.close();}catch{/* no connection survives failed readiness */}}
      throw new ContractError('regional-replay-preparation');
    }
  }
  get status(){return Object.freeze({state:this.#state,fault:this.#fault});}
  get signal(){return this.#abort.signal;}
  get binding(){return Object.freeze({run_id:this.#policy.run_id,policy_digest:regionalPolicyDigest(this.#policy),profile:this.#policy.profile});}
  close():void{
    if(this.#state==='closed')return;
    this.#state='closed';
    for(const {connection} of this.#slots){try{connection.close();}catch{/* close remaining connections too */}}
    this.#abort.abort();
  }
  #fail(reason:ReplayFault):void{
    if(this.#state==='closed')return;
    this.#fault=reason;this.close();
    try{this.#onFault(reason);}catch{/* closure precedes notification */}
  }
  async #bounded<T>(work:()=>Promise<T>,ms:number):Promise<T>{
    if(this.#state==='closed')throw new ContractError('regional-replay-unavailable');
    const end=performance.now()+ms;let timer:ReturnType<typeof setTimeout>|undefined;
    try{
      const timeout=new Promise<never>((_,reject)=>{timer=setTimeout(()=>{
        this.#fail('dependency-lost');reject(new ContractError('regional-replay-timeout'));
      },ms);});
      const value=await Promise.race([work(),timeout]);
      if(performance.now()>=end||this.status.state==='closed')throw Error();
      return value;
    }catch{
      this.#fail('dependency-lost');throw new ContractError('regional-replay-unavailable');
    }finally{clearTimeout(timer);}
  }
  #read(slot:Slot,command:string,...args:(string|number)[]):Promise<unknown>{
    return this.#bounded(()=>slot.connection.call(command,...args),this.#manifest.limits.gateway.redis_command_timeout_ms);
  }
  async #run<T>(work:(slot:Slot)=>Promise<T>):Promise<T|Unavailable>{
    if(this.#state!=='ready')return unavailable;
    const slot=this.#slots.find(s=>!s.busy);if(!slot)return busy;
    slot.busy=true;
    try{const result=await work(slot);return this.#state==='ready'?result:unavailable;}
    catch{this.#fail('unsafe-state');return unavailable;}
    finally{slot.busy=false;}
  }
  snapshot():Promise<RegionalReplaySnapshot>{
    return this.#run(async slot=>{
      const [command,...args]=regionalSnapshotCommand(this.#manifest,this.#policy);
      const reply=parseRegionalSnapshot(await this.#read(slot,command as string,...args),this.#manifest,this.#policy);
      if(reply.tag==='REGIONAL_SNAPSHOT')return {kind:'snapshot',now_ms:reply.now_ms} as const;
      if(reply.tag==='WINDOW_CLOSED')return {kind:'rejected',reason:'window-closed'} as const;
      this.#fail(reply.tag==='CLOCK_UNSAFE'?'clock-unsafe':'unsafe-state');return unavailable;
    });
  }
  claim(candidate:unknown):Promise<RegionalReplayClaim>{
    let command:(string|number)[];
    try{
      if(!candidate||typeof candidate!=='object'||Array.isArray(candidate))throw Error();
      const c=candidate as Record<string,unknown>;
      if(Object.keys(c).length!==3||c['kind']!=='regional-claim-candidate'||typeof c['spend_id']!=='string'
        ||typeof c['not_after_ms']!=='number')throw Error();
      // Own immutable primitives before any await. This shape is an internal contract, not proof of verification.
      command=regionalClaimCommand(this.#manifest,this.#policy,c['spend_id'],c['not_after_ms']);
    }catch{this.#fail('unsafe-state');return Promise.resolve(unavailable);}
    return this.#run(async slot=>{
      const reply=parseRegionalClaim(await this.#read(slot,command[0] as string,...command.slice(1)),this.#manifest,this.#policy);
      switch(reply.tag){
        case 'CLAIMED':return {kind:'claimed',expiry_ms:reply.expiry_ms} as const;
        case 'WINDOW_CLOSED':return {kind:'rejected',reason:'window-closed'} as const;
        case 'NONCE_EXPIRED':return {kind:'rejected',reason:'nonce-expired'} as const;
        case 'ALREADY_SPENT':return {kind:'rejected',reason:'already-spent'} as const;
        default:this.#fail(reply.tag==='CLOCK_UNSAFE'?'clock-unsafe':'unsafe-state');return unavailable;
      }
    });
  }
}
