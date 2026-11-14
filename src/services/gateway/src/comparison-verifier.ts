import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { ContractError, decodeBase64Url, sha256, validateManifest } from '../../../contracts/lib/index.ts';
import { regionalContext, regionalPolicyDigest, requireRegionalWindow, validateRegionalPolicy, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { regionalType2Challenge } from '../../../contracts/lib/regional-wire.ts';
import { TokenVerifier } from './token-verifier.ts';
import type { ArcVerification, RegionalClaimCandidate } from './arc-verifier-client.ts';

/** Comparison profiles share the coordinator and atomic claim path, never a fallback. */
export class ComparisonVerifier{
  readonly #p:RegionalPolicy;readonly #tokens:TokenVerifier|null;readonly #key:Uint8Array|null;
  readonly #receipts=new WeakMap<object,RegionalClaimCandidate>();#closed=false;
  private constructor(p:RegionalPolicy,tokens:TokenVerifier|null,key:Uint8Array|null){this.#p=p;this.#tokens=tokens;this.#key=key;}
  static async prepare(configuration:unknown,policy:unknown,sourceKey?:Uint8Array){
    const m=validateManifest(structuredClone(configuration)),p=validateRegionalPolicy(policy,m);
    if(!['ip','type2-bearer'].includes(p.profile)||(p.profile==='ip'&&(!(sourceKey instanceof Uint8Array)||sourceKey.length!==32)))
      throw new ContractError('comparison-configuration');
    const key=p.profile==='ip'?Uint8Array.from(sourceKey!):null;
    try{return new ComparisonVerifier(p,p.profile==='type2-bearer'?await TokenVerifier.prepare(m):null,key);}
    catch{key?.fill(0);throw new ContractError('comparison-preparation');}
  }
  get binding(){return {run_id:this.#p.run_id,policy_digest:regionalPolicyDigest(this.#p)};}
  get status(){return {closed:this.#closed};}
  async verifyRequest(body:Record<string,unknown>,now:number,options:{signal?:AbortSignal;deadline_ms?:number}={}):Promise<ArcVerification>{
    const stopped=()=>this.#closed||options.signal?.aborted||performance.now()>=(options.deadline_ms??Infinity);
    if(stopped())return {kind:this.#closed?'unavailable':'canceled'};
    try{
      requireRegionalWindow(this.#p,now);let spend:string;
      if(this.#p.profile==='ip'){
        const raw=body['remote_address'];if(typeof raw!=='string')return {kind:'rejected'};let address:string=raw;
        if(address.startsWith('::ffff:')&&isIP(address.slice(7))===4)address=address.slice(7);
        if(!isIP(address)||address.includes('%'))return {kind:'rejected'};
        spend=createHmac('sha256',this.#key!).update('TF-IP-BUDGET-1\0').update(regionalPolicyDigest(this.#p)).update('\0').update(address).digest('hex');
      }else{
        if(typeof body['token_b64url']!=='string')return {kind:'rejected'};
        const token=decodeBase64Url(body['token_b64url'],354,false);
        const signature=await this.#tokens!.verifySignature(token);token.fill(0);
        if(stopped())return {kind:this.#closed?'unavailable':'canceled'};
        if(signature.kind==='rejected')return {kind:signature.reason==='authorization-unavailable'?'unavailable':'rejected'};
        const context=this.#tokens!.consumeSignatureContext(signature.receipt,sha256(regionalType2Challenge(regionalContext(this.#p))));
        if(context.kind==='rejected')return {kind:context.reason==='authorization-unavailable'?'unavailable':'rejected'};
        spend=context.spend_id;
      }
      const receipt=Object.freeze({});this.#receipts.set(receipt,{kind:'regional-claim-candidate',spend_id:spend,not_after_ms:0});
      return {kind:'verified',receipt};
    }catch{return {kind:'rejected'};}
  }
  consume(receipt:object){const c=this.#receipts.get(receipt);this.#receipts.delete(receipt);return this.#closed?null:c??null;}
  async close(){this.#closed=true;this.#key?.fill(0);}
}
