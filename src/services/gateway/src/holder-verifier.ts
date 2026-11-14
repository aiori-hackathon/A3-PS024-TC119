import { createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { ContractError, decodeBase64Url, encodeBase64Url, hex, sha256, validateManifest, type Manifest } from '../../../contracts/lib/index.ts';
import { REGIONAL, holderContextInput, holderKeyHash, holderNonceMacInput, holderProofInput, regionalPolicyDigest,
  requireRegionalWindow, validateHolderProof, validateRegionalPolicy, type HolderNonce, type RegionalPolicy } from '../../../contracts/lib/regional.ts';
import { checkRegionalMac, regionalMac, regionalType2Challenge, validateRegionalPublicRequest,
  validateRegionalPublicResponse } from '../../../contracts/lib/regional-wire.ts';
import { TokenVerifier } from './token-verifier.ts';
import type { ArcVerification, RegionalClaimCandidate } from './arc-verifier-client.ts';

/** Experimental holder-bound Type2 profile. No replay claim happens inside verification. */
export class HolderVerifier {
  readonly #m:Manifest;readonly #p:RegionalPolicy;readonly #contextKey:Uint8Array;readonly #nonceKey:Uint8Array;
  readonly #tokens:TokenVerifier;readonly #receipts=new WeakMap<object,RegionalClaimCandidate>();
  #closed=false;#active=0;#drain:Promise<void>|null=null;#resolve:(()=>void)|null=null;
  private constructor(m:Manifest,p:RegionalPolicy,context:Uint8Array,nonce:Uint8Array,tokens:TokenVerifier){
    this.#m=m;this.#p=p;this.#contextKey=context;this.#nonceKey=nonce;this.#tokens=tokens;
  }
  static async prepare(configuration:unknown,policy:unknown,contextKey:Uint8Array,nonceKey:Uint8Array):Promise<HolderVerifier>{
    let context:Uint8Array|undefined,nonce:Uint8Array|undefined;
    try{
      const m=validateManifest(structuredClone(configuration)),p=validateRegionalPolicy(policy,m);
      if(p.profile!=='type2-holder'||!(contextKey instanceof Uint8Array)||contextKey.length!==32
        ||!(nonceKey instanceof Uint8Array)||nonceKey.length!==32||timingSafeEqual(contextKey,nonceKey))throw Error();
      context=Uint8Array.from(contextKey);nonce=Uint8Array.from(nonceKey);
      const tokens=await TokenVerifier.prepare(m);return new HolderVerifier(m,p,context,nonce,tokens);
    }catch{context?.fill(0);nonce?.fill(0);throw new ContractError('holder-verifier-configuration');}
  }
  get status(){return Object.freeze({closed:this.#closed,active:this.#active});}
  get binding(){return Object.freeze({run_id:this.#p.run_id,policy_digest:regionalPolicyDigest(this.#p)});}
  #current(nowMs:number):void{if(this.#closed)throw new ContractError('holder-verifier-closed');requireRegionalWindow(this.#p,nowMs);}
  #context(spki:string):Uint8Array{
    return Uint8Array.from(Buffer.from(regionalMac(this.#contextKey,holderContextInput(this.#p,spki)),'hex'));
  }
  challenge(spki:string,nowMs:number):Record<string,unknown>{
    this.#current(nowMs);
    const result={contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(this.#p),
      challenge_b64url:encodeBase64Url(regionalType2Challenge(this.#context(spki)),false),
      token_key_spki_b64url:encodeBase64Url(decodeBase64Url(this.#m.token_key_spki_b64url,undefined,true),false)};
    validateRegionalPublicResponse('holder-challenge',result,this.#p);return result;
  }
  nonce(tokenHash:string,spki:string,nowMs:number):Record<string,unknown>{
    this.#current(nowMs);if(typeof tokenHash!=='string'||!/^[0-9a-f]{64}$/.test(tokenHash))throw new ContractError('holder-token-hash');
    const body:HolderNonce={contract_version:REGIONAL.contract_version,run_id:this.#p.run_id,policy_digest:regionalPolicyDigest(this.#p),
      token_hash:tokenHash,holder_key_hash:holderKeyHash(spki),issued_ms:nowMs,
      expires_ms:Math.min(nowMs+REGIONAL.nonce_lifetime_ms,this.#p.window_end_ms),random_b64url:randomBytes(32).toString('base64url')};
    const result={body,mac:regionalMac(this.#nonceKey,holderNonceMacInput(body))};
    validateRegionalPublicResponse('holder-nonce',result,this.#p);return result;
  }
  async verifyRequest(value:Record<string,unknown>,nowMs:number,options:{signal?:AbortSignal;deadline_ms?:number}={}):Promise<ArcVerification>{
    const stopped=()=>this.#closed||!!options.signal?.aborted||performance.now()>=(options.deadline_ms??Infinity);
    if(stopped())return {kind:this.#closed?'unavailable':'canceled'};
    if(this.#active>=this.#m.limits.gateway.active_flows_per_worker)return {kind:'busy'};
    this.#active++;let token:Uint8Array|undefined;
    try{
      this.#current(nowMs);
      const body=validateRegionalPublicRequest('holder-redeem',value,this.#p);
      token=decodeBase64Url(body['token_b64url'] as string,354,false);
      const proof=validateHolderProof(body['proof'],this.#p,token,nowMs);
      if(!checkRegionalMac(this.#nonceKey,holderNonceMacInput(proof.nonce.body),proof.nonce.mac))return {kind:'rejected'};
      const publicKey=createPublicKey({key:Buffer.from(proof.public_key_spki_b64url,'base64url'),format:'der',type:'spki'});
      if(!verify('sha256',holderProofInput(this.#p,token,proof.public_key_spki_b64url,proof.nonce,nowMs),
        {key:publicKey,dsaEncoding:'ieee-p1363'},Buffer.from(proof.signature_b64url,'base64url')))return {kind:'rejected'};
      if(stopped())return {kind:this.#closed?'unavailable':'canceled'};
      const signature=await this.#tokens.verifySignature(token);
      if(stopped())return {kind:this.#closed?'unavailable':'canceled'};
      if(signature.kind==='rejected')return {kind:signature.reason==='authorization-unavailable'?'unavailable':'rejected'};
      const result=this.#tokens.consumeSignatureContext(signature.receipt,sha256(regionalType2Challenge(this.#context(proof.public_key_spki_b64url))));
      if(result.kind==='rejected')return {kind:result.reason==='authorization-unavailable'?'unavailable':'rejected'};
      if(result.token_hash!==hex(sha256(token))||result.token_hash!==proof.nonce.body.token_hash)return {kind:'rejected'};
      const receipt=Object.freeze({});this.#receipts.set(receipt,{kind:'regional-claim-candidate',spend_id:result.spend_id,not_after_ms:proof.nonce.body.expires_ms});
      return {kind:'verified',receipt};
    }catch{return {kind:this.#closed?'unavailable':'rejected'};}
    finally{token?.fill(0);this.#active--;if(this.#closed&&this.#active===0)this.#resolve?.();}
  }
  consume(receipt:object):RegionalClaimCandidate|null{
    const candidate=this.#receipts.get(receipt);this.#receipts.delete(receipt);
    return !this.#closed&&candidate?{...candidate}:null;
  }
  close():Promise<void>{
    if(!this.#drain){this.#drain=new Promise(resolve=>{this.#resolve=resolve;});this.#closed=true;this.#contextKey.fill(0);this.#nonceKey.fill(0);
      if(this.#active===0)this.#resolve?.();}
    return this.#drain;
  }
}
