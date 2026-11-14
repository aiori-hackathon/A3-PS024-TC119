// Real crypto fixtures. Private material is generated in memory and never printed or written to disk.
import { generateKeyPairSync, sign } from 'node:crypto';
import { publicVerif, TokenChallenge } from '@cloudflare/privacypass-ts';
import { configurationDigest, encodeBase64Url, hex, makeManifest, sha256, type Manifest } from '../../../../contracts/lib/index.ts';
import { REPLAY_SCRIPTS } from '../../../../contracts/lib/replay.ts';
import { REGIONAL, holderProofInput, regionalPolicyDigest, validateRegionalPolicy, type HolderNonce, type RegionalPolicy } from '../../../../contracts/lib/regional.ts';
import { HolderVerifier } from '../../src/holder-verifier.ts';

export async function holderSetup(start=Date.now()-1000){
  const mode=publicVerif.BlindRSAMode.PSS;
  const keys=await publicVerif.Issuer.generateKey(mode,{modulusLength:2048,publicExponent:Uint8Array.of(1,0,1)});
  const publicBytes=await publicVerif.getPublicKeyBytes(keys.publicKey);
  const m=makeManifest({run_id:'a'.repeat(32),run_start_ms:start,token_key_spki_b64url:encodeBase64Url(publicBytes),
    snapshot_script_sha1:REPLAY_SCRIPTS.snapshot.sha1,claim_script_sha1:REPLAY_SCRIPTS.claim.sha1,client_profile:'security'});
  const p=validateRegionalPolicy({contract_version:REGIONAL.contract_version,schema_version:1,run_id:m.run_id,
    baseline_config_digest:configurationDigest(m),profile:'type2-holder',window_start_ms:start,window_end_ms:start+60000,
    quota:5,admitted_entitlements:5,resource_id:REGIONAL.resource_id,method:REGIONAL.method,url:REGIONAL.url,
    type2_key_id:m.token_key_id,arc_key_id:null,arc_implementation_revision:null,arc_tag_encoding:null},m);
  const issuer=new publicVerif.Issuer(mode,m.issuer_name,keys.privateKey,keys.publicKey);
  return {m,p,publicBytes,issuer};
}
export function holderKey(){
  const key=generateKeyPairSync('ec',{namedCurve:'prime256v1'});
  return {privateKey:key.privateKey,spki:key.publicKey.export({format:'der',type:'spki'}).toString('base64url')};
}
export async function issueHolder(verifier:HolderVerifier,setup:Awaited<ReturnType<typeof holderSetup>>,now:number){
  const owner=holderKey(),challenge=verifier.challenge(owner.spki,now);
  const bytes=Uint8Array.from(Buffer.from(challenge['challenge_b64url'] as string,'base64url'));
  const client=new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
  const request=await client.createTokenRequest(TokenChallenge.deserialize(bytes),setup.publicBytes);
  const token=(await client.finalize(await setup.issuer.issue(request))).serialize();
  return {owner,token:Uint8Array.from(token)};
}
export function signedHolderBody(verifier:HolderVerifier,p:RegionalPolicy,token:Uint8Array,owner:ReturnType<typeof holderKey>,now:number,
  mutateInput?:(input:Uint8Array)=>Uint8Array){
  const nonce=verifier.nonce(hex(sha256(token)),owner.spki,now) as {body:HolderNonce;mac:string};
  let input=holderProofInput(p,token,owner.spki,nonce,now);if(mutateInput)input=mutateInput(input);
  const signature=sign('sha256',input,{key:owner.privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');
  return {contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(p),token_b64url:Buffer.from(token).toString('base64url'),
    proof:{contract_version:REGIONAL.contract_version,policy_digest:regionalPolicyDigest(p),public_key_spki_b64url:owner.spki,nonce,signature_b64url:signature}};
}
