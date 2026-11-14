import test,{before} from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { TokenChallenge } from '@cloudflare/privacypass-ts';
import { HolderVerifier } from '../src/holder-verifier.ts';
import { TokenVerifier } from '../src/token-verifier.ts';
import { hex, sha256 } from '../../../contracts/lib/index.ts';
import { REGIONAL } from '../../../contracts/lib/regional.ts';
import { regionalType2Challenge } from '../../../contracts/lib/regional-wire.ts';
import { holderKey, holderSetup, issueHolder, signedHolderBody } from './helpers/holder.ts';

let setup:Awaited<ReturnType<typeof holderSetup>>;
before(async()=>{setup=await holderSetup();});
async function fixture(t:any){
  const context=randomBytes(32),nonce=randomBytes(32);
  const v=await HolderVerifier.prepare(setup.m,setup.p,context,nonce);t.after(()=>v.close());
  const now=setup.p.window_start_ms+1000;return {v,now,context,nonce};
}
test('holder challenge uses RFC encoding and a fresh key binding; token-only theft fails before owner succeeds',async t=>{
  const {v,now}=await fixture(t),issued=await issueHolder(v,setup,now),attacker=holderKey();
  const stolen=signedHolderBody(v,setup.p,issued.token,attacker,now);
  assert.deepEqual(await v.verifyRequest(stolen,now),{kind:'rejected'});
  const owner=signedHolderBody(v,setup.p,issued.token,issued.owner,now),result=await v.verifyRequest(owner,now);
  assert.equal(result.kind,'verified');if(result.kind!=='verified')throw Error();
  const claim=v.consume(result.receipt);assert.equal(claim?.kind,'regional-claim-candidate');
  assert.equal(claim?.not_after_ms,now+REGIONAL.nonce_lifetime_ms);assert.equal(v.consume(result.receipt),null);
  assert.equal(v.consume({}),null);
  const a=v.challenge(issued.owner.spki,now),b=v.challenge(attacker.spki,now);
  assert.notEqual(a['challenge_b64url'],b['challenge_b64url']);
  const wire=Buffer.from(a['challenge_b64url'] as string,'base64url'),parsed=TokenChallenge.deserialize(Uint8Array.from(wire));
  assert.ok(Buffer.from(parsed.serialize()).equals(wire));
  const contextOffset=5+setup.m.issuer_name.length;
  assert.ok(Buffer.from(regionalType2Challenge(wire.subarray(contextOffset,contextOffset+32))).equals(wire));
});
test('wrong request, nonce, key, token and signature refuse without closing or consuming owner authorization',async t=>{
  const {v,now}=await fixture(t),issued=await issueHolder(v,setup,now);
  const owner=signedHolderBody(v,setup.p,issued.token,issued.owner,now);
  const mutations=[
    (b:any)=>{b.proof.signature_b64url=Buffer.alloc(64).toString('base64url');},
    (b:any)=>{b.proof.nonce.mac='0'.repeat(64);},
    (b:any)=>{b.proof.nonce.body.token_hash='0'.repeat(64);},
    (b:any)=>{b.proof.public_key_spki_b64url=holderKey().spki;},
    (b:any)=>{b.proof.nonce.body.policy_digest='0'.repeat(64);},
    (b:any)=>{b.expected_digest='0'.repeat(64);},
    (b:any)=>{b.token_b64url=Buffer.alloc(354).toString('base64url');}
  ];
  for(const mutate of mutations){const b=structuredClone(owner);mutate(b);assert.deepEqual(await v.verifyRequest(b,now),{kind:'rejected'});}
  const wrong=signedHolderBody(v,setup.p,issued.token,issued.owner,now,input=>Buffer.from(Buffer.from(input).toString().replace('"GET"','"PUT"')));
  assert.deepEqual(await v.verifyRequest(wrong,now),{kind:'rejected'});
  assert.deepEqual(await v.verifyRequest(owner,now+REGIONAL.nonce_lifetime_ms),{kind:'rejected'});
  assert.equal(v.status.closed,false);
  assert.equal((await v.verifyRequest(signedHolderBody(v,setup.p,issued.token,issued.owner,now+1),now+1)).kind,'verified');
});
test('private keys are copied, verifier instances share nonce semantics but not opaque receipts, close is terminal',async t=>{
  const {v,now,context,nonce}=await fixture(t),other=await HolderVerifier.prepare(setup.m,setup.p,context,nonce);t.after(()=>other.close());
  const issued=await issueHolder(v,setup,now),body=signedHolderBody(v,setup.p,issued.token,issued.owner,now);
  context.fill(0);nonce.fill(0);
  const result=await v.verifyRequest(body,now);assert.equal(result.kind,'verified');if(result.kind!=='verified')throw Error();
  assert.equal(other.consume(result.receipt),null);assert.equal((await other.verifyRequest(body,now)).kind,'verified');
  await v.close();assert.equal(v.consume(result.receipt),null);assert.deepEqual(await v.verifyRequest(body,now),{kind:'unavailable'});
  assert.throws(()=>v.challenge(issued.owner.spki,now));
});

test('RSA receipts bind the same owned token and context once; in-flight close suppresses successful verification',async t=>{
  const {v,now}=await fixture(t),issued=await issueHolder(v,setup,now);
  const a=await TokenVerifier.prepare(setup.m),b=await TokenVerifier.prepare(setup.m);
  const sig=await a.verifySignature(issued.token);assert.equal(sig.kind,'signature-valid');if(sig.kind!=='signature-valid')throw Error();
  const expected=sha256(Buffer.from(v.challenge(issued.owner.spki,now)['challenge_b64url'] as string,'base64url'));
  assert.equal(b.consumeSignatureContext(sig.receipt,expected).kind,'rejected');
  const verified=a.consumeSignatureContext(sig.receipt,expected);assert.equal(verified.kind,'verified-token');
  if(verified.kind!=='verified-token')throw Error();assert.equal(verified.token_hash,hex(sha256(issued.token)));
  assert.equal(a.consumeSignatureContext(sig.receipt,expected).kind,'rejected');
  const body=signedHolderBody(v,setup.p,issued.token,issued.owner,now),work=v.verifyRequest(body,now),drain=v.close();
  assert.deepEqual(await work,{kind:'unavailable'});await drain;assert.equal(v.status.active,0);
});
