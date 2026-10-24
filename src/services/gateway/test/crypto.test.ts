import test from 'node:test';
import assert from 'node:assert/strict';
import { publicVerif, Token, TokenChallenge, TOKEN_TYPES } from '@cloudflare/privacypass-ts';
import known from '../../../contracts/fixtures/rfc9578-public.json' with {type:'json'};
import golden from '../../../contracts/fixtures/policy-golden.json' with {type:'json'};
import { libraryBytes,tokenWire,hex,fromHex,sha256,encodeBase64Url,makeManifest,challengeBytes,redemptionContext,validateManifest } from '../../../contracts/lib/index.ts';
const {BlindRSAMode,Client,Issuer,Origin,TokenRequest,TokenResponse,getPublicKeyBytes,convertRSASSAPSSToEnc}=publicVerif;

test('independent RFC 9578 public vector verifies using public key only',async()=>{
  const spki=fromHex(known.pkS,known.pkS.length/2);
  const converted=libraryBytes(convertRSASSAPSSToEnc(spki));
  const key=await crypto.subtle.importKey('spki',converted,{name:'RSA-PSS',hash:'SHA-384'},true,['verify']);
  const bytes=tokenWire(fromHex(known.token,354));
  const token=Token.deserialize(TOKEN_TYPES.BLIND_RSA,bytes);
  assert.equal(await new Origin(BlindRSAMode.PSS).verify(token,key),true);
  assert.equal(hex(sha256(fromHex(known.token_challenge,known.token_challenge.length/2))),hex(token.authInput.challengeDigest));
  assert.equal(hex(sha256(spki)),hex(token.authInput.tokenKeyId));
  assert.equal(fromHex(known.token_request,259).length,259);
  assert.equal(fromHex(known.token_response,256).length,256);
  const altered=Uint8Array.from(bytes);altered[10]=altered[10]!^1;
  assert.equal(await new Origin(BlindRSAMode.PSS).verify(Token.deserialize(TOKEN_TYPES.BLIND_RSA,altered),key),false);
});

test('canonical challenge equals selected library RFC encoding with standalone buffers',()=>{
  const m=validateManifest(golden.manifest);
  const challenge=new TokenChallenge(2,m.issuer_name,redemptionContext(m,2),[m.origin_name]);
  assert.equal(hex(challenge.serialize()),golden.challenge_hex);
  assert.deepEqual(challenge.serialize(),challengeBytes(m,2));
});

test('fresh RSA-2048 blind issuance, finalize and public-only verification interoperate',async()=>{
  const mode=BlindRSAMode.PSS;
  const keys=await Issuer.generateKey(mode,{modulusLength:2048,publicExponent:Uint8Array.of(1,0,1)});
  const spki=libraryBytes(await getPublicKeyBytes(keys.publicKey));
  const manifest=makeManifest({run_id:hex(crypto.getRandomValues(new Uint8Array(16))),run_start_ms:1700000000000,
    token_key_spki_b64url:encodeBase64Url(spki),snapshot_script_sha1:'1'.repeat(40),claim_script_sha1:'2'.repeat(40)});
  const challenge=new TokenChallenge(2,manifest.issuer_name,redemptionContext(manifest,0),[manifest.origin_name]);
  const client=new Client(mode);
  const req=await client.createTokenRequest(challenge,spki);
  const requestWire=libraryBytes(req.serialize(),259);
  assert.equal(requestWire[2],sha256(spki).at(-1));
  const issuer=new Issuer(mode,manifest.issuer_name,keys.privateKey,keys.publicKey);
  const issued=await issuer.issue(TokenRequest.deserialize(TOKEN_TYPES.BLIND_RSA,requestWire));
  const responseWire=libraryBytes(issued.serialize(),256);
  const token=await client.finalize(TokenResponse.deserialize(responseWire));
  const wire=tokenWire(token.serialize());
  assert.equal(wire.length,354);
  // Gateway imports only public material; no Issuer instance/private key is required there.
  const publicKey=await crypto.subtle.importKey('spki',libraryBytes(convertRSASSAPSSToEnc(spki)),{name:'RSA-PSS',hash:'SHA-384'},false,['verify']);
  const origin=new Origin(mode);
  assert.equal(await origin.verify(Token.deserialize(TOKEN_TYPES.BLIND_RSA,wire),publicKey),true);
  assert.equal(hex(token.authInput.challengeDigest),hex(sha256(challenge.serialize())));
  // Signature verification alone does NOT enforce the gateway's configured epoch/context.
  assert.notEqual(hex(token.authInput.challengeDigest),hex(sha256(challengeBytes(manifest,1))));
  const backing=Buffer.alloc(400,0xff);backing.set(wire,19);
  const isolated=tokenWire(backing.subarray(19,373));
  assert.equal(await origin.verify(Token.deserialize(TOKEN_TYPES.BLIND_RSA,isolated),publicKey),true);
  assert.throws(()=>tokenWire(Uint8Array.from([...wire,0])));
});
