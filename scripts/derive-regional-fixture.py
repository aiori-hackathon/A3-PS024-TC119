"""Public framing/MAC vectors, independently derived using Python stdlib.

All MAC seeds, token bytes and identities below are public TEST DATA, never live setup.
The token is intentionally not a signed Privacy Pass token. No private signing key exists here.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
SPEC = json.loads((ROOT / 'src/contracts/regional-v1.json').read_text())
def canon(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
def framed(domain, *fields):
    return canon([domain, *fields])
def digest(value):
    return hashlib.sha256(value).hexdigest()
def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')
def mac(label, value):
    return hmac.new(hashlib.sha256(label.encode('ascii')).digest(), value, hashlib.sha256).hexdigest()
def policy(profile):
    return dict(contract_version=SPEC['contract_version'], schema_version=1, run_id='a'*32,
        baseline_config_digest='b'*64, profile=profile, window_start_ms=100000, window_end_ms=160000,
        quota=5, admitted_entitlements=5, resource_id=SPEC['resource_id'], method=SPEC['method'],url=SPEC['url'],
        type2_key_id='c'*64 if profile.startswith('type2-') else None,
        arc_key_id='d'*64 if profile=='arc' else None,
        arc_implementation_revision='e'*40 if profile=='arc' else None,
        arc_tag_encoding=SPEC['arc_tag_encoding'] if profile=='arc' else None)
def pd(p):
    return digest(framed(SPEC['domains']['policy'], p))

# Standard P-256 generator point, encoded as canonical SPKI. Public encoding fixture only.
x='6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
y='4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'
spki=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004'+x+y)
holder=policy('type2-holder')
arc=policy('arc')
token=bytes(354)
nonce=dict(contract_version=SPEC['contract_version'], run_id=holder['run_id'],policy_digest=pd(holder),
    token_hash=digest(token),holder_key_hash=digest(spki),issued_ms=100010,expires_ms=110010,
    random_b64url=b64(bytes([7])*32))
nonce_input=framed(SPEC['domains']['holder_nonce'],nonce)
signed_nonce=dict(body=nonce,mac=mac('TokenForge-public-fixture-nonce-key',nonce_input))
proof_input=framed(SPEC['domains']['holder_proof'],pd(holder),digest(token),digest(spki),
    'POST',SPEC['routes']['holder_redeem'],holder['method'],holder['url'],digest(b''),signed_nonce)
holder_context_input=framed(SPEC['domains']['holder_context'],pd(holder),digest(spki))
request=dict(contract_version=SPEC['contract_version'],run_id=arc['run_id'],policy_digest=pd(arc),
    request_id='1'*32,service_incarnation='2'*32,operation='verify',presentation_b64url=b64(bytes([1,2,3])))
tag=b64(bytes.fromhex('03'+x)) # Generator's y is odd.
reply={k:v for k,v in request.items() if k!='presentation_b64url'}
reply.update(request_digest=digest(canon(request)),status='verified',spend_tag_b64url=tag)
rpc_input=framed(SPEC['domains']['arc_rpc'],'request','verify',request)
reply_input=framed(SPEC['domains']['arc_rpc'],'response','verify',reply)
request_mac=mac('TokenForge-public-fixture-verify-key',rpc_input)
out=dict(notice='PUBLIC TEST DATA: encoding/MAC fixtures, not live keys or signed credentials.',
    holder_policy=holder,arc_policy=arc,holder_policy_digest=pd(holder),arc_policy_digest=pd(arc),
    public_key_spki_b64url=b64(spki),token_hash=digest(token),signed_nonce=signed_nonce,
    holder_context_input_hex=holder_context_input.hex(),
    holder_context_hex=mac('TokenForge-public-fixture-context-key',holder_context_input),
    holder_nonce_input_hex=nonce_input.hex(),holder_proof_input_hex=proof_input.hex(),
    arc_request=request,arc_response=reply,arc_rpc_input_hex=rpc_input.hex(),arc_reply_input_hex=reply_input.hex(),
    arc_request_mac=request_mac,arc_reply_mac=mac('TokenForge-public-fixture-verify-key',reply_input),
    arc_request_frame=(canon(dict(body=request,mac=request_mac))+b'\n').decode(),
    arc_spend_id=digest(framed(SPEC['domains']['arc_spend'],pd(arc),tag)),
    contexts={kind:hashlib.sha256(framed(SPEC['domains'][kind],pd(arc))).hexdigest()
              for kind in ['context','arc_request_context','arc_presentation_context']})
target=ROOT/'src/contracts/fixtures/regional-golden.json'
rendered=json.dumps(out,indent=2)+'\n'
if '--check' in sys.argv:
    if target.read_text()!=rendered:
        raise SystemExit('Regional fixture differs from independent Python derivation')
    print('PASS: independent regional framing/MAC fixture')
else:
    target.write_text(rendered)
