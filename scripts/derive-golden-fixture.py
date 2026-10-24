"""Independent stdlib implementation of policy encodings; never imports TS helpers.
Check in public output only. This is a cross-check, not a token implementation.
"""
from pathlib import Path
import base64
import hashlib
import json
import struct
import sys

root = Path(__file__).resolve().parent.parent
directory = root / 'src/contracts'
p = json.loads((directory / 'protocol-v1.json').read_text(encoding='utf-8'))
v = json.loads((directory / 'fixtures/rfc9578-public.json').read_text(encoding='utf-8'))
sha = lambda b: hashlib.sha256(b).digest()
spki = bytes.fromhex(v['pkS'])
manifest = {
    'schema_version': 1, 'contract_version': p['contract_version'], 'policy_version': 1,
    'run_id': bytes(range(16)).hex(), 'run_start_ms': 1700000000000,
    'epoch_ms': 600000, 'guard_ms': 30000, 'token_type': 2,
    'token_key_id': sha(spki).hex(),
    'token_key_spki_b64url': base64.urlsafe_b64encode(spki).decode('ascii'),
    'issuer_name': 'issuer.lab.test', 'origin_name': 'origin.lab.test',
    'resource_scope': 'GET /resource', 'issuer_request_uri': 'https://issuer.lab.test/issue',
    'snapshot_script_sha1': '1' * 40, 'claim_script_sha1': '2' * 40,
    'gateway_profile': 'B1', 'client_profile': 'security', 'inventory_total': 128,
    'endpoints': p['endpoints'],
    'limits': {
        'gateway': {**p['gateway_common'], **p['gateway_profiles']['B1']},
        'issuer': p['issuer_limits'], 'client': p['client_profiles']['security'],
        'control_message_max_bytes': 65536, 'provision_batch_max': 128,
    },
}
canonical = json.dumps(manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
epoch = 2
start = manifest['run_start_ms'] + epoch * 600000
end = start + 600000
lp = lambda s: struct.pack('!H', len(s.encode('ascii'))) + s.encode('ascii')
context_input = (
    b'PS024-context-v1' + struct.pack('!H', 2) + bytes(range(16)) + sha(spki)
    + struct.pack('!QQQ', epoch, start, end)
    + lp(manifest['issuer_name']) + lp(manifest['origin_name']) + lp('GET /resource')
)
context = sha(context_input)
challenge = struct.pack('!H', 2) + lp(manifest['issuer_name']) + bytes([32]) + context + lp(manifest['origin_name'])
nonce = bytes(range(32))
auth_input = struct.pack('!H', 2) + nonce + sha(challenge) + sha(spki)
golden = {
    'test_only': True,
    'provenance': 'Independent Python hashlib/struct derivation: scripts/derive-golden-fixture.py; pinned public RSA key from rfc9578-public.json',
    'note': 'Script SHAs are fixture placeholders, not installed Redis scripts. No live signing key.',
    'manifest': manifest, 'canonical_manifest': canonical,
    'config_digest': sha(canonical.encode('ascii')).hex(),
    'epoch': epoch, 'epoch_start_ms': start, 'epoch_end_ms': end,
    'context_input_hex': context_input.hex(), 'redemption_context_hex': context.hex(),
    'challenge_hex': challenge.hex(), 'challenge_digest_hex': sha(challenge).hex(),
    'nonce_hex': nonce.hex(), 'auth_input_hex': auth_input.hex(),
    'spend_id': sha(b'PS024-spend-v1' + auth_input).hex(),
    'truncated_token_key_id': sha(spki)[-1],
    'voucher_hex': bytes(range(64, 96)).hex(),
    'voucher_digest': sha(b'PS024-voucher-v1' + bytes(range(64, 96))).hex(),
}
output = json.dumps(golden, indent=2, ensure_ascii=True) + '\n'
destination = directory / 'fixtures/policy-golden.json'
if '--check' in sys.argv:
    assert destination.read_text(encoding='utf-8') == output, 'Golden fixture drift'
    print('Independent Python golden fixture matches')
else:
    destination.write_text(output, encoding='utf-8')
    print('Derived public policy golden fixture independently')
