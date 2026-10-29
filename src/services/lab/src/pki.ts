// Throwaway lab PKI built with node:crypto (no openssl binary needed). ECDSA P-256. The CA private key exists only
// inside the returned closure: it is never exported, so it cannot be written to disk or reused after provisioning.
import { generateKeyPairSync, sign, randomBytes, type KeyObject } from 'node:crypto';

const cat = (...p: Uint8Array[]) => Buffer.concat(p);
const len = (n: number) => (n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0x81, n]) : Buffer.from([0x82, n >> 8, n & 255]));
const tlv = (tag: number, ...p: Uint8Array[]) => { const c = cat(...p); return cat(Buffer.from([tag]), len(c.length), c); };
const seq = (...p: Uint8Array[]) => tlv(0x30, ...p);
const oid = (s: string) => {
  const n = s.split('.').map(Number); const out = [n[0]! * 40 + n[1]!];
  for (const v of n.slice(2)) { const b = [v & 127]; for (let x = v >> 7; x > 0; x >>= 7) b.unshift((x & 127) | 128); out.push(...b); }
  return tlv(0x06, Buffer.from(out));
};
const name = (cn: string) => seq(tlv(0x31, seq(oid('2.5.4.3'), tlv(0x0c, Buffer.from(cn)))));
const utc = (d: Date) => tlv(0x17, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
const ECDSA_SHA256 = seq(oid('1.2.840.10045.4.3.2'));
const ext = (id: string, critical: boolean, value: Buffer) => seq(oid(id), ...(critical ? [tlv(0x01, Buffer.from([0xff]))] : []), tlv(0x04, value));

function cert(subject: string, issuer: string, spki: Buffer, signer: KeyObject, ca: boolean, validityDays: number, dns?: string): string {
  const exts = [
    ext('2.5.29.19', true, ca ? seq(tlv(0x01, Buffer.from([0xff]))) : seq()),
    ext('2.5.29.15', true, ca ? Buffer.from([0x03, 0x02, 0x01, 0x06]) : Buffer.from([0x03, 0x02, 0x07, 0x80])),
    ...(dns ? [ext('2.5.29.17', false, seq(tlv(0x82, Buffer.from(dns))))] : []),
  ];
  const tbs = seq(tlv(0xa0, tlv(0x02, Buffer.from([2]))), tlv(0x02, cat(Buffer.from([0x01]), randomBytes(8))), ECDSA_SHA256,
    name(issuer), seq(utc(new Date(Date.now() - 3600_000)), utc(new Date(Date.now() + validityDays * 86_400_000))), name(subject), spki,
    tlv(0xa3, seq(...exts)));
  const der = seq(tbs, ECDSA_SHA256, tlv(0x03, Buffer.from([0]), sign('sha256', tbs, signer)));
  return `-----BEGIN CERTIFICATE-----\n${der.toString('base64').replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
}

export function createPki(caName = 'Lab Test CA', validityDays = 1) {
  const ca = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const caPem = cert(caName, caName, ca.publicKey.export({ type: 'spki', format: 'der' }), ca.privateKey, true, validityDays);
  return {
    caPem,
    leaf(dns: string): { key: string; cert: string } {
      const k = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      return { key: k.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
        cert: cert(dns, caName, k.publicKey.export({ type: 'spki', format: 'der' }), ca.privateKey, false, validityDays, dns) };
    },
  };
}
