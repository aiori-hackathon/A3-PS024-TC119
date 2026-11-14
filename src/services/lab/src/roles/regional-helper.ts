import { canonicalJson } from '../../../../contracts/lib/index.ts';
import { decodeCanonicalRegionalJson } from '../../../../contracts/lib/regional-wire.ts';
import { regionalControlCall } from '../regional-control.ts';

try {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 65536) throw Error();
    chunks.push(chunk);
  }
  const request = decodeCanonicalRegionalJson(Buffer.concat(chunks), true) as Record<string, any>;
  const reply = await regionalControlCall(request);
  process.stdout.write(canonicalJson(reply) + '\n');
} catch {
  process.stderr.write('regional-helper-failed\n');
  process.exitCode = 1;
}
