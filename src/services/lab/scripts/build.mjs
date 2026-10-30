import { build } from 'esbuild';
// One self-contained bundle per runtime entry point. Roles are separate processes that share only the contract code.
const entries = {
  bootstrap: 'src/bootstrap.ts',
  issuer: 'src/roles/issuer.ts',
  client: 'src/roles/client.ts',
  origin: 'src/roles/origin.ts',
  harness: 'src/roles/harness.ts',
  'control-helper': 'src/roles/control-helper.ts',
};
const { metafile } = await build({
  entryPoints: entries,
  outdir: 'dist',
  outExtension: { '.js': '.mjs' },
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  packages: 'external',
  sourcemap: false,
  metafile: true,
});
const inputs = Object.keys(metafile.inputs);
if (!inputs.some((p) => p.includes('contracts/lib/'))) throw new Error('Shared contract was not bundled');
// Independence: no gateway private source and no test/fixture material may enter a lab bundle.
const bad = inputs.filter((p) => /services\/gateway|contracts\/fixtures|\/test\//.test(p.replaceAll(String.fromCharCode(92), '/')));
if (bad.length) throw new Error('Forbidden bundle inputs: ' + bad.join(', '));
