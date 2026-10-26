import { build } from 'esbuild';
const { metafile } = await build({
  entryPoints: ['src/bootstrap.ts'],
  outfile: 'dist/bootstrap.mjs',
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
// Independence: no gateway private source and no test/fixture material may enter the lab bundle.
const bad = inputs.filter((p) => /services\/gateway|contracts\/fixtures|\/test\//.test(p.replaceAll(String.fromCharCode(92), '/')));
if (bad.length) throw new Error('Forbidden bundle inputs: ' + bad.join(', '));
