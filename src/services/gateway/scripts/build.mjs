import { build } from 'esbuild';
await build({
  entryPoints: { bootstrap: 'src/bootstrap.ts', 'token-verifier': 'src/token-verifier.ts', 'http-auth': 'src/http-auth.ts', 'replay-scripts': 'src/replay-scripts.ts' },
  outdir: 'dist',
  outExtension: { '.js': '.mjs' },
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node24',
  packages: 'external',
  sourcemap: false,
  metafile: true,
}).then(({ metafile }) => {
  if (!Object.keys(metafile.inputs).some((p) => p.includes('contracts/lib/'))) {
    throw new Error('Shared contract was not bundled');
  }
});
