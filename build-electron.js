import esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';

async function runBuild() {
  if (!fs.existsSync('dist-electron')) {
    fs.mkdirSync('dist-electron', { recursive: true });
  }

  console.log('⚡ [1/3] Bundling Electron Main Process...');
  await esbuild.build({
    entryPoints: ['electron/main.ts'],
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    outfile: 'dist-electron/main.cjs',
    external: ['electron'],
    sourcemap: false,
  });

  console.log('⚡ [2/3] Bundling Electron Preload...');
  await esbuild.build({
    entryPoints: ['electron/preload.ts'],
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    outfile: 'dist-electron/preload.cjs',
    external: ['electron'],
    sourcemap: false,
  });

  console.log('⚡ [3/3] Bundling SpaceSec Backend Server for Production...');
  await esbuild.build({
    entryPoints: ['server.ts'],
    bundle: true,
    platform: 'node',
    target: 'node20',
    format: 'cjs',
    outfile: 'dist-electron/server.cjs',
    external: ['vite', 'fsevents'],
    sourcemap: false,
  });

  console.log('✅ [Build Complete] dist-electron/ generated successfully.');
}

runBuild().catch((err) => {
  console.error('❌ Build failed:', err);
  process.exit(1);
});
