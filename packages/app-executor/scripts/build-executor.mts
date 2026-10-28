import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { execa } from 'execa';
import chalk from 'chalk';
import * as esbuild from 'esbuild';
import { resolve } from 'node:path';
import { relocateUniversalPkg } from './relocate-universal-pkg.mjs';

const resolveRivet: esbuild.Plugin = {
  name: 'resolve-rivet',
  setup(build) {
    build.onResolve({ filter: /^@ironclad\/rivet-/ }, (args) => {
      const rivetPackage = args.path.replace(/^@ironclad\/rivet-/, '');
      return {
        path: resolve(`../${rivetPackage}/src/index.ts`),
      };
    });
  },
};

console.log(`Bundling to ${chalk.cyan('bin/executor-bundle.cjs')}...`);

await esbuild.build({
  entryPoints: ['bin/executor.mts'],
  bundle: true,
  platform: 'node',
  outfile: './bin/executor-bundle.cjs',
  format: 'cjs',
  // Preserve createRequire's module location when compiling ESM sources into the CommonJS sidecar.
  define: { 'import.meta.url': '__filename' },
  target: 'node16',
  external: [],
  plugins: [resolveRivet],
});

console.log(`Compiling to native binary for ${chalk.cyan(process.platform)}...`);

const { platform } = process;

if (platform !== 'darwin' && platform !== 'linux' && platform !== 'win32') {
  console.error(`Unsupported platform ${platform}.`);
  process.exit(1);
}

// Build each architecture explicitly: copying an Intel executable to an ARM filename
// prevents the sidecar from launching on Apple Silicon without Rosetta.
const targets =
  platform === 'darwin'
    ? [
        { pkg: 'node18-macos-x64', file: 'app-executor-x86_64-apple-darwin' },
        { pkg: 'node18-macos-arm64', file: 'app-executor-aarch64-apple-darwin' },
      ]
    : platform === 'win32'
      ? [{ pkg: 'node18-win-x64', file: 'app-executor-x86_64-pc-windows-msvc.exe' }]
      : process.arch === 'arm64'
        ? [{ pkg: 'node18-linux-arm64', file: 'app-executor-aarch64-unknown-linux-gnu' }]
        : [{ pkg: 'node18-linux-x64', file: 'app-executor-x86_64-unknown-linux-gnu' }];

await mkdir('dist', { recursive: true });
for (const target of targets) {
  await execa(
    'yarn',
    [
      'pkg',
      '.',
      '--output',
      `dist/${target.file}`,
      '--no-bytecode',
      '--options',
      'experimental-network-imports',
      '--targets',
      target.pkg,
    ],
    { stdio: 'inherit' },
  );
  console.log(`Built ${chalk.cyan(target.file)} for ${target.pkg}`);
}

if (platform === 'darwin') {
  const universal = 'dist/app-executor-universal-apple-darwin';
  await execa('lipo', ['-create', ...targets.map((target) => `dist/${target.file}`), '-output', universal]);
  // Read the exact Node runtimes selected by pkg, before its position markers were replaced.
  const require = createRequire(import.meta.url);
  const { need } = createRequire(require.resolve('pkg'))('pkg-fetch') as {
    need: (options: { nodeRange: string; platform: string; arch: string }) => Promise<string>;
  };
  const runtimes = await Promise.all(
    ['x64', 'arm64'].map(async (arch) => readFile(await need({ nodeRange: 'node18', platform: 'macos', arch }))),
  );
  const binary = await readFile(universal);
  relocateUniversalPkg(binary, { x64: runtimes[0]!, arm64: runtimes[1]! });
  await writeFile(universal, new Uint8Array(binary));
  await execa('codesign', ['--force', '--sign', '-', universal]);
  // Test the actual universal executable, not just a thin binary that lipo might break.
  const smoke = await execa(resolve(universal), ['--oauth-login'], {
    input: '{"cancel":true}\n',
    timeout: 15000,
    env: { NODE_OPTIONS: '', NODE_PATH: '', PKG_EXECPATH: '' },
  });
  if (smoke.stdout.trim() !== '{"result":false}') throw new Error('Universal executor startup check failed');
  console.log(`Built ${chalk.cyan(universal)} with Intel and Apple Silicon architectures`);
}
