const fs = require('node:fs/promises');
const path = require('node:path');
const { assertCommand, run } = require('./process');
const { resolvePlatformTarget } = require('./targets');

const ROOT = path.resolve(__dirname, '../..');
const COPYFILE_DISABLE_ENV = { COPYFILE_DISABLE: '1' };

const backends = {
  sqlite: { binary: 'sso_sqlite', feature: 'db_sqlite' },
  postgres: { binary: 'sso_psql', feature: 'db_psql' },
  mysql: { binary: 'sso_mysql', feature: 'db_mysql' },
};

function parseArgs(argv) {
  const result = {
    backend: 'sqlite',
    outputDir: '.authos/releases',
    platform: 'linux/amd64',
    skipUpx: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--backend') result.backend = argv[++index];
    else if (arg === '--output-dir') result.outputDir = argv[++index];
    else if (arg === '--platform') result.platform = argv[++index];
    else if (arg === '--skip-upx') result.skipUpx = true;
    else throw new Error(`Unknown option: ${arg}`);
  }

  return result;
}

function formatBytes(value) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 100 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

async function maybePrintSectionProfile(binaryPath, cwd) {
  try {
    const { stdout } = await run('objdump', ['-h', binaryPath], cwd, { quiet: true });
    const interestingSections = stdout
      .split('\n')
      .filter((line) => /\s\.(text|rodata|data\.rel\.ro|eh_frame|gcc_except_table)\s/.test(line))
      .map((line) => line.trim().replace(/\s+/g, ' '));
    if (interestingSections.length > 0) {
      console.log('\nSection profile:');
      for (const section of interestingSections) {
        console.log(`  ${section}`);
      }
    }
  } catch (error) {
    console.warn(`\nSkipped objdump section profile: ${error.message}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const backend = backends[args.backend];
  if (!backend) {
    throw new Error(`Unsupported backend "${args.backend}". Use sqlite, postgres, or mysql.`);
  }

  const target = resolvePlatformTarget(args.platform);
  const apiDir = path.join(ROOT, 'api');
  const outputDir = path.resolve(ROOT, args.outputDir);
  const releaseRoot = path.join(outputDir, `authos-${args.backend}-linux-${target.archiveArch}`);
  const archiveName = `authos-${args.backend}-linux-${target.archiveArch}.tar.gz`;
  const archivePath = path.join(outputDir, archiveName);
  const standaloneDir = path.join(releaseRoot, 'standalone');

  console.log(`\nBuilding standalone AuthOS binary bundle for ${args.backend} on ${args.platform}...`);
  await assertCommand('cargo', ['zigbuild', '--help'], apiDir);
  if (!args.skipUpx) {
    await assertCommand('upx', ['--version'], ROOT);
  }
  await run('npm', ['run', 'build', '-w', '@drmhse/sso-sdk'], ROOT);
  await run('npm', ['--workspace', 'lite-web-client', 'run', 'build'], ROOT);
  await run(
    'cargo',
    [
      'zigbuild',
      '--release',
      '--target',
      target.rustTarget,
      '--no-default-features',
      '--features',
      backend.feature,
      '--bin',
      backend.binary,
    ],
    apiDir,
  );

  const builtBinary = path.join(apiDir, `target/${target.rustTarget}/release/${backend.binary}`);
  const bundledBinary = path.join(releaseRoot, 'authos');

  await fs.rm(releaseRoot, { recursive: true, force: true });
  await fs.rm(archivePath, { force: true });
  await fs.mkdir(releaseRoot, { recursive: true });
  await fs.mkdir(standaloneDir, { recursive: true });
  await fs.copyFile(builtBinary, bundledBinary);
  await fs.chmod(bundledBinary, 0o755);
  const builtStats = await fs.stat(builtBinary);
  console.log(`\nBuilt binary size: ${formatBytes(builtStats.size)} (${builtStats.size.toLocaleString()} bytes)`);
  await maybePrintSectionProfile(builtBinary, apiDir);
  if (!args.skipUpx) {
    console.log('\nCompressing binary with UPX...');
    await run('upx', ['--best', '--lzma', bundledBinary], ROOT);
    await run('upx', ['-t', bundledBinary], ROOT);
  }
  await fs.copyFile(path.join(ROOT, 'authos.config.example.json'), path.join(releaseRoot, 'authos.config.example.json'));
  await fs.writeFile(
    path.join(releaseRoot, 'install.sh'),
    [
      '#!/usr/bin/env bash',
      'set -euo pipefail',
      'SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"',
      'exec python3 "${SCRIPT_DIR}/standalone/authos_standalone.py" install --bundle-dir "${SCRIPT_DIR}" "$@"',
      '',
    ].join('\n'),
    'utf8',
  );
  await fs.chmod(path.join(releaseRoot, 'install.sh'), 0o755);
  await fs.copyFile(
    path.join(ROOT, 'scripts/authos-standalone/authos_standalone.py'),
    path.join(standaloneDir, 'authos_standalone.py'),
  );
  await fs.chmod(path.join(standaloneDir, 'authos_standalone.py'), 0o755);
  await fs.writeFile(
    path.join(releaseRoot, 'README.txt'),
    [
      'AuthOS standalone bundle',
      '',
      `Backend: ${args.backend}`,
      `Platform: ${args.platform}`,
      `Rust target: ${target.rustTarget}`,
      '',
      'Contents:',
      '- authos',
      '- authos.config.example.json',
      '- install.sh',
      '- standalone/authos_standalone.py',
      '',
      'Notes:',
      '- The lite web client is embedded in the binary.',
      '- Run sudo ./install.sh for the no-Docker Linux install flow.',
      '- The installer manages config.json, systemd, and optional Caddy setup.',
      '- Managed config writes live in /var/lib/authos so the lite admin UI can edit them.',
      '',
    ].join('\n'),
    'utf8',
  );

  await fs.mkdir(outputDir, { recursive: true });
  await run('tar', ['-czf', archiveName, path.basename(releaseRoot)], outputDir, {
    env: COPYFILE_DISABLE_ENV,
  });

  const bundledStats = await fs.stat(bundledBinary);
  const archiveStats = await fs.stat(archivePath);
  const compressionRatio = builtStats.size === 0
    ? 'n/a'
    : `${((1 - bundledStats.size / builtStats.size) * 100).toFixed(2)}%`;

  console.log('\nStandalone bundle complete\n');
  console.log(`Directory: ${path.relative(ROOT, releaseRoot)}`);
  console.log(`Archive: ${path.relative(ROOT, archivePath)}`);
  console.log(`Binary: ${path.relative(ROOT, bundledBinary)}`);
  console.log(`Compressed binary size: ${formatBytes(bundledStats.size)} (${bundledStats.size.toLocaleString()} bytes)`);
  console.log(`Archive size: ${formatBytes(archiveStats.size)} (${archiveStats.size.toLocaleString()} bytes)`);
  console.log(`UPX reduction: ${compressionRatio}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
