const fs = require('node:fs/promises');
const path = require('node:path');
const { run } = require('./process');
const { compileBackendBinary, getBackend, resolveBuildVersion } = require('./release-build');

const ROOT = path.resolve(__dirname, '../..');

function parseArgs(argv) {
  const result = {
    backend: 'sqlite',
    platforms: [],
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--backend') result.backend = argv[++index];
    else if (arg === '--platform') result.platforms.push(argv[++index]);
    else throw new Error(`Unknown option: ${arg}`);
  }

  if (result.platforms.length === 0) {
    result.platforms.push('linux/amd64', 'linux/arm64');
  }

  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const backend = getBackend(args.backend);
  const apiDir = path.join(ROOT, 'api');
  const distRoot = path.join(apiDir, 'target', 'dist');
  const buildVersion = await resolveBuildVersion(ROOT);

  console.log(`\nPreparing Docker image binaries for ${args.backend}...`);
  console.log(`Embedding build version: ${buildVersion}`);

  await run('npm', ['run', 'build', '-w', '@drmhse/sso-sdk'], ROOT);
  await run('npm', ['--workspace', 'lite-web-client', 'run', 'build'], ROOT);

  for (const platform of args.platforms) {
    const { target, binaryPath } = await compileBackendBinary({
      root: ROOT,
      backendName: args.backend,
      platform,
      buildVersion,
    });
    const platformDir = path.join(distRoot, `linux-${target.archiveArch}`);
    const destination = path.join(platformDir, backend.binary);
    await fs.mkdir(platformDir, { recursive: true });
    await fs.copyFile(binaryPath, destination);
    await fs.chmod(destination, 0o755);
    console.log(`Staged ${path.relative(ROOT, destination)} for ${platform}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
