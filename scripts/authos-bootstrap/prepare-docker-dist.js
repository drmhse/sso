const path = require('node:path');
const {
  compileBackendBinary,
  getBackend,
  resolveBuildVersion,
  prepareFrontendAssets,
  ensureLiteClientDist,
  stageDockerBinary,
} = require('./release-build');

const ROOT = path.resolve(__dirname, '../..');

function parseArgs(argv) {
  const result = {
    backend: 'sqlite',
    platforms: [],
    skipFrontendBuild: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--backend') result.backend = argv[++index];
    else if (arg === '--platform') result.platforms.push(argv[++index]);
    else if (arg === '--skip-frontend-build') result.skipFrontendBuild = true;
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
  const buildVersion = await resolveBuildVersion(ROOT);

  console.log(`\nPreparing Docker image binaries for ${args.backend}...`);
  console.log(`Embedding build version: ${buildVersion}`);

  if (args.skipFrontendBuild) {
    await ensureLiteClientDist(ROOT);
  } else {
    await prepareFrontendAssets(ROOT);
  }

  for (const platform of args.platforms) {
    const { target, binaryPath, apiDir } = await compileBackendBinary({
      root: ROOT,
      backendName: args.backend,
      platform,
      buildVersion,
    });
    const destination = await stageDockerBinary({ apiDir, target, backend, binaryPath });
    console.log(`Staged ${path.relative(ROOT, destination)} for ${platform}`);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
