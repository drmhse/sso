const path = require('node:path');
const { resolvePlatformTarget } = require('./targets');
const { run } = require('./process');

const backends = {
  sqlite: { binary: 'sso_sqlite', feature: 'db_sqlite', dockerTagPrefix: 'sqlite' },
  postgres: { binary: 'sso_psql', feature: 'db_psql', dockerTagPrefix: 'psql' },
  mysql: { binary: 'sso_mysql', feature: 'db_mysql', dockerTagPrefix: 'mysql' },
};

function getBackend(name) {
  const backend = backends[name];
  if (!backend) {
    throw new Error(`Unsupported backend "${name}". Use sqlite, postgres, or mysql.`);
  }
  return backend;
}

async function resolveBuildVersion(root) {
  const explicit = process.env.AUTHOS_BUILD_VERSION?.trim();
  if (explicit) {
    return explicit;
  }

  try {
    const { stdout } = await run('git', ['describe', '--tags', '--exact-match'], root, {
      quiet: true,
    });
    const tag = stdout.trim();
    if (tag) {
      return tag;
    }
  } catch (error) {
    // Ignore; callers enforce release-build requirements below.
  }

  throw new Error(
    'Release builds require an exact git tag or AUTHOS_BUILD_VERSION. ' +
      'Create a tag for the release commit or export AUTHOS_BUILD_VERSION before running the release builder.',
  );
}

async function compileBackendBinary({ root, backendName, platform, buildVersion }) {
  const backend = getBackend(backendName);
  const target = resolvePlatformTarget(platform);
  const apiDir = path.join(root, 'api');

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
    {
      env: { AUTHOS_BUILD_VERSION: buildVersion },
    },
  );

  return {
    backend,
    target,
    apiDir,
    binaryPath: path.join(apiDir, `target/${target.rustTarget}/release/${backend.binary}`),
  };
}

module.exports = {
  backends,
  getBackend,
  resolveBuildVersion,
  compileBackendBinary,
};
