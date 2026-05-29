const fs = require('node:fs/promises');
const path = require('node:path');
const { run } = require('./process');
const { resolvePlatformTarget } = require('./targets');

const backends = {
  sqlite: { binary: 'sso_sqlite', feature: 'db_sqlite' },
  postgres: { binary: 'sso_psql', feature: 'db_psql' },
  mysql: { binary: 'sso_mysql', feature: 'db_mysql' },
};

async function buildLocalImage(root, config) {
  const backend = backends[config.deployment.backend];
  if (!backend) {
    throw new Error(`Unsupported local image backend: ${config.deployment.backend}`);
  }
  const target = resolvePlatformTarget(config.deployment.platform);

  const apiDir = path.join(root, 'api');
  console.log(`\nBuilding local AuthOS image ${config.deployment.image} (${config.deployment.backend})...`);
  await run('npm', ['--workspace', 'lite-web-client', 'run', 'build'], root);
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

  const distDir = path.join(apiDir, 'target', 'dist', `linux-${target.archiveArch}`);
  await fs.mkdir(distDir, { recursive: true });
  await fs.copyFile(
    path.join(apiDir, `target/${target.rustTarget}/release/${backend.binary}`),
    path.join(distDir, backend.binary),
  );

  await run(
    'docker',
    [
      'build',
      '-f',
      'Dockerfile',
      '--platform',
      config.deployment.platform,
      '--build-arg',
      `BINARY_NAME=${backend.binary}`,
      '-t',
      config.deployment.image,
      '.',
    ],
    apiDir,
  );
}

module.exports = {
  buildLocalImage,
};
