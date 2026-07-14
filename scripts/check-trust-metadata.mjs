import fs from 'node:fs';
import path from 'node:path';

const root = process.env.AUTHOS_TRUST_ROOT || process.cwd();
const failures = [];
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const json = (file) => JSON.parse(read(file));
const requireValue = (condition, message) => {
  if (!condition) failures.push(message);
};

const trustDocs = [
  'CHANGELOG.md',
  'CONTRIBUTING.md',
  'PRODUCTION_READINESS.md',
  'PROJECT_STATUS.md',
  'RELEASES.md',
  'SECURITY.md',
  'SUPPORT.md',
];

const readme = read('README.md');
for (const file of trustDocs) {
  requireValue(fs.existsSync(path.join(root, file)), `missing trust document: ${file}`);
  requireValue(readme.includes(`./${file}`), `README does not link to ${file}`);
}

for (const file of ['README.md', ...trustDocs]) {
  const markdown = read(file);
  for (const match of markdown.matchAll(/\]\((\.\/[^)#]+)(?:#[^)]+)?\)/g)) {
    const target = decodeURIComponent(match[1]);
    requireValue(
      fs.existsSync(path.resolve(root, target)),
      `${file} links to missing local target ${target}`,
    );
  }
}

const rootPackage = json('package.json');
requireValue(rootPackage.private === true, 'root npm workspace must remain private');
requireValue(rootPackage.version === '0.0.0', 'root npm workspace version must remain 0.0.0');
requireValue(
  rootPackage.engines?.node === '^20.19.0 || ^22.13.0 || >=24.0.0',
  'root Node engine must satisfy the ESLint 10 and Vite 8 runtime floors',
);

const publicPackages = [
  ['sso-sdk/package.json', 'sso-sdk/README.md'],
  ['packages/authos-cli/package.json', 'packages/authos-cli/README.md'],
  ['packages/authos-node/package.json', 'packages/authos-node/README.md'],
  ['packages/authos-react/package.json', 'packages/authos-react/README.md'],
  ['packages/authos-vue/package.json', 'packages/authos-vue/README.md'],
].map(([file, packageReadme]) => ({ file, packageReadme, package: json(file) }));
const sourceVersions = new Set(publicPackages.map(({ package: pkg }) => pkg.version));
requireValue(sourceVersions.size === 1, 'public npm package source versions are not aligned');
const sdkVersion = publicPackages[0].package.version;
for (const { file, packageReadme, package: pkg } of publicPackages) {
  requireValue(/pre-1\.0/i.test(pkg.description), `${file} description does not state pre-1.0 maturity`);
  const packageReadmeText = read(packageReadme);
  requireValue(
    /pre-1\.0 and Beta/i.test(packageReadmeText),
    `${packageReadme} does not state pre-1.0 Beta maturity`,
  );
  requireValue(
    packageReadmeText.includes('https://github.com/drmhse/AuthOS/blob/main/PROJECT_STATUS.md'),
    `${packageReadme} does not link to PROJECT_STATUS.md`,
  );
}
for (const { file, package: pkg } of publicPackages.slice(1)) {
  if (pkg.dependencies?.['@drmhse/sso-sdk']) {
    requireValue(
      pkg.dependencies['@drmhse/sso-sdk'] === sdkVersion,
      `${file} does not pin @drmhse/sso-sdk to ${sdkVersion}`,
    );
  }
}

const changelog = read('CHANGELOG.md');
const currentRelease = changelog.match(/^## (\d+\.\d+\.\d+) - /m)?.[1];
requireValue(Boolean(currentRelease), 'CHANGELOG has no latest numbered release');
requireValue(
  readme.includes(`AUTHOS_VERSION=v${currentRelease}`),
  `README install example does not use v${currentRelease}`,
);

const bootstrapConfig = read('scripts/authos-bootstrap/config.js');
for (const backend of ['sqlite', 'psql', 'mysql']) {
  requireValue(
    bootstrapConfig.includes(`editoredit/sso:${backend}-v${currentRelease}`),
    `bootstrap default for ${backend} does not use v${currentRelease}`,
  );
}

const composePins = {
  // This file is a developer-only database dependency, not a release topology.
  'api/docker-compose.dev.yml': ['postgres:15-alpine'],
  'api/docker-compose.sqlite.yml': [
    `editoredit/sso:sqlite-v${currentRelease}`,
  ],
  'api/docker-compose.postgres.yml': [
    `editoredit/sso:psql-v${currentRelease}`,
    'postgres:16-alpine',
  ],
  'api/docker-compose.mysql.yml': [
    `editoredit/sso:mysql-v${currentRelease}`,
    'mysql:8.4',
  ],
  'api/docker-compose.yml': [
    `editoredit/sso:sqlite-v${currentRelease}`,
    `editoredit/sso:psql-v${currentRelease}`,
    `editoredit/sso:mysql-v${currentRelease}`,
    'postgres:16-alpine',
    'mysql:8.4',
  ],
  'api/docker-compose.test.yml': ['postgres:16-alpine', 'mysql:8.4'],
};
const composeFiles = fs.readdirSync(path.join(root, 'api'))
  .filter((file) => /^docker-compose(?:\.[a-z]+)?\.yml$/.test(file))
  .map((file) => `api/${file}`)
  .sort();
requireValue(
  JSON.stringify(composeFiles) === JSON.stringify(Object.keys(composePins).sort()),
  'every api/docker-compose*.yml file must have an explicit trust-pin classification',
);
const missingPins = (compose, expectedPins) => expectedPins.filter((pin) => !compose.includes(pin));
for (const [file, expectedPins] of Object.entries(composePins)) {
  const compose = read(file);
  for (const expected of missingPins(compose, expectedPins)) {
    requireValue(false, `${file} does not pin ${expected}`);
  }
  const releasePin = expectedPins.find((pin) => pin.includes(`v${currentRelease}`));
  if (releasePin) {
    const staleFixture = compose.replace(releasePin, releasePin.replace(currentRelease, '0.0.0'));
    requireValue(
      missingPins(staleFixture, expectedPins).includes(releasePin),
      `${file} stale-version negative self-test did not reject a replaced release pin`,
    );
  }
}

const installer = read('install.sh');
requireValue(
  installer.includes('sha256sum --check --strict'),
  'standalone installer does not strictly verify the selected published checksum',
);
requireValue(
  installer.includes('observed_files != required_files'),
  'standalone installer does not enforce the exact archive inventory',
);

if (failures.length) {
  console.error('Trust metadata validation failed:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `Trust metadata is consistent: ${trustDocs.length} documents, ` +
    `${publicPackages.length} public package manifests, release v${currentRelease}.`,
);
