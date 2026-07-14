import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
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
  'PUBLIC_CLAIMS.md',
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
  'sso-sdk/package.json',
  'packages/authos-cli/package.json',
  'packages/authos-node/package.json',
  'packages/authos-react/package.json',
  'packages/authos-vue/package.json',
].map((file) => ({ file, package: json(file) }));
const sourceVersions = new Set(publicPackages.map(({ package: pkg }) => pkg.version));
requireValue(sourceVersions.size === 1, 'public npm package source versions are not aligned');
const sdkVersion = publicPackages[0].package.version;
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

const installer = read('install.sh');
requireValue(
  installer.includes('sha256sum --ignore-missing --check'),
  'standalone installer does not verify the published checksum manifest',
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
