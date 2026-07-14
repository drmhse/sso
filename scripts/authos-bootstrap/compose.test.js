const assert = require('node:assert/strict');
const test = require('node:test');

const { buildCompose } = require('./compose');
const { buildContainerEnv } = require('./env');
const { normalizeConfig } = require('./config');
const { ensureMaterial, serializeState } = require('./material');

function configFor(backend) {
  return {
    deployment: {
      image: `example/authos:${backend}`,
      platform: 'linux/amd64',
      apiPort: 3001,
      backend,
    },
    database: {
      postgresHostPort: 5433,
      mysqlHostPort: 3307,
    },
    smtp: { mode: 'external' },
  };
}

const material = {
  database: {
    postgresPassword: 'postgres-test-password',
    mysqlRootPassword: 'mysql-root-test-password',
    mysqlPassword: 'mysql-test-password',
  },
};

for (const backend of ['sqlite', 'postgres', 'mysql']) {
  test(`${backend} Compose output hardens the AuthOS container`, () => {
    const output = buildCompose(configFor(backend), material);

    assert.match(output, /- "3001:3000"/);
    assert.match(output, /    init: true/);
    assert.match(output, /    read_only: true/);
    assert.match(output, /      - \/tmp:rw,noexec,nosuid,nodev,size=64m/);
    assert.match(output, /    cap_drop:\n      - ALL/);
    assert.match(output, /      - no-new-privileges:true/);
    assert.match(output, /      - authos_geoip_data:\/app\/geoip/);
  });
}

test('SQLite Compose output mounts a dedicated writable database volume', () => {
  const output = buildCompose(configFor('sqlite'), material);

  assert.match(output, /      - authos_sqlite_data:\/app\/data/);
  assert.match(output, /  authos_sqlite_data:/);
});

test('external database Compose output does not mount the SQLite volume', () => {
  for (const backend of ['postgres', 'mysql']) {
    const output = buildCompose(configFor(backend), material);
    assert.doesNotMatch(output, /authos_sqlite_data/);
  }
});

test('bootstrap state preserves and renders the encryption keyring', () => {
  const oldKey = '1'.repeat(64);
  const activeKey = '2'.repeat(64);
  const config = normalizeConfig({ deployment: { backend: 'sqlite' } });
  const rotationState = {
    encryptionKey: activeKey,
    encryptionKeyId: 'key-2026-07',
    encryptionPreviousKeys: { 'key-2026-01': oldKey },
  };
  const rotationMaterial = ensureMaterial(config, rotationState);
  const persisted = serializeState(rotationMaterial);
  const env = buildContainerEnv(config, rotationMaterial);

  assert.equal(persisted.encryptionKey, activeKey);
  assert.equal(persisted.encryptionKeyId, 'key-2026-07');
  assert.deepEqual(persisted.encryptionPreviousKeys, { 'key-2026-01': oldKey });
  assert.equal(env.ENCRYPTION_KEY, activeKey);
  assert.equal(env.ENCRYPTION_KEY_ID, 'key-2026-07');
  assert.equal(env.ENCRYPTION_PREVIOUS_KEYS, `key-2026-01=${oldKey}`);
});
