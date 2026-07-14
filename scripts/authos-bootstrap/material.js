const crypto = require('node:crypto');
const fs = require('node:fs');

const STATE_VERSION = 1;

function loadState(readJson, statePath) {
  if (!fs.existsSync(statePath)) return {};
  const state = readJson(statePath);
  return state.version === STATE_VERSION ? state : {};
}

function ensureMaterial(config, state) {
  const jwt = state.jwt || generateJwtKeys();
  const database = state.database || {};
  return {
    jwt,
    encryptionKey: state.encryptionKey || crypto.randomBytes(32).toString('hex'),
    encryptionKeyId: state.encryptionKeyId || 'default',
    encryptionPreviousKeys: state.encryptionPreviousKeys || {},
    deviceTrustSecret: state.deviceTrustSecret || crypto.randomBytes(32).toString('hex'),
    platformOwnerPassword:
      config.platformOwner.password ||
      state.platformOwnerPassword ||
      randomSecret('owner'),
    database: {
      postgresPassword:
        config.database.postgresPassword ||
        database.postgresPassword ||
        randomSecret('pg'),
      mysqlRootPassword:
        config.database.mysqlRootPassword ||
        database.mysqlRootPassword ||
        randomSecret('mysql-root'),
      mysqlPassword:
        config.database.mysqlPassword ||
        database.mysqlPassword ||
        randomSecret('mysql'),
    },
  };
}

function serializeState(material) {
  return {
    version: STATE_VERSION,
    updatedAt: new Date().toISOString(),
    jwt: material.jwt,
    encryptionKey: material.encryptionKey,
    encryptionKeyId: material.encryptionKeyId,
    encryptionPreviousKeys: material.encryptionPreviousKeys,
    deviceTrustSecret: material.deviceTrustSecret,
    platformOwnerPassword: material.platformOwnerPassword,
    database: material.database,
  };
}

function generateJwtKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return {
    privateKeyBase64: Buffer.from(privateKey).toString('base64'),
    publicKeyBase64: Buffer.from(publicKey).toString('base64'),
    kid: `authos-${crypto.randomBytes(8).toString('hex')}`,
  };
}

function randomSecret(prefix) {
  return `${prefix}_${crypto.randomBytes(24).toString('base64url')}`;
}

module.exports = {
  loadState,
  ensureMaterial,
  serializeState,
};
