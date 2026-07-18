const { run } = require('./process');

function buildCompose(config, material) {
  const lines = [
    'name: authos-bootstrap',
    'services:',
    '  authos:',
    `    image: ${quote(config.deployment.image)}`,
    `    platform: ${quote(config.deployment.platform)}`,
    '    restart: unless-stopped',
    '    init: true',
    '    read_only: true',
    '    tmpfs:',
    '      - /tmp:rw,noexec,nosuid,nodev,size=64m',
    '    cap_drop:',
    '      - ALL',
    '    security_opt:',
    '      - no-new-privileges:true',
    '    ulimits:',
    '      nofile:',
    '        soft: 65535',
    '        hard: 65535',
    '    env_file:',
    '      - ./authos.env',
    '    ports:',
    `      - "${config.deployment.apiPort}:3000"`,
    '    volumes:',
    '      - authos_geoip_data:/app/geoip',
  ];

  if (config.deployment.backend === 'sqlite') {
    lines.push('      - authos_sqlite_data:/app/data');
  }

  const dependencies = dependenciesFor(config);
  if (dependencies.length > 0) {
    lines.push('    depends_on:');
    for (const service of dependencies) {
      lines.push(`      ${service}:`, '        condition: service_started');
    }
  }

  if (config.deployment.backend === 'postgres') {
    addPostgres(lines, config, material);
  }
  if (config.deployment.backend === 'mysql') {
    addMysql(lines, config, material);
  }
  if (config.smtp.mode === 'mailpit') {
    addMailpit(lines, config);
  }

  lines.push('volumes:', '  authos_geoip_data:');
  if (config.deployment.backend === 'sqlite') lines.push('  authos_sqlite_data:');
  if (config.deployment.backend === 'postgres') lines.push('  authos_postgres_data:');
  if (config.deployment.backend === 'mysql') lines.push('  authos_mysql_data:');
  return `${lines.join('\n')}\n`;
}

function dependenciesFor(config) {
  const dependencies = [];
  if (config.smtp.mode === 'mailpit') dependencies.push('mailpit');
  if (config.deployment.backend === 'postgres') dependencies.push('postgres');
  if (config.deployment.backend === 'mysql') dependencies.push('mysql');
  return dependencies;
}

function addPostgres(lines, config, material) {
  const db = config.database;
  lines.push(
    '  postgres:',
    '    image: postgres:16-alpine',
    '    restart: unless-stopped',
    '    environment:',
    `      POSTGRES_USER: ${quote(db.postgresUser || 'authos')}`,
    `      POSTGRES_PASSWORD: ${quote(material.database.postgresPassword)}`,
    `      POSTGRES_DB: ${quote(db.postgresDb || 'authos')}`,
    '    ports:',
    `      - "${Number(db.postgresHostPort || 5433)}:5432"`,
    '    volumes:',
    '      - authos_postgres_data:/var/lib/postgresql/data',
  );
}

function addMysql(lines, config, material) {
  const db = config.database;
  lines.push(
    '  mysql:',
    '    image: mysql:8.4',
    '    restart: unless-stopped',
    '    environment:',
    `      MYSQL_ROOT_PASSWORD: ${quote(material.database.mysqlRootPassword)}`,
    `      MYSQL_DATABASE: ${quote(db.mysqlDatabase || 'authos')}`,
    `      MYSQL_USER: ${quote(db.mysqlUser || 'authos')}`,
    `      MYSQL_PASSWORD: ${quote(material.database.mysqlPassword)}`,
    '    ports:',
    `      - "${Number(db.mysqlHostPort || 3307)}:3306"`,
    '    volumes:',
    '      - authos_mysql_data:/var/lib/mysql',
  );
}

function addMailpit(lines, config) {
  lines.push(
    '  mailpit:',
    '    image: axllent/mailpit:latest',
    `    platform: ${quote(config.deployment.platform)}`,
    '    restart: unless-stopped',
    '    ports:',
    '      - "8025:8025"',
    '      - "1025:1025"',
  );
}

async function composeCmd(root, paths, args) {
  await run('docker', ['compose', '-f', paths.composeFile, ...args], root);
}

function quote(value) {
  return JSON.stringify(String(value));
}

module.exports = {
  buildCompose,
  composeCmd,
};
