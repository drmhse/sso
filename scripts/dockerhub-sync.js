#!/usr/bin/env node

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const HUB_BASE_URL = 'https://hub.docker.com/v2';
const DEFAULT_SERVER = 'https://index.docker.io/v1/';

function usage() {
  console.error(
    'Usage: node scripts/dockerhub-sync.js [--repo namespace/name] [--description "text"] [--overview-file path] [--dry-run]'
  );
}

function parseArgs(argv) {
  const args = {
    repo: process.env.DOCKERHUB_REPOSITORY || 'editoredit/sso',
    description:
      process.env.DOCKERHUB_DESCRIPTION ||
      'Self-hosted identity platform for multi-tenant SaaS products',
    overviewFile:
      process.env.DOCKERHUB_OVERVIEW_FILE ||
      path.resolve(process.cwd(), 'DOCKERHUB_README.md'),
    dryRun: false,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--repo') {
      args.repo = argv[++i];
    } else if (arg === '--description') {
      args.description = argv[++i];
    } else if (arg === '--overview-file') {
      args.overviewFile = path.resolve(process.cwd(), argv[++i]);
    } else if (arg === '--dry-run') {
      args.dryRun = true;
    } else if (arg === '--help' || arg === '-h') {
      usage();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return args;
}

function readDockerConfig() {
  const configPath = path.join(os.homedir(), '.docker', 'config.json');
  if (!fs.existsSync(configPath)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(configPath, 'utf8'));
}

function getDockerCredential(config, server) {
  const helper = config.credsStore || config.credHelpers?.[server];
  if (!helper) {
    return null;
  }

  const output = execFileSync(`docker-credential-${helper}`, ['get'], {
    input: `${server}\n`,
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'ignore'],
  });

  return JSON.parse(output);
}

function getDockerHubAuth(config) {
  const explicitUsername = process.env.DOCKERHUB_USERNAME;
  const explicitToken = process.env.DOCKERHUB_TOKEN;
  if (explicitUsername && explicitToken) {
    return { username: explicitUsername, secret: explicitToken, source: 'env' };
  }

  const helperCredential = getDockerCredential(config, DEFAULT_SERVER);
  if (helperCredential?.Username && helperCredential?.Secret) {
    return {
      username: helperCredential.Username,
      secret: helperCredential.Secret,
      source: 'docker-credential-store',
    };
  }

  const auth = config.auths?.[DEFAULT_SERVER]?.auth;
  if (auth) {
    const [username, secret] = Buffer.from(auth, 'base64').toString('utf8').split(':');
    if (username && secret) {
      return { username, secret, source: 'docker-config-auth' };
    }
  }

  throw new Error(
    'Docker Hub credentials not found. Set DOCKERHUB_USERNAME and DOCKERHUB_TOKEN, or run docker login first.'
  );
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }

  if (!response.ok) {
    throw new Error(
      `Request failed (${response.status} ${response.statusText}) for ${url}: ${typeof data === 'string' ? data : JSON.stringify(data)}`
    );
  }

  return data;
}

async function getJwt(username, secret) {
  const payload = { identifier: username, secret };
  const data = await requestJson(`${HUB_BASE_URL}/auth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!data?.access_token) {
    throw new Error('Docker Hub auth token exchange did not return a JWT');
  }

  return data.access_token;
}

async function getRepository(token, namespace, repository) {
  return requestJson(`${HUB_BASE_URL}/repositories/${namespace}/${repository}/`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

async function updateRepository(token, namespace, repository, description, fullDescription) {
  return requestJson(`${HUB_BASE_URL}/repositories/${namespace}/${repository}/`, {
    method: 'PATCH',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      description,
      full_description: fullDescription,
    }),
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const [namespace, repository] = args.repo.split('/');
  if (!namespace || !repository) {
    throw new Error(`Invalid repository value '${args.repo}'. Expected namespace/name.`);
  }
  if (!fs.existsSync(args.overviewFile)) {
    throw new Error(`Overview file not found: ${args.overviewFile}`);
  }

  const fullDescription = fs.readFileSync(args.overviewFile, 'utf8').trim();
  if (!fullDescription) {
    throw new Error(`Overview file is empty: ${args.overviewFile}`);
  }
  if (args.description.length > 100) {
    throw new Error('Docker Hub short description must be 100 characters or fewer.');
  }

  const config = readDockerConfig();
  const auth = getDockerHubAuth(config);
  const token = await getJwt(auth.username, auth.secret);

  const current = await getRepository(token, namespace, repository);
  const summary = {
    repo: `${namespace}/${repository}`,
    authSource: auth.source,
    currentDescription: current.description || '',
    currentOverviewPresent: Boolean(current.full_description),
    nextDescription: args.description,
    nextOverviewBytes: Buffer.byteLength(fullDescription, 'utf8'),
  };

  if (args.dryRun) {
    console.log(JSON.stringify(summary, null, 2));
    return;
  }

  await updateRepository(token, namespace, repository, args.description, fullDescription);
  const updated = await getRepository(token, namespace, repository);
  console.log(
    JSON.stringify(
      {
        ...summary,
        updatedDescription: updated.description || '',
        updatedOverviewPresent: Boolean(updated.full_description),
      },
      null,
      2
    )
  );
}

main().catch((error) => {
  console.error(error.message || String(error));
  process.exit(1);
});
