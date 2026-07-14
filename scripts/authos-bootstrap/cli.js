const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');

const DEFAULT_CONFIG = 'authos.config.json';
const DEFAULT_EXAMPLE_CONFIG = 'scripts/authos-standalone/authos.config.example.json';

function parseArgs(argv) {
  const result = {
    config: '',
    force: false,
    help: false,
    init: false,
    provision: false,
    reset: false,
    timeout: 120000,
    up: false,
    wait: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--config' || arg === '-c') result.config = argv[++index];
    else if (arg === '--force') result.force = true;
    else if (arg === '--help' || arg === '-h') result.help = true;
    else if (arg === '--init') result.init = true;
    else if (arg === '--provision') result.provision = true;
    else if (arg === '--reset') result.reset = true;
    else if (arg === '--timeout-ms') result.timeout = Number(argv[++index]);
    else if (arg === '--up') result.up = true;
    else if (arg === '--wait') result.wait = true;
    else throw new Error(`Unknown option: ${arg}`);
  }

  return result;
}

function printHelp() {
  console.log(`AuthOS bootstrap

Usage:
  npm run authos:bootstrap -- --init
  npm run authos:bootstrap -- --up --wait --provision
  npm run authos:bootstrap -- --reset --up --wait --provision

Options:
  -c, --config <path>     JSON config path (default: authos.config.json)
      --init              Create a config from the AGPL-licensed standalone example
      --force             Overwrite the config when used with --init
      --up                Start or update the generated Docker Compose stack
      --wait              Wait for /health/ready
      --provision         Log in and converge org/service resources
      --reset             docker compose down -v before starting
      --timeout-ms <ms>   Readiness timeout (default: 120000)
`);
}

async function initConfig(root, configPath, force) {
  if (fs.existsSync(configPath) && !force) {
    throw new Error(`${path.relative(root, configPath)} already exists. Use --force to overwrite it.`);
  }
  await fsp.copyFile(path.resolve(root, DEFAULT_EXAMPLE_CONFIG), configPath);
  console.log(`Created ${path.relative(root, configPath)} from ${DEFAULT_EXAMPLE_CONFIG}.`);
}

module.exports = {
  DEFAULT_CONFIG,
  parseArgs,
  printHelp,
  initConfig,
};
