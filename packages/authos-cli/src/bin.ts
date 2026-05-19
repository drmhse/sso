import { Command } from 'commander';
import { initCommand, addCommand, provisionActCommand } from './commands';
import { getAvailableTemplates, getTemplate } from './templates/registry';
import pc from 'picocolors';

const program = new Command();

program
  .name('authos')
  .description('CLI for scaffolding AuthOS integrations')
  .version('0.1.0');

program
  .command('init')
  .description('Initialize AuthOS in your project')
  .option('--skip-install', 'Skip package installation')
  .action(async (options) => {
    await initCommand({ skipInstall: options.skipInstall });
  });

program
  .command('add [template]')
  .description('Add a component template to your project')
  .option('-f, --force', 'Overwrite existing files without prompting')
  .action(async (template, options) => {
    await addCommand(template, { force: options.force });
  });

program
  .command('list')
  .description('List available component templates')
  .action(() => {
    console.log(pc.bold('\nAvailable templates:\n'));

    for (const name of getAvailableTemplates()) {
      const template = getTemplate(name)!;
      console.log(`  ${pc.cyan(name)}`);
      console.log(`    ${pc.dim(template.description)}\n`);
    }

    console.log(`Run ${pc.cyan('authos add <template>')} to add a component.\n`);
  });

const provision = program
  .command('provision')
  .description('Provision AuthOS resources for a deployed application');

provision
  .command('act')
  .description('Idempotently bootstrap the ACT organization, service, redirects, and API key')
  .option('--act-url <url>', 'Public ACT backend URL')
  .option('--base-url <url>', 'AuthOS API base URL')
  .option('--admin-token <token>', 'AuthOS admin bearer token')
  .option('--owner-email <email>', 'Platform owner email for bootstrap login')
  .option('--owner-password <password>', 'Platform owner password for bootstrap login')
  .option('--org <slug>', 'AuthOS organization slug', 'act')
  .option('--org-name <name>', 'AuthOS organization display name', 'ACT')
  .option('--service <slug>', 'AuthOS service slug', 'act')
  .option('--name <name>', 'AuthOS service display name', 'ACT')
  .option('--native-redirect-uri <uri>', 'Native app callback URI', 'act://auth/callback')
  .option('--web-redirect-uri <uri>', 'Web callback URI')
  .option('--github-scopes <scopes>', 'Comma-separated GitHub scopes')
  .option('--github-client-id <id>', 'BYOO GitHub OAuth client ID')
  .option('--github-client-secret <secret>', 'BYOO GitHub OAuth client secret')
  .option('--api-key-name <name>', 'Service API key name', 'act-provider-token-reader')
  .option('--force-new-api-key', 'Create a fresh service API key')
  .option('--write-api-key <path>', 'Write the one-time service API key to this file')
  .option('--write-client-id <path>', 'Write the ACT AuthOS client ID to this file')
  .option('--json', 'Print machine-readable JSON')
  .action(async (options) => {
    await provisionActCommand(options);
  });

program.parse();
