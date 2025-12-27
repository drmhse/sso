import { Command } from 'commander';
import { initCommand, addCommand } from './commands';
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

program.parse();
