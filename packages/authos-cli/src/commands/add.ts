import * as path from 'path';
import prompts from 'prompts';
import {
  detectFramework,
  detectStyling,
  findComponentsDir,
  getFileExtension,
  writeFile,
  fileExists,
  log,
  getFrameworkName,
  type Framework,
  type StylingVariant,
} from '../utils';
import { getTemplate, getAvailableTemplates } from '../templates/registry';

interface AddOptions {
  cwd?: string;
  force?: boolean;
}

/**
 * Add a component template to the project
 */
export async function addCommand(
  templateName?: string,
  options: AddOptions = {}
): Promise<void> {
  const cwd = options.cwd || process.cwd();

  // Detect framework
  let framework = detectFramework(cwd);

  if (framework === 'unknown') {
    log.warn('Could not detect project framework from package.json.');

    const response = await prompts({
      type: 'select',
      name: 'framework',
      message: 'Select your framework:',
      choices: [
        { title: 'React', value: 'react' },
        { title: 'Next.js', value: 'next' },
        { title: 'Vue', value: 'vue' },
        { title: 'Nuxt', value: 'nuxt' },
      ],
    });

    if (!response.framework) {
      log.error('Command cancelled.');
      process.exit(1);
    }

    framework = response.framework as Framework;
  } else {
    log.info(`Detected ${getFrameworkName(framework)} project`);
  }

  // Detect styling preference
  let styling = detectStyling(cwd);

  if (styling === 'unknown') {
    const response = await prompts({
      type: 'select',
      name: 'styling',
      message: 'How do you want to style this component?',
      choices: [
        { title: 'Tailwind CSS (utility classes)', value: 'tailwind' },
        { title: 'CSS Modules (.module.css)', value: 'css-modules' },
        { title: 'Unstyled (headless)', value: 'none' },
      ],
    });

    if (!response.styling) {
      log.error('Command cancelled.');
      process.exit(1);
    }

    styling = response.styling as StylingVariant;
  } else {
    log.info(`Using Tailwind CSS styling (detected)`);
  }

  // If no template specified, show selection
  if (!templateName) {
    const availableTemplates = getAvailableTemplates();
    const choices = availableTemplates.map((name) => {
      const template = getTemplate(name)!;
      return {
        title: template.name,
        description: template.description,
        value: name,
      };
    });

    const response = await prompts({
      type: 'select',
      name: 'template',
      message: 'Select a component to add:',
      choices,
    });

    if (!response.template) {
      log.error('Command cancelled.');
      process.exit(1);
    }

    templateName = response.template;
  }

  // Get the template (templateName is guaranteed to be defined at this point)
  const template = getTemplate(templateName!);

  if (!template) {
    log.error(`Unknown template: ${templateName}`);
    console.log('\nAvailable templates:');
    for (const name of getAvailableTemplates()) {
      const t = getTemplate(name)!;
      console.log(`  - ${name}: ${t.description}`);
    }
    process.exit(1);
  }

  // Find components directory
  const componentsDir = findComponentsDir(cwd);
  const extension = getFileExtension(framework);

  log.info(`Adding ${template.name}...`);

  // Write each file
  for (const file of template.files) {
    const fileName = `${file.name}${extension}`;
    const filePath = path.join(componentsDir, fileName);

    // Check if file exists
    if (fileExists(filePath) && !options.force) {
      const response = await prompts({
        type: 'confirm',
        name: 'overwrite',
        message: `${fileName} already exists. Overwrite?`,
        initial: false,
      });

      if (!response.overwrite) {
        log.warn(`Skipped ${fileName}`);
        continue;
      }
    }

    // Get content for styling variant AND framework, with fallbacks
    const content = file.content[styling]?.[framework] 
      ?? file.content['none']?.[framework]
      ?? '';

    // Write the file
    writeFile(filePath, content);
    log.success(`Created ${path.relative(cwd, filePath)}`);

    // Write extra files if the variant has them (e.g., .module.css for CSS modules)
    const extraFiles = file.extraFiles?.[styling];
    if (extraFiles) {
      for (const extra of extraFiles) {
        const extraPath = path.join(componentsDir, extra.name);

        // Check if extra file exists
        if (fileExists(extraPath) && !options.force) {
          const response = await prompts({
            type: 'confirm',
            name: 'overwrite',
            message: `${extra.name} already exists. Overwrite?`,
            initial: false,
          });

          if (!response.overwrite) {
            log.warn(`Skipped ${extra.name}`);
            continue;
          }
        }

        writeFile(extraPath, extra.content);
        log.success(`Created ${path.relative(cwd, extraPath)}`);
      }
    }
  }

  console.log('\n');
  log.success(`Added ${template.name} component!`);

  // Print usage instructions
  console.log('\nUsage:\n');

  if (framework === 'react' || framework === 'next') {
    console.log(`  import { ${template.files[0].name} } from "@/components/${template.files[0].name}";`);
    console.log('');
    console.log(`  <${template.files[0].name} />`);
  } else {
    console.log(`  <script setup>`);
    console.log(`  import ${template.files[0].name} from "@/components/${template.files[0].name}.vue";`);
    console.log(`  </script>`);
    console.log('');
    console.log(`  <${template.files[0].name} />`);
  }

  console.log('\n');
}
