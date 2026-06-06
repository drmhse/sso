import * as path from 'path';
import prompts from 'prompts';
import { execSync } from 'child_process';
import {
  detectFramework,
  getAdapterPackage,
  appendToFile,
  fileExists,
  log,
  getFrameworkName,
  type Framework,
} from '../utils';

interface InitOptions {
  cwd?: string;
  skipInstall?: boolean;
}

/**
 * Initialize AuthOS in the current project
 */
export async function initCommand(options: InitOptions = {}): Promise<void> {
  const cwd = options.cwd || process.cwd();

  log.info('Initializing AuthOS...\n');

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
      log.error('Initialization cancelled.');
      process.exit(1);
    }

    framework = response.framework as Framework;
  } else {
    log.success(`Detected ${getFrameworkName(framework)} project`);
  }

  // Get the adapter package
  const adapterPackage = getAdapterPackage(framework);

  if (!adapterPackage) {
    log.error('Unsupported framework.');
    process.exit(1);
  }

  // Ask for base URL
  const urlResponse = await prompts({
    type: 'text',
    name: 'baseUrl',
    message: 'Enter your AuthOS base URL:',
    initial: 'http://localhost:3001',
    validate: (value) => {
      try {
        new URL(value);
        return true;
      } catch {
        return 'Please enter a valid URL';
      }
    },
  });

  if (!urlResponse.baseUrl) {
    log.error('Initialization cancelled.');
    process.exit(1);
  }

  const baseUrl = urlResponse.baseUrl;

  // Install the adapter package
  if (!options.skipInstall) {
    log.step(`Installing ${adapterPackage}...`);

    try {
      // Detect package manager
      const packageManager = detectPackageManager(cwd);
      const installCmd = getInstallCommand(packageManager, adapterPackage);

      execSync(installCmd, { cwd, stdio: 'inherit' });
      log.success(`Installed ${adapterPackage}`);
    } catch (error) {
      log.error(`Failed to install ${adapterPackage}`);
      log.info(`You can install it manually: npm install ${adapterPackage}`);
    }
  }

  // Create/update .env file
  const envPath = path.join(cwd, '.env');
  const envLocalPath = path.join(cwd, '.env.local');
  const envContent = envContentForFramework(framework, baseUrl);

  // Prefer .env.local for Next.js/Nuxt
  const targetEnvPath = framework === 'next' || framework === 'nuxt' ? envLocalPath : envPath;

  if (fileExists(targetEnvPath)) {
    appendToFile(targetEnvPath, envContent);
    log.success(`Updated ${path.basename(targetEnvPath)}`);
  } else {
    appendToFile(targetEnvPath, envContent);
    log.success(`Created ${path.basename(targetEnvPath)}`);
  }

  // Print next steps
  console.log('\n');
  log.success('AuthOS initialized successfully!\n');

  console.log('Next steps:\n');

  if (framework === 'react' || framework === 'next') {
    console.log('  1. Wrap your app with AuthOSProvider:\n');
    console.log('     import { AuthOSProvider } from "@drmhse/authos-react";');
    console.log('');
    if (framework === 'next') {
      console.log('     <AuthOSProvider config={{ baseURL: process.env.NEXT_PUBLIC_AUTHOS_URL! }}>');
    } else {
      console.log('     <AuthOSProvider config={{ baseURL: import.meta.env.VITE_AUTHOS_BASE_URL }}>');
    }
    console.log('       <App />');
    console.log('     </AuthOSProvider>\n');
  } else if (framework === 'vue' || framework === 'nuxt') {
    console.log('  1. Install the Vue plugin:\n');
    console.log('     import { createAuthOS } from "@drmhse/authos-vue";');
    console.log('');
    console.log('     app.use(createAuthOS({');
    if (framework === 'nuxt') {
      console.log('       baseURL: useRuntimeConfig().public.authosBaseUrl,');
    } else {
      console.log('       baseURL: import.meta.env.VITE_AUTHOS_BASE_URL,');
    }
    console.log('     }));\n');
  }

  console.log('  2. Add authentication components:');
  console.log('     npx authos add login-form');
  console.log('     npx authos add user-profile\n');

  console.log('  3. Check out the docs: https://authos.dev/docs\n');
}

/**
 * Detect the package manager being used
 */
function detectPackageManager(cwd: string): 'npm' | 'yarn' | 'pnpm' | 'bun' {
  if (fileExists(path.join(cwd, 'bun.lockb'))) {
    return 'bun';
  }
  if (fileExists(path.join(cwd, 'pnpm-lock.yaml'))) {
    return 'pnpm';
  }
  if (fileExists(path.join(cwd, 'yarn.lock'))) {
    return 'yarn';
  }
  return 'npm';
}

function envContentForFramework(framework: Framework, baseUrl: string): string {
  switch (framework) {
    case 'next':
      return `AUTHOS_BASE_URL=${baseUrl}\nNEXT_PUBLIC_AUTHOS_URL=${baseUrl}\n`;
    case 'nuxt':
      return `AUTHOS_BASE_URL=${baseUrl}\nNUXT_PUBLIC_AUTHOS_BASE_URL=${baseUrl}\n`;
    case 'react':
    case 'vue':
      return `AUTHOS_BASE_URL=${baseUrl}\nVITE_AUTHOS_BASE_URL=${baseUrl}\n`;
    default:
      return `AUTHOS_BASE_URL=${baseUrl}\n`;
  }
}

/**
 * Get the install command for a package manager
 */
function getInstallCommand(pm: 'npm' | 'yarn' | 'pnpm' | 'bun', pkg: string): string {
  switch (pm) {
    case 'yarn':
      return `yarn add ${pkg}`;
    case 'pnpm':
      return `pnpm add ${pkg}`;
    case 'bun':
      return `bun add ${pkg}`;
    default:
      return `npm install ${pkg}`;
  }
}
