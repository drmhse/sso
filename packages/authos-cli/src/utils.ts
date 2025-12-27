import * as fs from 'fs';
import * as path from 'path';
import pc from 'picocolors';

export type Framework = 'react' | 'vue' | 'next' | 'nuxt' | 'unknown';
export type StylingVariant = 'tailwind' | 'css-modules' | 'none';

interface PackageJson {
  name?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

/**
 * Detect the project framework from package.json
 */
export function detectFramework(cwd: string): Framework {
  const packageJsonPath = path.join(cwd, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return 'unknown';
  }

  try {
    const content = fs.readFileSync(packageJsonPath, 'utf8');
    const pkg: PackageJson = JSON.parse(content);
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };

    // Check for meta-frameworks first (they include base frameworks)
    if (deps['nuxt'] || deps['nuxt3']) {
      return 'nuxt';
    }
    if (deps['next']) {
      return 'next';
    }
    if (deps['vue']) {
      return 'vue';
    }
    if (deps['react']) {
      return 'react';
    }

    return 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * Get the package name for the detected framework
 */
export function getAdapterPackage(framework: Framework): string | null {
  switch (framework) {
    case 'react':
    case 'next':
      return '@drmhse/authos-react';
    case 'vue':
    case 'nuxt':
      return '@drmhse/authos-vue';
    default:
      return null;
  }
}

/**
 * Read package.json from a directory
 */
export function readPackageJson(cwd: string): PackageJson | null {
  const packageJsonPath = path.join(cwd, 'package.json');

  if (!fs.existsSync(packageJsonPath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(packageJsonPath, 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Write content to a file, creating directories if needed
 */
export function writeFile(filePath: string, content: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, content, 'utf8');
}

/**
 * Check if a file exists
 */
export function fileExists(filePath: string): boolean {
  return fs.existsSync(filePath);
}

/**
 * Append content to a file or create it if it doesn't exist
 */
export function appendToFile(filePath: string, content: string): void {
  if (fs.existsSync(filePath)) {
    const existing = fs.readFileSync(filePath, 'utf8');
    if (!existing.includes(content.trim())) {
      fs.appendFileSync(filePath, '\n' + content);
    }
  } else {
    writeFile(filePath, content);
  }
}

/**
 * Find the components directory in a project
 */
export function findComponentsDir(cwd: string): string {
  // Common locations for components
  const candidates = [
    'src/components',
    'components',
    'app/components',
    'src/app/components',
  ];

  for (const candidate of candidates) {
    const fullPath = path.join(cwd, candidate);
    if (fs.existsSync(fullPath)) {
      return fullPath;
    }
  }

  // Default to src/components
  return path.join(cwd, 'src', 'components');
}

/**
 * Get file extension for framework
 */
export function getFileExtension(framework: Framework): string {
  switch (framework) {
    case 'vue':
    case 'nuxt':
      return '.vue';
    case 'react':
    case 'next':
    default:
      return '.tsx';
  }
}

/**
 * Log messages with consistent styling
 */
export const log = {
  info: (msg: string) => console.log(pc.blue('i'), msg),
  success: (msg: string) => console.log(pc.green('✓'), msg),
  warn: (msg: string) => console.log(pc.yellow('!'), msg),
  error: (msg: string) => console.log(pc.red('✗'), msg),
  step: (msg: string) => console.log(pc.cyan('→'), msg),
};

/**
 * Get the framework display name
 */
export function getFrameworkName(framework: Framework): string {
  switch (framework) {
    case 'react':
      return 'React';
    case 'vue':
      return 'Vue';
    case 'next':
      return 'Next.js';
    case 'nuxt':
      return 'Nuxt';
    default:
      return 'Unknown';
  }
}

/**
 * Detect if Tailwind CSS is installed in the project
 */
export function detectTailwind(cwd: string): boolean {
  const packageJson = readPackageJson(cwd);
  if (!packageJson) return false;

  const deps = { ...packageJson.dependencies, ...packageJson.devDependencies };

  // Check for Tailwind CSS package
  return !!(
    deps['tailwindcss'] ||
    deps['@tailwindcss/vite'] ||
    deps['@tailwindcss/typography']
  );
}

/**
 * Check if Tailwind config file exists
 */
export function hasTailwindConfig(cwd: string): boolean {
  const configFiles = [
    'tailwind.config.js',
    'tailwind.config.ts',
    'tailwind.config.cjs',
    'tailwind.config.mjs',
    'tailwind.config.cts',
  ];

  return configFiles.some((file) => fs.existsSync(path.join(cwd, file)));
}

/**
 * Verify Tailwind CSS is properly configured
 * Returns true if Tailwind is installed AND has a config file
 */
export function isTailwindConfigured(cwd: string): boolean {
  return detectTailwind(cwd) || hasTailwindConfig(cwd);
}

/**
 * Detect the styling strategy in the project
 * Returns the detected styling variant or 'unknown' if unable to determine
 */
export function detectStyling(cwd: string): StylingVariant | 'unknown' {
  // If Tailwind is configured, return 'tailwind'
  if (isTailwindConfigured(cwd)) {
    return 'tailwind';
  }
  // Otherwise, we can't auto-detect - will prompt user
  return 'unknown';
}

