/**
 * AuthOS CLI - Scaffolding tool for AuthOS integrations
 *
 * @packageDocumentation
 */

export { initCommand, addCommand, provisionActCommand } from './commands';
export { getTemplate, getAvailableTemplates } from './templates/registry';
export type { Template, TemplateFile } from './templates/registry';
export {
  detectFramework,
  getAdapterPackage,
  getFrameworkName,
  type Framework,
} from './utils';
