import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const entitiesDir = path.resolve('api/src/entities');
const sensitiveField = /(?:^|_)(?:password_hash|token_hash|client_secret_hash|private_key_encrypted|secret_encrypted|client_secret_encrypted|access_token_encrypted|refresh_token_encrypted|smtp_password_encrypted|api_key_encrypted|webhook_secret_encrypted|access_token|refresh_token|verification_token|api_key|auth_header|encryption_key_id|secret|token)$/;
const failures = [];

for (const entry of fs.readdirSync(entitiesDir, { withFileTypes: true })) {
  if (!entry.isFile() || !entry.name.endsWith('.rs')) continue;
  const file = path.join(entitiesDir, entry.name);
  const source = fs.readFileSync(file, 'utf8');
  if (!/derive\([^)]*Serialize/.test(source)) continue;

  const lines = source.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(/^\s*pub\s+(\w+)\s*:/);
    if (!match || !sensitiveField.test(match[1])) continue;
    const attributes = lines.slice(Math.max(0, index - 4), index).join('\n');
    if (!attributes.includes('#[serde(skip_serializing)]')) {
      failures.push(`${path.relative(process.cwd(), file)}:${index + 1} ${match[1]}`);
    }
  }
}

if (failures.length > 0) {
  console.error('Serializable entity secrets must be marked #[serde(skip_serializing)]:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log('Entity secret-serialization policy passed.');
