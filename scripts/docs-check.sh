#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

command -v node >/dev/null 2>&1 || {
  echo "docs-check failed: node is required" >&2
  exit 1
}

# Keep this check dependency-free so it can run before package builds and in
# release qualification. It validates first-party Markdown only; vendored and
# generated dependency trees are intentionally outside the documentation gate.
node <<'NODE'
const fs = require('node:fs');
const path = require('node:path');

const root = process.cwd();
const ignoredDirectories = new Set([
  '.git',
  'node_modules',
  'target',
  'vendor',
]);
const markdownFiles = [];

function collectMarkdown(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;

    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      collectMarkdown(absolute);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.md')) {
      markdownFiles.push(absolute);
    }
  }
}

collectMarkdown(root);
markdownFiles.sort();

if (markdownFiles.length === 0) {
  console.error('docs-check failed: no Markdown files found');
  process.exit(1);
}

const failures = [];
let relativeLinksChecked = 0;

// These are previously published quantitative or metadata claims that do not
// have reproducible evidence in this repository. Add a narrowly scoped entry
// here when a stale public claim is retired; do not ban honest roadmap text.
const staleClaims = [
  { pattern: /\b12\s*ms\b/i, label: 'unsupported 12 ms latency claim' },
  { pattern: /\b18\s*mb\b/i, label: 'unsupported 18 MB footprint claim' },
  { pattern: /\b25\s*(?:m\+?|million)\b/i, label: 'unsupported 25 million scale claim' },
  { pattern: /github\.com\/authos(?:\/|\b)/i, label: 'stale GitHub organization' },
  { pattern: /@authos-sdk\b/i, label: 'stale npm package name' },
  { pattern: /drmhse\.com\/docs\/sso/i, label: 'obsolete documentation hostname' },
  { pattern: /https:\/\/authapi\.authos\.dev/i, label: 'unpublished API hostname' },
];

function recordFailure(file, message) {
  failures.push(`${path.relative(root, file)}: ${message}`);
}

function checkDestination(file, rawDestination) {
  let destination = rawDestination.trim();
  if (destination.startsWith('<') && destination.endsWith('>')) {
    destination = destination.slice(1, -1).trim();
  } else {
    destination = destination.split(/\s+(?=["'])/, 1)[0];
  }

  if (!destination || destination.startsWith('#')) return;
  if (/^javascript:/i.test(destination)) {
    recordFailure(file, `unsafe Markdown link target ${JSON.stringify(destination)}`);
    return;
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(destination) || destination.startsWith('//')) return;
  // Root-relative links refer to the deployed documentation site, not this
  // repository's filesystem. Relative repository links are checked below.
  if (destination.startsWith('/')) return;

  const withoutFragment = destination.split('#', 1)[0].split('?', 1)[0];
  if (!withoutFragment) return;

  let decoded;
  try {
    decoded = decodeURIComponent(withoutFragment);
  } catch {
    recordFailure(file, `link target is not valid percent-encoding: ${destination}`);
    return;
  }

  relativeLinksChecked += 1;
  const target = path.resolve(path.dirname(file), decoded);
  if (!fs.existsSync(target)) {
    recordFailure(file, `relative link target does not exist: ${destination}`);
  }
}

for (const file of markdownFiles) {
  const markdown = fs.readFileSync(file, 'utf8');
  if (markdown.trim().length === 0) {
    recordFailure(file, 'Markdown file is empty');
  }

  for (const marker of ['<<<<<<<', '=======', '>>>>>>>']) {
    if (markdown.includes(marker)) recordFailure(file, `contains merge-conflict marker ${marker}`);
  }

  for (const { pattern, label } of staleClaims) {
    if (pattern.test(markdown)) recordFailure(file, `contains ${label}`);
  }

  // Inline links and images: [label](target), ![alt](target).
  for (const match of markdown.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
    checkDestination(file, match[1]);
  }
  // Reference definitions: [name]: target
  for (const match of markdown.matchAll(/^\s*\[[^\]]+\]:\s*(\S+)/gm)) {
    checkDestination(file, match[1]);
  }
}

if (failures.length > 0) {
  console.error('docs-check failed:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `docs-check passed: ${markdownFiles.length} Markdown files, ` +
    `${relativeLinksChecked} relative links, ${staleClaims.length} stale-claim rules.`,
);
NODE
