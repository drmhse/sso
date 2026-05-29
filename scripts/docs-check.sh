#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

targets=(
  README.md
  DEVELOPMENT.md
  OPERATIONS.md
  DOCS_AUDIT.md
  docs
  auth-os
  sso-sdk/README.md
  web-client/README.md
  kitchen/README.md
  test-integration/README.md
  packages
  examples
)

check_pattern() {
  local pattern="$1"
  local label="$2"
  if rg -n "$pattern" "${targets[@]}" >/tmp/authos-docs-check.out 2>/dev/null; then
    echo "docs-check failed: found banned pattern for ${label}"
    cat /tmp/authos-docs-check.out
    rm -f /tmp/authos-docs-check.out
    exit 1
  fi
  rm -f /tmp/authos-docs-check.out
}

check_pattern 'localhost:3000' 'old local API port'
check_pattern 'docker-compose' 'legacy docker compose command'
check_pattern 'docker-publish\.sh' 'removed docker publish script'
check_pattern 'github\.com/authos' 'stale repository reference'
check_pattern '@authos-sdk' 'stale package name'
check_pattern 'drmhse\.com/docs/sso' 'obsolete docs hostname'
check_pattern 'https://authapi\.authos\.dev' 'invented API hostname'

echo "Building docs site..."
hugo --source docs --gc --minify >/tmp/authos-docs-hugo.out

echo "Building microsite..."
hugo --source auth-os --gc --minify >/tmp/authos-authos-hugo.out

rm -f /tmp/authos-docs-hugo.out /tmp/authos-authos-hugo.out
echo "docs-check passed"
