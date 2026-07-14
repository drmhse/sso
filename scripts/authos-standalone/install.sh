#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

exec python3 "${SCRIPT_DIR}/authos_standalone.py" install --bundle-dir "${BUNDLE_DIR}" "$@"
