#!/usr/bin/env bash
set -euo pipefail

REPO_SLUG="drmhse/AuthOS"
RELEASE_TAG="${AUTHOS_RELEASE_TAG:-}"
ARCH_OVERRIDE="${AUTHOS_ARCH:-}"

detect_arch() {
  local machine
  machine="${ARCH_OVERRIDE:-$(uname -m)}"
  case "$machine" in
    x86_64|amd64)
      printf '%s\n' "amd64"
      ;;
    aarch64|arm64)
      printf '%s\n' "arm64"
      ;;
    *)
      echo "Unsupported architecture: $machine" >&2
      exit 1
      ;;
  esac
}

build_release_url() {
  local asset="$1"
  if [ -n "$RELEASE_TAG" ]; then
    printf 'https://github.com/%s/releases/download/%s/%s\n' "$REPO_SLUG" "$RELEASE_TAG" "$asset"
  else
    printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO_SLUG" "$asset"
  fi
}

require_command() {
  local command_name="$1"
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    exit 1
  fi
}

main() {
  require_command curl
  require_command tar
  require_command mktemp

  local authos_arch bundle_name archive_name archive_url temp_dir
  authos_arch="$(detect_arch)"
  bundle_name="authos-sqlite-linux-${authos_arch}"
  archive_name="${bundle_name}.tar.gz"
  archive_url="$(build_release_url "$archive_name")"
  temp_dir="$(mktemp -d)"

  cleanup() {
    rm -rf "$temp_dir"
  }
  trap cleanup EXIT

  echo "Downloading ${archive_name}..."
  curl -fsSL -o "${temp_dir}/${archive_name}" "$archive_url"

  echo "Extracting ${archive_name}..."
  tar -xzf "${temp_dir}/${archive_name}" -C "$temp_dir"

  exec "${temp_dir}/${bundle_name}/install.sh" "$@"
}

main "$@"
