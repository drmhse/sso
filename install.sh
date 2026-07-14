#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail

REPO_SLUG="drmhse/AuthOS"
RELEASE_TAG="${AUTHOS_RELEASE_TAG:-}"
ARCH_OVERRIDE="${AUTHOS_ARCH:-}"
AUTHOS_TEMP_DIR=""

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
  require_command python3
  require_command tar
  require_command mktemp
  require_command sha256sum

  local authos_arch bundle_name archive_name archive_url checksum_name checksum_url temp_dir
  authos_arch="$(detect_arch)"
  if [ -n "$RELEASE_TAG" ] && ! [[ "$RELEASE_TAG" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "AUTHOS_RELEASE_TAG must be a stable v-prefixed semantic version." >&2
    exit 1
  fi
  bundle_name="authos-sqlite-linux-${authos_arch}"
  archive_name="${bundle_name}.tar.gz"
  archive_url="$(build_release_url "$archive_name")"
  checksum_name="SHA256SUMS.txt"
  checksum_url="$(build_release_url "$checksum_name")"
  temp_dir="$(mktemp -d)"
  AUTHOS_TEMP_DIR="$temp_dir"

  cleanup() {
    if [ -n "$AUTHOS_TEMP_DIR" ]; then
      rm -rf -- "$AUTHOS_TEMP_DIR"
    fi
  }
  trap cleanup EXIT

  echo "Downloading ${archive_name}..."
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 600 \
    --max-filesize 536870912 \
    --output "${temp_dir}/${archive_name}" "$archive_url"
  curl --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 60 \
    --max-filesize 65536 \
    --output "${temp_dir}/${checksum_name}" "$checksum_url"

  echo "Verifying ${archive_name}..."
  local checksum_line
  checksum_line="$(python3 - "${temp_dir}/${checksum_name}" "$archive_name" <<'PY'
import re
import sys
from pathlib import Path

checksum_path, archive_name = sys.argv[1:]
if Path(checksum_path).stat().st_size > 65536:
    raise SystemExit("Release checksum file exceeds its size limit")
pattern = re.compile(rf"^[0-9a-f]{{64}}  {re.escape(archive_name)}$")
matches = [
    line
    for line in Path(checksum_path).read_text(encoding="utf-8").splitlines()
    if pattern.fullmatch(line)
]
if len(matches) != 1:
    raise SystemExit(
        f"Release checksums do not contain exactly one canonical entry for {archive_name}"
    )
print(matches[0])
PY
)"
  (cd "$temp_dir" && printf '%s\n' "$checksum_line" | sha256sum --check --strict)

  python3 - "${temp_dir}/${archive_name}" "$bundle_name" <<'PY'
import sys
import tarfile
from pathlib import PurePosixPath

archive_path, bundle_name = sys.argv[1:]
maximum_members = 256
maximum_expanded_bytes = 1024 * 1024 * 1024
required_files = {
    "authos",
    "authos.config.example.json",
    "LICENSE",
    "AGPL-3.0.txt",
    "install.sh",
    "README.txt",
    "standalone/authos_standalone.py",
}

with tarfile.open(archive_path, mode="r:gz") as archive:
    members = archive.getmembers()
    if not members or len(members) > maximum_members:
        raise SystemExit("AuthOS archive has an invalid member count")
    if sum(max(member.size, 0) for member in members) > maximum_expanded_bytes:
        raise SystemExit("AuthOS archive exceeds the expanded-size limit")

    observed_names = set()
    observed_files = set()
    for member in members:
        if member.name in observed_names:
            raise SystemExit(f"AuthOS archive duplicates a member: {member.name}")
        observed_names.add(member.name)
        raw_name = member.name.rstrip("/") if member.isdir() else member.name
        raw_parts = raw_name.split("/")
        if any(part in {"", ".", ".."} for part in raw_parts):
            raise SystemExit(f"AuthOS archive contains an unsafe path: {member.name}")
        member_path = PurePosixPath(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise SystemExit(f"AuthOS archive contains an unsafe path: {member.name}")
        if member.isdev() or member.isfifo() or member.issym() or member.islnk():
            raise SystemExit(f"AuthOS archive contains an unsupported member: {member.name}")
        if not member_path.parts or member_path.parts[0] != bundle_name:
            raise SystemExit(f"AuthOS archive member escapes its bundle root: {member.name}")
        relative = PurePosixPath(*member_path.parts[1:])
        if member.isfile():
            observed_files.add(str(relative))

    if observed_files != required_files:
        missing = sorted(required_files - observed_files)
        unexpected = sorted(observed_files - required_files)
        raise SystemExit(
            f"AuthOS archive inventory mismatch; missing={missing}, unexpected={unexpected}"
        )
PY

  echo "Extracting ${archive_name}..."
  tar --extract --gzip --file "${temp_dir}/${archive_name}" --directory "$temp_dir" \
    --no-same-owner --no-same-permissions

  "${temp_dir}/${bundle_name}/install.sh" "$@"
}

main "$@"
