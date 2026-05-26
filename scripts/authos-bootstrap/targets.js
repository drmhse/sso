const PLATFORM_TARGETS = {
  'linux/amd64': {
    rustTarget: 'x86_64-unknown-linux-musl',
    archiveArch: 'amd64',
  },
  'linux/arm64': {
    rustTarget: 'aarch64-unknown-linux-musl',
    archiveArch: 'arm64',
  },
  'linux/arm64/v8': {
    rustTarget: 'aarch64-unknown-linux-musl',
    archiveArch: 'arm64',
  },
};

function resolvePlatformTarget(platform) {
  const normalized = String(platform || '').trim();
  const target = PLATFORM_TARGETS[normalized];
  if (!target) {
    throw new Error(
      `Unsupported deployment.platform "${platform}". Supported values: ${Object.keys(PLATFORM_TARGETS).join(', ')}`,
    );
  }
  return target;
}

module.exports = {
  resolvePlatformTarget,
};
