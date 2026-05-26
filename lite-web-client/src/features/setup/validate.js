export function validateManagedConfig(config) {
  const errors = [];

  if (!isValidEmail(config.platformOwner.email)) {
    errors.push('Platform owner email must be a valid email address.');
  }
  if (!isValidUrl(config.deployment.baseUrl)) {
    errors.push('Base URL must be a valid absolute URL.');
  }
  if (!isValidUrl(config.deployment.platformBaseUrl)) {
    errors.push('Platform base URL must be a valid absolute URL.');
  }
  if (config.deployment.fullWebClientBaseUrl && !isValidUrl(config.deployment.fullWebClientBaseUrl)) {
    errors.push('Full web client URL must be a valid absolute URL when provided.');
  }
  if (config.deployment.apiPort < 1 || config.deployment.apiPort > 65535) {
    errors.push('API port must be between 1 and 65535.');
  }
  if (config.deployment.jobProcessorIntervalSecs < 1) {
    errors.push('Job processor interval must be at least 1 second.');
  }
  if (config.deployment.jobProcessorBatchSize < 1) {
    errors.push('Job processor batch size must be at least 1.');
  }
  if (!isAbsolutePath(config.standalone.dataDir)) {
    errors.push('Standalone data directory must be an absolute path.');
  }
  if (config.caddy.enabled && !config.caddy.domain) {
    errors.push('Caddy domain is required when Caddy is enabled.');
  }
  if (config.caddy.enabled && config.caddy.tls === 'auto' && !isValidEmail(config.caddy.email)) {
    errors.push('Caddy email must be a valid email address when automatic TLS is enabled.');
  }
  if (config.smtp.fromEmail && !isValidEmail(config.smtp.fromEmail)) {
    errors.push('SMTP from email must be a valid email address.');
  }

  const serviceSlugs = new Set();
  config.services.forEach((service, index) => {
    const label = `Service ${index + 1}`;
    if (!service.org) {
      errors.push(`${label}: organization slug is required.`);
    }
    if (!service.service) {
      errors.push(`${label}: application slug is required.`);
    }
    if (!service.name) {
      errors.push(`${label}: application name is required.`);
    }
    if (serviceSlugs.has(service.service)) {
      errors.push(`${label}: application slug must be unique.`);
    }
    serviceSlugs.add(service.service);
    if (!service.redirectUris.length) {
      errors.push(`${label}: at least one redirect URI is required.`);
    }
    service.redirectUris.forEach((uri) => {
      if (!isValidUrl(uri)) {
        errors.push(`${label}: "${uri}" is not a valid redirect URI.`);
      }
    });

    const apiKeyNames = new Set();
    service.apiKeys.forEach((apiKey, apiKeyIndex) => {
      const apiKeyLabel = `${label} API key ${apiKeyIndex + 1}`;
      if (!apiKey.name) {
        errors.push(`${apiKeyLabel}: name is required.`);
      }
      if (apiKeyNames.has(apiKey.name)) {
        errors.push(`${apiKeyLabel}: name must be unique within the service.`);
      }
      apiKeyNames.add(apiKey.name);
      if (!apiKey.permissions.length) {
        errors.push(`${apiKeyLabel}: at least one permission is required.`);
      }
    });
  });

  return errors;
}

function isValidEmail(value) {
  if (!value) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isValidUrl(value) {
  if (!value) return false;
  try {
    new URL(value);
    return true;
  } catch (error) {
    return false;
  }
}

function isAbsolutePath(value) {
  return typeof value === 'string' && value.startsWith('/');
}
