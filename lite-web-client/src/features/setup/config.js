import {
  API_KEY_KEYS,
  BILLING_KEYS,
  CADDY_KEYS,
  DEFAULT_CONFIG,
  DEPLOYMENT_KEYS,
  OAUTH_PROVIDER_KEYS,
  PLATFORM_OWNER_KEYS,
  SERVICE_KEYS,
  SMTP_KEYS,
  STANDALONE_KEYS,
  TOP_LEVEL_KEYS,
  createEmptyApiKey,
  createEmptyService,
} from './defaults';
import { validateManagedConfig as validateSerializedConfig } from './validate';

export { createEmptyApiKey, createEmptyService } from './defaults';

export function normalizeManagedConfig(source = {}) {
  const config = {
    ...cloneData(DEFAULT_CONFIG),
    ...cloneData(source || {}),
  };

  config.deployment = {
    ...cloneData(DEFAULT_CONFIG.deployment),
    ...(source?.deployment || {}),
  };
  config.standalone = {
    ...cloneData(DEFAULT_CONFIG.standalone),
    ...(source?.standalone || {}),
  };
  config.caddy = {
    ...cloneData(DEFAULT_CONFIG.caddy),
    ...(source?.caddy || {}),
  };
  config.platformOwner = {
    ...cloneData(DEFAULT_CONFIG.platformOwner),
    ...(source?.platformOwner || {}),
  };
  config.billing = {
    ...cloneData(DEFAULT_CONFIG.billing),
    ...(source?.billing || {}),
  };
  config.smtp = {
    ...cloneData(DEFAULT_CONFIG.smtp),
    ...(source?.smtp || {}),
  };
  config.oauth = {
    ...cloneData(DEFAULT_CONFIG.oauth),
    ...(source?.oauth || {}),
    github: {
      ...cloneData(DEFAULT_CONFIG.oauth.github),
      ...(source?.oauth?.github || {}),
    },
    google: {
      ...cloneData(DEFAULT_CONFIG.oauth.google),
      ...(source?.oauth?.google || {}),
    },
    microsoft: {
      ...cloneData(DEFAULT_CONFIG.oauth.microsoft),
      ...(source?.oauth?.microsoft || {}),
    },
  };
  config.services = Array.isArray(source?.services) && source.services.length > 0
    ? source.services.map(normalizeService)
    : cloneData(DEFAULT_CONFIG.services).map(normalizeService);

  return config;
}

export function serializeManagedConfig(form) {
  const config = cloneData(form || {});
  const extraTopLevel = omitKnownKeys(config, TOP_LEVEL_KEYS);

  const deployment = orderedObject(
    DEPLOYMENT_KEYS,
    {
      ...config.deployment,
      backend: 'sqlite',
      apiPort: parsePositiveInt(config.deployment?.apiPort, DEFAULT_CONFIG.deployment.apiPort),
      baseUrl: trimString(config.deployment?.baseUrl),
      platformBaseUrl: trimString(config.deployment?.platformBaseUrl),
      fullWebClientBaseUrl: trimString(config.deployment?.fullWebClientBaseUrl),
      trustProxyHeaders: Boolean(config.deployment?.trustProxyHeaders),
      trustedProxyIps: trimString(config.deployment?.trustedProxyIps),
      disableRateLimiting: Boolean(config.deployment?.disableRateLimiting),
      geoipDisabled: Boolean(config.deployment?.geoipDisabled),
      jobProcessorIntervalSecs: parsePositiveInt(
        config.deployment?.jobProcessorIntervalSecs,
        DEFAULT_CONFIG.deployment.jobProcessorIntervalSecs,
      ),
      jobProcessorBatchSize: parsePositiveInt(
        config.deployment?.jobProcessorBatchSize,
        DEFAULT_CONFIG.deployment.jobProcessorBatchSize,
      ),
    },
  );

  const standalone = orderedObject(
    STANDALONE_KEYS,
    {
      ...omitKnownKeys(config.standalone || {}, ['serviceName']),
      dataDir: trimString(config.standalone?.dataDir || DEFAULT_CONFIG.standalone.dataDir),
    },
  );

  const caddy = orderedObject(
    CADDY_KEYS,
    {
      ...config.caddy,
      enabled: Boolean(config.caddy?.enabled),
      install: Boolean(config.caddy?.install),
      domain: trimString(config.caddy?.domain),
      email: trimString(config.caddy?.email),
      tls: normalizeTlsMode(config.caddy?.tls),
    },
  );

  const platformOwner = orderedObject(
    PLATFORM_OWNER_KEYS,
    {
      ...config.platformOwner,
      email: trimString(config.platformOwner?.email),
      password: trimString(config.platformOwner?.password),
    },
  );

  const billing = orderedObject(
    BILLING_KEYS,
    {
      ...config.billing,
      provider: trimString(config.billing?.provider || DEFAULT_CONFIG.billing.provider),
      stripeSecretKey: trimString(config.billing?.stripeSecretKey),
      stripeWebhookSecret: trimString(config.billing?.stripeWebhookSecret),
      stripeWebhookTestMode: Boolean(config.billing?.stripeWebhookTestMode),
    },
  );

  const smtp = orderedObject(
    SMTP_KEYS,
    {
      ...config.smtp,
      mode: trimString(config.smtp?.mode || DEFAULT_CONFIG.smtp.mode),
      fromEmail: trimString(config.smtp?.fromEmail),
      fromName: trimString(config.smtp?.fromName),
    },
  );

  const oauth = {
    ...omitKnownKeys(config.oauth || {}, ['github', 'google', 'microsoft']),
    github: orderedObject(
      OAUTH_PROVIDER_KEYS,
      {
        ...config.oauth?.github,
        clientId: trimString(config.oauth?.github?.clientId),
        clientSecret: trimString(config.oauth?.github?.clientSecret),
      },
    ),
    google: orderedObject(
      OAUTH_PROVIDER_KEYS,
      {
        ...config.oauth?.google,
        clientId: trimString(config.oauth?.google?.clientId),
        clientSecret: trimString(config.oauth?.google?.clientSecret),
      },
    ),
    microsoft: orderedObject(
      OAUTH_PROVIDER_KEYS,
      {
        ...config.oauth?.microsoft,
        clientId: trimString(config.oauth?.microsoft?.clientId),
        clientSecret: trimString(config.oauth?.microsoft?.clientSecret),
      },
    ),
  };

  const services = Array.isArray(config.services)
    ? config.services.map((service) => orderedObject(
      SERVICE_KEYS,
      {
        ...service,
        org: trimString(service?.org),
        orgName: trimString(service?.orgName),
        service: trimString(service?.service),
        name: trimString(service?.name),
        type: trimString(service?.type || 'web'),
        redirectUris: sanitizeStringArray(service?.redirectUris),
        githubScopes: sanitizeStringArray(service?.githubScopes),
        apiKeys: Array.isArray(service?.apiKeys)
          ? service.apiKeys.map((apiKey) => orderedObject(
            API_KEY_KEYS,
            {
              ...apiKey,
              name: trimString(apiKey?.name),
              permissions: sanitizeStringArray(apiKey?.permissions),
              writeTo: trimString(apiKey?.writeTo),
            },
          ))
          : [],
      },
    ))
    : [];

  return {
    deployment,
    standalone,
    caddy,
    platformOwner,
    billing,
    smtp,
    oauth,
    services,
    ...extraTopLevel,
  };
}

export function validateManagedConfig(form) {
  return validateSerializedConfig(serializeManagedConfig(form));
}

function normalizeService(service = {}) {
  return {
    ...createEmptyService(),
    ...cloneData(service),
    type: service?.type || 'web',
    redirectUris: sanitizeStringArray(service?.redirectUris),
    githubScopes: sanitizeStringArray(service?.githubScopes),
    apiKeys: Array.isArray(service?.apiKeys)
      ? service.apiKeys.map((apiKey) => ({
        ...createEmptyApiKey(),
        ...cloneData(apiKey),
        permissions: sanitizeStringArray(apiKey?.permissions),
      }))
      : [],
  };
}

function cloneData(value) {
  return JSON.parse(JSON.stringify(value));
}

function orderedObject(keys, source) {
  const extra = omitKnownKeys(source, keys);
  const ordered = {};

  keys.forEach((key) => {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      ordered[key] = source[key];
    }
  });

  return {
    ...ordered,
    ...extra,
  };
}

function omitKnownKeys(source = {}, keys = []) {
  return Object.fromEntries(
    Object.entries(source || {}).filter(([key]) => !keys.includes(key)),
  );
}

function sanitizeStringArray(values) {
  if (!Array.isArray(values)) return [];
  return values
    .map((value) => trimString(value))
    .filter(Boolean);
}

function trimString(value) {
  return String(value ?? '').trim();
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function normalizeTlsMode(value) {
  return ['auto', 'internal', 'disabled'].includes(value) ? value : 'auto';
}
