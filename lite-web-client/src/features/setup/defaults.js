export const DEFAULT_CONFIG = {
  deployment: {
    project: 'authos',
    backend: 'sqlite',
    image: 'authos-local:sqlite-bootstrap',
    buildLocalImage: true,
    platform: 'linux/amd64',
    apiPort: 3001,
    baseUrl: 'http://localhost:3001',
    platformBaseUrl: 'http://localhost:3001',
    fullWebClientBaseUrl: '',
    trustProxyHeaders: false,
    trustedProxyIps: '',
    disableRateLimiting: false,
    geoipDisabled: true,
    jobProcessorIntervalSecs: 10,
    jobProcessorBatchSize: 10,
  },
  standalone: {
    dataDir: '/var/lib/authos',
  },
  caddy: {
    enabled: false,
    install: false,
    domain: '',
    email: '',
    tls: 'auto',
  },
  platformOwner: {
    email: 'admin@example.com',
    password: '',
  },
  billing: {
    provider: 'stripe',
    stripeSecretKey: '',
    stripeWebhookSecret: '',
    stripeWebhookTestMode: true,
  },
  smtp: {
    mode: 'mailpit',
    fromEmail: 'noreply@authos.local',
    fromName: 'AuthOS',
  },
  oauth: {
    github: {
      clientId: '',
      clientSecret: '',
    },
    google: {
      clientId: '',
      clientSecret: '',
    },
    microsoft: {
      clientId: '',
      clientSecret: '',
    },
  },
  services: [
    {
      org: 'demo',
      orgName: 'Demo',
      service: 'demo-app',
      name: 'Demo App',
      type: 'web',
      redirectUris: ['http://localhost:3001/callback'],
      githubScopes: ['read:user', 'user:email'],
      apiKeys: [
        {
          name: 'demo-server',
          permissions: ['read:provider_tokens:github'],
          writeTo: '.authos/demo-server-api-key.env',
        },
      ],
    },
  ],
  outputs: {
    directory: '.authos',
    apiEnv: 'api/.env',
  },
};

export const TOP_LEVEL_KEYS = [
  'deployment',
  'standalone',
  'caddy',
  'platformOwner',
  'billing',
  'smtp',
  'oauth',
  'services',
  'outputs',
];

export const DEPLOYMENT_KEYS = [
  'project',
  'backend',
  'image',
  'buildLocalImage',
  'platform',
  'apiPort',
  'baseUrl',
  'platformBaseUrl',
  'fullWebClientBaseUrl',
  'trustProxyHeaders',
  'trustedProxyIps',
  'disableRateLimiting',
  'geoipDisabled',
  'jobProcessorIntervalSecs',
  'jobProcessorBatchSize',
];

export const STANDALONE_KEYS = ['dataDir'];
export const CADDY_KEYS = ['enabled', 'install', 'domain', 'email', 'tls'];
export const PLATFORM_OWNER_KEYS = ['email', 'password'];
export const BILLING_KEYS = ['provider', 'stripeSecretKey', 'stripeWebhookSecret', 'stripeWebhookTestMode'];
export const SMTP_KEYS = ['mode', 'fromEmail', 'fromName'];
export const OAUTH_PROVIDER_KEYS = ['clientId', 'clientSecret'];
export const OUTPUT_KEYS = ['directory', 'apiEnv'];
export const SERVICE_KEYS = ['org', 'orgName', 'service', 'name', 'type', 'redirectUris', 'githubScopes', 'apiKeys'];
export const API_KEY_KEYS = ['name', 'permissions', 'writeTo'];

export function createEmptyApiKey() {
  return {
    name: '',
    permissions: [],
    writeTo: '',
  };
}

export function createEmptyService() {
  return {
    org: '',
    orgName: '',
    service: '',
    name: '',
    type: 'web',
    redirectUris: [],
    githubScopes: [],
    apiKeys: [],
  };
}
