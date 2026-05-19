import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import pc from 'picocolors';

interface ProvisionActOptions {
  baseUrl?: string;
  adminToken?: string;
  ownerEmail?: string;
  ownerPassword?: string;
  org?: string;
  orgName?: string;
  service?: string;
  name?: string;
  actUrl?: string;
  nativeRedirectUri?: string;
  webRedirectUri?: string;
  githubScopes?: string;
  githubClientId?: string;
  githubClientSecret?: string;
  apiKeyName?: string;
  forceNewApiKey?: boolean;
  writeApiKey?: string;
  writeClientId?: string;
  json?: boolean;
}

interface ServiceResponse {
  id: string;
  slug: string;
  name: string;
  service_type: string;
  client_id: string;
  github_scopes?: string[] | null;
  redirect_uris?: string[] | null;
}

interface ApiKeyResponse {
  id: string;
  name: string;
  prefix: string;
  permissions: string[];
}

interface ProvisionReport {
  authosBaseUrl: string;
  orgSlug: string;
  organizationStatus: 'created' | 'unchanged' | 'skipped';
  serviceSlug: string;
  serviceStatus: 'created' | 'updated' | 'unchanged';
  clientId: string;
  redirectUris: {
    desired: string[];
    added: string[];
    removed: string[];
  };
  githubScopes: string[];
  providerCredentials: {
    github: 'configured' | 'unchanged' | 'missing';
  };
  apiKey: {
    name: string;
    status: 'created' | 'existing' | 'skipped';
    prefix?: string;
    writtenTo?: string;
  };
  blockers: string[];
}

const defaultScopes = ['repo', 'read:user', 'user:email', 'read:org'];

export async function provisionActCommand(
  options: ProvisionActOptions = {},
): Promise<void> {
  const baseUrl = normalizeUrl(
    options.baseUrl ?? process.env.AUTHOS_BASE_URL ?? '',
  );
  let adminToken = options.adminToken ?? process.env.AUTHOS_ADMIN_TOKEN ?? '';
  const ownerEmail =
    options.ownerEmail ??
    process.env.AUTHOS_PLATFORM_OWNER_EMAIL ??
    process.env.PLATFORM_OWNER_EMAIL ??
    '';
  const ownerPassword =
    options.ownerPassword ??
    process.env.AUTHOS_PLATFORM_OWNER_PASSWORD ??
    process.env.PLATFORM_OWNER_PASSWORD ??
    '';
  const orgSlug = options.org ?? process.env.ACT_SSO_ORG_SLUG ?? 'act';
  const orgName = options.orgName ?? process.env.ACT_SSO_ORG_NAME ?? 'ACT';
  const serviceSlug = options.service ?? 'act';
  const serviceName = options.name ?? 'ACT';
  const actUrl = normalizeUrl(options.actUrl ?? process.env.ACT_PUBLIC_URL ?? '');
  const nativeRedirectUri = options.nativeRedirectUri ?? 'act://auth/callback';
  const webRedirectUri =
    options.webRedirectUri ?? (actUrl ? `${actUrl}/auth/callback` : '');
  const githubScopes = parseCsv(options.githubScopes, defaultScopes);
  const apiKeyName = options.apiKeyName ?? 'act-provider-token-reader';
  const blockers: string[] = [];

  if (!baseUrl) {
    blockers.push('Missing --base-url or AUTHOS_BASE_URL.');
  }
  if (!adminToken && (!ownerEmail || !ownerPassword)) {
    blockers.push(
      'Missing --admin-token/AUTHOS_ADMIN_TOKEN or platform owner email/password.',
    );
  }
  if (!actUrl) {
    blockers.push('Missing --act-url or ACT_PUBLIC_URL.');
  }
  if (!webRedirectUri) {
    blockers.push('Missing web redirect URI.');
  }

  if (blockers.length > 0 || !baseUrl) {
    renderReport(
      {
        authosBaseUrl: baseUrl,
        orgSlug,
        organizationStatus: 'skipped',
        serviceSlug,
        serviceStatus: 'unchanged',
        clientId: '',
        redirectUris: { desired: [], added: [], removed: [] },
        githubScopes,
        providerCredentials: { github: 'missing' },
        apiKey: { name: apiKeyName, status: 'skipped' },
        blockers,
      },
      options.json === true,
    );
    process.exitCode = 1;
    return;
  }

  if (!adminToken) {
    try {
      adminToken = await loginPlatformOwner(baseUrl, ownerEmail, ownerPassword);
    } catch (error) {
      renderReport(
        {
          authosBaseUrl: baseUrl,
          orgSlug,
          organizationStatus: 'skipped',
          serviceSlug,
          serviceStatus: 'unchanged',
          clientId: '',
          redirectUris: { desired: [], added: [], removed: [] },
          githubScopes,
          providerCredentials: { github: 'missing' },
          apiKey: { name: apiKeyName, status: 'skipped' },
          blockers: [`Platform owner login failed: ${errorMessage(error)}`],
        },
        options.json === true,
      );
      process.exitCode = 1;
      return;
    }
  }

  const client = new AuthOsAdminClient(baseUrl, adminToken);
  const organizationStatus = await ensureOrganization(client, orgSlug, orgName);
  const desiredRedirectUris = unique([webRedirectUri, nativeRedirectUri]);
  const existingService = await findService(client, orgSlug, serviceSlug);
  let serviceStatus: ProvisionReport['serviceStatus'] = 'unchanged';
  let service: ServiceResponse;

  if (existingService) {
    const existingRedirects = existingService.redirect_uris ?? [];
    const existingScopes = existingService.github_scopes ?? [];
    const needsUpdate =
      existingService.name !== serviceName ||
      existingService.service_type !== 'mobile' ||
      !sameStringSet(existingRedirects, desiredRedirectUris) ||
      !sameStringSet(existingScopes, githubScopes);

    if (needsUpdate) {
      service = await client.request<ServiceResponse>(
        `/api/organizations/${encodeURIComponent(orgSlug)}/services/${encodeURIComponent(
          serviceSlug,
        )}`,
        {
          method: 'PATCH',
          body: {
            name: serviceName,
            service_type: 'mobile',
            github_scopes: githubScopes,
            redirect_uris: desiredRedirectUris,
          },
        },
      );
      serviceStatus = 'updated';
    } else {
      service = existingService;
    }
  } else {
    const response = await client.request<{ service: ServiceResponse }>(
      `/api/organizations/${encodeURIComponent(orgSlug)}/services`,
      {
        method: 'POST',
        body: {
          slug: serviceSlug,
          name: serviceName,
          service_type: 'mobile',
          github_scopes: githubScopes,
          redirect_uris: desiredRedirectUris,
        },
      },
    );
    service = response.service;
    serviceStatus = 'created';
  }

  const previousRedirectUris = existingService?.redirect_uris ?? [];
  const providerCredentials = await provisionGitHubCredentials(
    client,
    orgSlug,
    options.githubClientId ?? process.env.AUTHOS_GITHUB_CLIENT_ID,
    options.githubClientSecret ?? process.env.AUTHOS_GITHUB_CLIENT_SECRET,
  );
  const apiKey = await provisionApiKey(client, orgSlug, serviceSlug, {
    name: apiKeyName,
    forceNew: options.forceNewApiKey === true,
    writePath: options.writeApiKey,
    blockers,
  });
  if (options.writeClientId) {
    await mkdir(dirname(options.writeClientId), { recursive: true });
    await writeFile(options.writeClientId, `${service.client_id}\n`, {
      mode: 0o600,
    });
  }

  renderReport(
    {
      authosBaseUrl: baseUrl,
      orgSlug,
      organizationStatus,
      serviceSlug,
      serviceStatus,
      clientId: service.client_id,
      redirectUris: {
        desired: desiredRedirectUris,
        added: desiredRedirectUris.filter(
          (uri) => !previousRedirectUris.includes(uri),
        ),
        removed: previousRedirectUris.filter(
          (uri) => !desiredRedirectUris.includes(uri),
        ),
      },
      githubScopes,
      providerCredentials: { github: providerCredentials },
      apiKey,
      blockers,
    },
    options.json === true,
  );

  if (blockers.length > 0) {
    process.exitCode = 1;
  }
}

class AuthOsAdminClient {
  constructor(private readonly baseUrl: string, private readonly token: string) {}

  async request<T>(
    path: string,
    init: { method?: string; body?: unknown } = {},
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method: init.method ?? 'GET',
      headers: {
        authorization: `Bearer ${this.token}`,
        accept: 'application/json',
        ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
    });
    if (!response.ok) {
      const message = await response.text();
      throw new AuthOsHttpError(init.method ?? 'GET', path, response.status, message);
    }
    return (await response.json()) as T;
  }
}

class AuthOsHttpError extends Error {
  constructor(
    readonly method: string,
    readonly path: string,
    readonly status: number,
    readonly responseText: string,
  ) {
    super(`AuthOS ${method} ${path} failed (${status}): ${responseText}`);
  }
}

async function loginPlatformOwner(
  baseUrl: string,
  email: string,
  password: string,
): Promise<string> {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    throw new Error(`${response.status}: ${await response.text()}`);
  }
  const data = (await response.json()) as {
    access_token?: string;
    refresh_token?: string;
  };
  if (!data.access_token) {
    throw new Error('AuthOS login did not return an access token');
  }
  if (!data.refresh_token) {
    throw new Error('Platform owner login requires MFA or was risk-challenged');
  }
  return data.access_token;
}

async function ensureOrganization(
  client: AuthOsAdminClient,
  orgSlug: string,
  orgName: string,
): Promise<ProvisionReport['organizationStatus']> {
  try {
    await client.request(`/api/organizations/${encodeURIComponent(orgSlug)}`);
    return 'unchanged';
  } catch (error) {
    if (!(error instanceof AuthOsHttpError) || error.status !== 404) {
      throw error;
    }
  }

  await client.request('/api/organizations', {
    method: 'POST',
    body: { slug: orgSlug, name: orgName },
  });
  return 'created';
}

async function findService(
  client: AuthOsAdminClient,
  orgSlug: string,
  serviceSlug: string,
): Promise<ServiceResponse | null> {
  const response = await client.request<{ services: ServiceResponse[] }>(
    `/api/organizations/${encodeURIComponent(orgSlug)}/services`,
  );
  return (
    response.services.find((candidate) => candidate.slug === serviceSlug) ?? null
  );
}

async function provisionGitHubCredentials(
  client: AuthOsAdminClient,
  orgSlug: string,
  clientId?: string,
  clientSecret?: string,
): Promise<ProvisionReport['providerCredentials']['github']> {
  if (clientId && clientSecret) {
    await client.request(
      `/api/organizations/${encodeURIComponent(orgSlug)}/oauth-credentials/github`,
      {
        method: 'POST',
        body: { client_id: clientId, client_secret: clientSecret },
      },
    );
    return 'configured';
  }

  try {
    await client.request(
      `/api/organizations/${encodeURIComponent(orgSlug)}/oauth-credentials/github`,
    );
    return 'unchanged';
  } catch {
    return 'missing';
  }
}

async function provisionApiKey(
  client: AuthOsAdminClient,
  orgSlug: string,
  serviceSlug: string,
  options: {
    name: string;
    forceNew: boolean;
    writePath?: string;
    blockers: string[];
  },
): Promise<ProvisionReport['apiKey']> {
  const response = await client.request<{ api_keys: ApiKeyResponse[] }>(
    `/api/organizations/${encodeURIComponent(orgSlug)}/services/${encodeURIComponent(
      serviceSlug,
    )}/api-keys`,
  );
  const existing = response.api_keys.find((key) => key.name === options.name);
  if (existing && !options.forceNew) {
    return {
      name: options.name,
      status: 'existing',
      prefix: existing.prefix,
    };
  }
  if (!options.writePath) {
    options.blockers.push(
      `API key "${options.name}" is not present or rotation was requested; pass --write-api-key so the one-time secret can be saved without printing it.`,
    );
    return { name: options.name, status: 'skipped' };
  }

  const created = await client.request<ApiKeyResponse & { key: string }>(
    `/api/organizations/${encodeURIComponent(orgSlug)}/services/${encodeURIComponent(
      serviceSlug,
    )}/api-keys`,
    {
      method: 'POST',
      body: {
        name: options.name,
        permissions: ['read:provider_tokens:github'],
      },
    },
  );
  await mkdir(dirname(options.writePath), { recursive: true });
  await writeFile(options.writePath, `${created.key}\n`, { mode: 0o600 });
  return {
    name: options.name,
    status: 'created',
    prefix: created.prefix,
    writtenTo: options.writePath,
  };
}

function renderReport(report: ProvisionReport, asJson: boolean): void {
  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  console.log(pc.bold('\nAuthOS ACT provisioning report\n'));
  console.log(`AuthOS: ${pc.cyan(report.authosBaseUrl || '(missing)')}`);
  console.log(
    `Organization: ${pc.cyan(report.orgSlug)} (${report.organizationStatus})`,
  );
  console.log(`Service: ${pc.cyan(report.serviceSlug)} (${report.serviceStatus})`);
  if (report.clientId) {
    console.log(`Client ID: ${pc.cyan(report.clientId)}`);
  }
  console.log(`Redirects: ${report.redirectUris.desired.join(', ') || '(none)'}`);
  console.log(`GitHub scopes: ${report.githubScopes.join(', ')}`);
  console.log(`GitHub BYOO credentials: ${report.providerCredentials.github}`);
  console.log(
    `API key: ${report.apiKey.status}${
      report.apiKey.prefix ? ` (${report.apiKey.prefix}...)` : ''
    }${report.apiKey.writtenTo ? ` written to ${report.apiKey.writtenTo}` : ''}`,
  );

  if (report.blockers.length > 0) {
    console.log(pc.red('\nRemaining blockers:'));
    for (const blocker of report.blockers) {
      console.log(`- ${blocker}`);
    }
  } else {
    console.log(pc.green('\nProvisioning complete.'));
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function normalizeUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) {
    return '';
  }
  const url = new URL(
    trimmed.includes('://') ? trimmed : `${defaultScheme(trimmed)}://${trimmed}`,
  );
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function defaultScheme(input: string): string {
  const host = input.split('/')[0].split(':')[0].toLowerCase();
  const localOrIp =
    host === 'localhost' ||
    host.endsWith('.local') ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  return localOrIp ? 'http' : 'https';
}

function parseCsv(value: string | undefined, fallback: string[]): string[] {
  const source = value?.trim();
  if (!source) {
    return fallback;
  }
  return unique(
    source
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean),
  );
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function sameStringSet(left: string[], right: string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  const rightSet = new Set(right);
  return left.every((item) => rightSet.has(item));
}
