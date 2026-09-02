import { SsoClient, SsoApiError, MemoryStorage } from '@drmhse/sso-sdk';
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

  const sso = createAdminClient(baseUrl);

  if (adminToken) {
    await sso.setSession({ access_token: adminToken });
  } else {
    try {
      await loginPlatformOwner(sso, ownerEmail, ownerPassword);
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

  const organizationStatus = await ensureOrganization(sso, orgSlug, orgName);
  const desiredRedirectUris = unique([webRedirectUri, nativeRedirectUri]);
  const existingService = await findService(sso, orgSlug, serviceSlug);
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
      service = (await sso.services.update(orgSlug, serviceSlug, {
        name: serviceName,
        service_type: 'mobile',
        github_scopes: githubScopes,
        redirect_uris: desiredRedirectUris,
      })) as unknown as ServiceResponse;
      serviceStatus = 'updated';
    } else {
      service = existingService;
    }
  } else {
    const response = await sso.services.create(orgSlug, {
      slug: serviceSlug,
      name: serviceName,
      service_type: 'mobile',
      github_scopes: githubScopes,
      redirect_uris: desiredRedirectUris,
    });
    service = response.service as unknown as ServiceResponse;
    serviceStatus = 'created';
  }

  const previousRedirectUris = existingService?.redirect_uris ?? [];
  const providerCredentials = await provisionGitHubCredentials(
    sso,
    orgSlug,
    options.githubClientId ?? process.env.AUTHOS_GITHUB_CLIENT_ID,
    options.githubClientSecret ?? process.env.AUTHOS_GITHUB_CLIENT_SECRET,
  );
  const apiKey = await provisionApiKey(sso, orgSlug, serviceSlug, {
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

/**
 * Build an SDK client for admin provisioning. Every API call in this command
 * goes through the SDK so the CLI cannot drift from the published contract.
 */
function createAdminClient(baseUrl: string): SsoClient {
  return new SsoClient({ baseURL: baseUrl, storage: new MemoryStorage() });
}

function isNotFound(error: unknown): boolean {
  return error instanceof SsoApiError && error.statusCode === 404;
}


async function loginPlatformOwner(
  sso: SsoClient,
  email: string,
  password: string,
): Promise<void> {
  const tokens = await sso.auth.login({ email, password });
  if (!tokens.refresh_token) {
    throw new Error('Platform owner login requires MFA or was risk-challenged');
  }
}

async function ensureOrganization(
  sso: SsoClient,
  orgSlug: string,
  orgName: string,
): Promise<ProvisionReport['organizationStatus']> {
  try {
    await sso.organizations.get(orgSlug);
    return 'unchanged';
  } catch (error) {
    if (!isNotFound(error)) {
      throw error;
    }
  }

  await sso.organizations.create({ slug: orgSlug, name: orgName });
  return 'created';
}

async function findService(
  sso: SsoClient,
  orgSlug: string,
  serviceSlug: string,
): Promise<ServiceResponse | null> {
  const response = await sso.services.list(orgSlug);
  const match = response.services.find(
    (candidate) => candidate.service.slug === serviceSlug,
  );
  return (match?.service as unknown as ServiceResponse | undefined) ?? null;
}

async function provisionGitHubCredentials(
  sso: SsoClient,
  orgSlug: string,
  clientId?: string,
  clientSecret?: string,
): Promise<ProvisionReport['providerCredentials']['github']> {
  if (clientId && clientSecret) {
    await sso.organizations.oauthCredentials.set(orgSlug, 'github', {
      client_id: clientId,
      client_secret: clientSecret,
    });
    return 'configured';
  }

  try {
    await sso.organizations.oauthCredentials.get(orgSlug, 'github');
    return 'unchanged';
  } catch {
    return 'missing';
  }
}

async function provisionApiKey(
  sso: SsoClient,
  orgSlug: string,
  serviceSlug: string,
  options: {
    name: string;
    forceNew: boolean;
    writePath?: string;
    blockers: string[];
  },
): Promise<ProvisionReport['apiKey']> {
  const response = await sso.services.apiKeys.list(orgSlug, serviceSlug);
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

  const created = await sso.services.apiKeys.create(orgSlug, serviceSlug, {
    name: options.name,
    permissions: ['read:provider_tokens:github'],
  });
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
