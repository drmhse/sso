export function hasFullClient(config) {
  return Boolean(config?.full_client_url);
}

export function buildFullClientUrl(config, path = '/home', tokens = null) {
  if (!config?.full_client_url) return '';

  const base = config.full_client_url.replace(/\/$/, '');
  const targetPath = path.startsWith('/') ? path : `/${path}`;
  const url = new URL(`${base}${targetPath}`, window.location.origin);

  if (tokens?.accessToken && tokens?.refreshToken) {
    const hash = new URLSearchParams(url.hash.replace(/^#/, ''));
    hash.set('access_token', tokens.accessToken);
    hash.set('refresh_token', tokens.refreshToken);
    url.hash = hash.toString();
  }

  return url.toString();
}
