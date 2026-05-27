export function buildScrubbedUrl(href, { queryKeys = [], hashKeys = [] } = {}) {
  const base = typeof window === 'undefined' ? 'http://localhost' : window.location.origin;
  const url = new URL(href, base);
  const query = new URLSearchParams(url.search);
  const hash = new URLSearchParams(url.hash.replace(/^#/, ''));
  const originalSearch = url.search;
  const originalHash = url.hash;

  for (const key of queryKeys) {
    query.delete(key);
  }

  for (const key of hashKeys) {
    hash.delete(key);
  }

  const nextSearch = query.toString();
  const nextHash = hash.toString();

  if (originalSearch === (nextSearch ? `?${nextSearch}` : '') && originalHash === (nextHash ? `#${nextHash}` : '')) {
    return null;
  }

  return `${url.pathname}${nextSearch ? `?${nextSearch}` : ''}${nextHash ? `#${nextHash}` : ''}`;
}

export function scrubCurrentUrl(options) {
  if (typeof window === 'undefined') return;

  const nextUrl = buildScrubbedUrl(window.location.href, options);
  if (!nextUrl) return;
  window.history.replaceState(null, '', nextUrl);
}
