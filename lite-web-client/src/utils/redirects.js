export const POST_LOGIN_REDIRECT_KEY = 'sso_lite_post_login_redirect';

export function normalizeInternalRedirect(value) {
  const redirect = Array.isArray(value) ? value[0] : value;
  if (typeof redirect !== 'string' || !redirect.startsWith('/') || redirect.startsWith('//')) {
    return null;
  }
  return redirect;
}

export function storePostLoginRedirect(value) {
  const redirect = normalizeInternalRedirect(value);
  if (redirect) sessionStorage.setItem(POST_LOGIN_REDIRECT_KEY, redirect);
  return redirect;
}

export function clearPostLoginRedirect() {
  sessionStorage.removeItem(POST_LOGIN_REDIRECT_KEY);
}

export function takePostLoginRedirect() {
  const redirect = normalizeInternalRedirect(sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY));
  sessionStorage.removeItem(POST_LOGIN_REDIRECT_KEY);
  return redirect;
}

export function defaultAuthenticatedRoute() {
  return '/app/overview';
}

export function postLoginRedirect(route) {
  return (
    normalizeInternalRedirect(route?.query?.redirect) ||
    takePostLoginRedirect() ||
    defaultAuthenticatedRoute()
  );
}
