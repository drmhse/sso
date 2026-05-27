export function formatDateTime(value, fallback = 'Unknown') {
  if (!value) return fallback;
  return new Date(value).toLocaleString();
}

export function providerNameList(identities = []) {
  if (!identities.length) return [];
  return identities.map((identity) => identity.provider);
}
