function resetStorage(storage) {
  if (!storage) {
    return;
  }

  if (typeof storage.clear === 'function') {
    storage.clear();
    return;
  }

  if (typeof storage.length === 'number' && typeof storage.key === 'function' && typeof storage.removeItem === 'function') {
    const keys = [];
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (key) {
        keys.push(key);
      }
    }

    for (const key of keys) {
      storage.removeItem(key);
    }
  }
}

export function clearBrowserStorage() {
  if (typeof localStorage !== 'undefined') {
    resetStorage(localStorage);
  }

  if (typeof sessionStorage !== 'undefined') {
    resetStorage(sessionStorage);
  }
}
