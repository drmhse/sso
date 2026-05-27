import { computed, ref } from 'vue';
import { useAuthStore } from '@/stores/auth';
import {
  normalizeManagedConfig,
  serializeManagedConfig,
  validateManagedConfig,
} from './config';

export function useManagedConfig() {
  const authStore = useAuthStore();

  const loading = ref(true);
  const refreshing = ref(false);
  const saving = ref(false);
  const applying = ref(false);
  const form = ref(normalizeManagedConfig());
  const configPath = ref('');
  const status = ref(null);
  const message = ref('');
  const messageType = ref('success');

  const statusLabel = computed(() => status.value?.status || 'idle');
  const statusMessage = computed(() => status.value?.message || '');
  const statusUpdatedAt = computed(() => {
    const value = status.value?.updated_at;
    return value ? new Date(value).toLocaleString() : 'Never';
  });
  const statusClass = computed(() => {
    if (status.value?.status === 'success') return 'active';
    if (['queued', 'running'].includes(status.value?.status)) return 'pending';
    if (status.value?.status === 'error') return 'suspended';
    return '';
  });
  const validationErrors = computed(() => validateManagedConfig(form.value));
  const advancedJson = computed(() => `${JSON.stringify(serializeManagedConfig(form.value), null, 2)}\n`);

  async function loadConfig() {
    loading.value = !configPath.value;
    refreshing.value = Boolean(configPath.value);

    try {
      const payload = await request(authStore.token, '/api/platform/bootstrap/config');
      form.value = normalizeManagedConfig(payload.config);
      configPath.value = payload.config_path || '';
      status.value = payload.status || null;
      message.value = '';
    } catch (error) {
      messageType.value = 'error';
      message.value = error.message || 'Failed to load the managed config.';
    } finally {
      loading.value = false;
      refreshing.value = false;
    }
  }

  async function saveConfig({ quiet = false } = {}) {
    saving.value = true;

    try {
      const errors = validationErrors.value;
      if (errors.length > 0) {
        throw new Error(errors[0]);
      }

      const payload = serializeManagedConfig(form.value);
      const response = await request(authStore.token, '/api/platform/bootstrap/config', {
        method: 'PATCH',
        body: payload,
      });
      form.value = normalizeManagedConfig(response.config);
      status.value = response.status || status.value;
      configPath.value = response.config_path || configPath.value;
      if (!quiet) {
        messageType.value = 'success';
        message.value = 'Managed config saved.';
      }
      return serializeManagedConfig(form.value);
    } catch (error) {
      messageType.value = 'error';
      message.value = error.message || 'Failed to save the managed config.';
      throw error;
    } finally {
      saving.value = false;
    }
  }

  async function saveAndApply() {
    applying.value = true;
    message.value = '';

    try {
      const payload = await saveConfig({ quiet: true });
      const response = await request(authStore.token, '/api/platform/bootstrap/apply', {
        method: 'POST',
      });
      messageType.value = 'success';
      message.value = response.message || 'AuthOS reload queued.';
      status.value = {
        status: 'queued',
        message: response.message || 'AuthOS reload queued.',
        updated_at: new Date().toISOString(),
      };

      const targetUrl = resolveTargetUrl(payload);
      const recovery = await waitForServiceRecovery(window.location.origin, targetUrl);

      if (recovery.targetReady) {
        window.location.href = `${targetUrl}/app/platform-setup`;
        return;
      }

      await loadConfig();
      messageType.value = 'success';
      message.value = `AuthOS restarted. Finish bringing ${targetUrl} online, then open ${targetUrl}/app/platform-setup.`;
    } catch (error) {
      messageType.value = 'error';
      message.value = error.message || 'Failed to apply the managed config.';
    } finally {
      applying.value = false;
    }
  }

  return {
    loading,
    refreshing,
    saving,
    applying,
    form,
    configPath,
    statusMessage,
    statusUpdatedAt,
    statusLabel,
    statusClass,
    message,
    messageType,
    validationErrors,
    advancedJson,
    loadConfig,
    saveConfig,
    saveAndApply,
  };
}

function resolveTargetUrl(config) {
  const deployment = config?.deployment || {};
  const url = deployment.platformBaseUrl || deployment.baseUrl || window.location.origin;
  return String(url).replace(/\/$/, '');
}

async function waitForServiceRecovery(currentOrigin, targetUrl) {
  const currentUrl = String(currentOrigin || '').replace(/\/$/, '');
  const normalizedTargetUrl = String(targetUrl || '').replace(/\/$/, '');
  const sameOrigin = currentUrl === normalizedTargetUrl;
  const deadline = Date.now() + 90000;
  let currentReady = false;

  while (Date.now() < deadline) {
    if (await isReady(normalizedTargetUrl)) {
      return { currentReady: true, targetReady: true };
    }

    if (sameOrigin) {
      await new Promise((resolve) => window.setTimeout(resolve, 2000));
      continue;
    }

    if (!currentReady && await isReady(currentUrl)) {
      currentReady = true;
      return { currentReady: true, targetReady: false };
    }

    await new Promise((resolve) => window.setTimeout(resolve, 2000));
  }

  if (currentReady) {
    return { currentReady: true, targetReady: false };
  }

  throw new Error(`Timed out waiting for AuthOS to restart at ${normalizedTargetUrl}/health/ready.`);
}

async function isReady(baseUrl) {
  if (!baseUrl) return false;

  try {
    const response = await fetch(`${baseUrl}/health/ready`, { cache: 'no-store' });
    return response.ok;
  } catch (error) {
    return false;
  }
}

async function request(token, url, init = {}) {
  const response = await fetch(url, {
    method: init.method || 'GET',
    headers: {
      accept: 'application/json',
      authorization: `Bearer ${token}`,
      ...(init.body ? { 'content-type': 'application/json' } : {}),
    },
    body: init.body ? JSON.stringify(init.body) : undefined,
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || 'Request failed.');
  }

  return payload;
}
