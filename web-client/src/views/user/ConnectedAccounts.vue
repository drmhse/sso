<template>
  <div>
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900">Connected Accounts</h1>
      <p class="mt-2 text-gray-600">
        Manage your linked social accounts. You can link multiple accounts to access your profile.
      </p>
    </div>

    <LoadingSpinner v-if="loading" text="Loading connected accounts..." />

    <div v-else class="space-y-6">
      <div class="bg-white shadow overflow-hidden sm:rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <h2 class="text-lg font-medium text-gray-900 mb-4">Linked Accounts</h2>

          <EmptyState
            v-if="linkedProviders.length === 0"
            icon="link"
            title="No accounts linked"
            description="You don't have any social accounts linked yet."
          />

          <div v-else class="space-y-3">
            <div
              v-for="provider in linkedProviders"
              :key="provider"
              class="flex items-center justify-between p-4 border border-gray-200 rounded-lg"
            >
              <div class="flex items-center">
                <div
                  class="flex-shrink-0 h-10 w-10 rounded-full flex items-center justify-center"
                  :class="getProviderColor(provider)"
                >
                  <span class="text-white font-semibold text-sm">
                    {{ provider.charAt(0).toUpperCase() }}
                  </span>
                </div>
                <div class="ml-4">
                  <p class="text-sm font-medium text-gray-900">
                    {{ capitalizeProvider(provider) }}
                  </p>
                  <p class="text-xs text-gray-500">Connected</p>
                </div>
              </div>

              <BaseButton
                @click="handleUnlink(provider)"
                variant="danger"
                size="sm"
                :loading="unlinking === provider"
                :disabled="linkedProviders.length === 1"
              >
                Disconnect
              </BaseButton>
            </div>
          </div>
        </div>
      </div>

      <div class="bg-white shadow overflow-hidden sm:rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <h2 class="text-lg font-medium text-gray-900 mb-4">Available Accounts</h2>

          <EmptyState
            v-if="availableProviders.length === 0"
            icon="check"
            title="All accounts connected"
            description="You've already linked all available social accounts."
          />

          <div v-else class="space-y-3">
            <div
              v-for="provider in availableProviders"
              :key="provider"
              class="flex items-center justify-between p-4 border border-gray-200 rounded-lg"
            >
              <div class="flex items-center">
                <div
                  class="flex-shrink-0 h-10 w-10 rounded-full flex items-center justify-center"
                  :class="getProviderColor(provider)"
                >
                  <span class="text-white font-semibold text-sm">
                    {{ provider.charAt(0).toUpperCase() }}
                  </span>
                </div>
                <div class="ml-4">
                  <p class="text-sm font-medium text-gray-900">
                    {{ capitalizeProvider(provider) }}
                  </p>
                  <p class="text-xs text-gray-500">Not connected</p>
                </div>
              </div>

              <BaseButton
                @click="handleConnect(provider)"
                variant="primary"
                size="sm"
                :loading="connecting === provider"
              >
                Connect
              </BaseButton>
            </div>
          </div>
        </div>
      </div>
    </div>

    <ConfirmDialog
      :open="confirmDialog.open"
      :title="confirmDialog.title"
      :message="confirmDialog.message"
      :confirm-text="confirmDialog.confirmText"
      :cancel-text="confirmDialog.cancelText"
      @confirm="confirmDialog.onConfirm"
      @cancel="closeConfirmDialog"
    />
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';
import { useRoute } from 'vue-router';
import { sso } from '@/api';
import { useNotifications } from '@/composables/useNotifications';
import BaseButton from '@/components/BaseButton.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import EmptyState from '@/components/EmptyState.vue';
import ConfirmDialog from '@/components/ConfirmDialog.vue';

const route = useRoute();
const { success, error } = useNotifications();

const ALL_PROVIDERS = ['github', 'google', 'microsoft'];

const loading = ref(false);
const identities = ref([]);
const connecting = ref(null);
const unlinking = ref(null);

const confirmDialog = ref({
  open: false,
  title: '',
  message: '',
  confirmText: 'Confirm',
  cancelText: 'Cancel',
  onConfirm: () => {},
});

const linkedProviders = computed(() => {
  return identities.value.map(identity => identity.provider);
});

const availableProviders = computed(() => {
  return ALL_PROVIDERS.filter(provider => !linkedProviders.value.includes(provider));
});

const fetchIdentities = async () => {
  loading.value = true;
  try {
    identities.value = await sso.user.identities.list();
  } catch (err) {
    console.error('Failed to fetch identities:', err);
    error('Load Error', 'Failed to load connected accounts');
  } finally {
    loading.value = false;
  }
};

const handleConnect = async (provider) => {
  connecting.value = provider;

  try {
    const { authorization_url } = await sso.user.identities.startLink(provider);
    window.location.href = authorization_url;
  } catch (err) {
    console.error('Failed to start link:', err);
    error('Connection Error', `Failed to start linking ${capitalizeProvider(provider)}`);
    connecting.value = null;
  }
};

const handleUnlink = (provider) => {
  if (linkedProviders.value.length === 1) {
    error(
      'Cannot Disconnect',
      'You cannot disconnect your last social account. At least one account must remain linked.'
    );
    return;
  }

  confirmDialog.value = {
    open: true,
    title: 'Disconnect Account',
    message: `Are you sure you want to disconnect your ${capitalizeProvider(provider)} account? You can reconnect it at any time.`,
    confirmText: 'Disconnect',
    cancelText: 'Cancel',
    onConfirm: () => performUnlink(provider),
  };
};

const performUnlink = async (provider) => {
  closeConfirmDialog();
  unlinking.value = provider;

  try {
    await sso.user.identities.unlink(provider);
    success(
      'Account Disconnected',
      `Your ${capitalizeProvider(provider)} account has been disconnected`
    );

    // Remove from local list
    identities.value = identities.value.filter(identity => identity.provider !== provider);
  } catch (err) {
    console.error('Failed to unlink:', err);
    error('Disconnect Failed', err.message || 'Failed to disconnect account');
  } finally {
    unlinking.value = null;
  }
};

const closeConfirmDialog = () => {
  confirmDialog.value.open = false;
};

const capitalizeProvider = (provider) => {
  return provider.charAt(0).toUpperCase() + provider.slice(1);
};

const getProviderColor = (provider) => {
  const colors = {
    github: 'bg-gray-800',
    google: 'bg-red-500',
    microsoft: 'bg-blue-600',
  };
  return colors[provider] || 'bg-gray-500';
};

onMounted(async () => {
  await fetchIdentities();

  // Check for callback status from OAuth flow
  const status = route.query.status;
  if (status === 'success') {
    success('Account Linked', 'Your social account has been successfully linked');
    // Refresh the list
    await fetchIdentities();
    // Clean up URL
    window.history.replaceState({}, '', route.path);
  } else if (status === 'error') {
    const message = route.query.message || 'Failed to link account';
    error('Linking Failed', message);
    // Clean up URL
    window.history.replaceState({}, '', route.path);
  }
});
</script>
