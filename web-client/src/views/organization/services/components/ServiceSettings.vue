<template>
  <div class="bg-white shadow rounded-lg">
    <div class="px-6 py-4 border-b border-gray-200">
      <h2 class="text-lg font-medium text-gray-900">Service Configuration</h2>
      <p class="mt-1 text-sm text-gray-600">
        Manage your service settings and configuration
      </p>
    </div>

    <form @submit.prevent="handleUpdate" class="px-6 py-6 space-y-6">
      <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
        <BaseInput
          v-model="form.name"
          label="Service Name"
          placeholder="My Application"
          required
          :error="errors.name"
        />

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Service Slug
          </label>
          <input
            :value="currentService?.service?.slug"
            type="text"
            disabled
            readonly
            class="block w-full rounded-md border-gray-300 bg-gray-50 shadow-sm sm:text-sm cursor-not-allowed"
          />
          <p class="mt-1 text-xs text-gray-500">Cannot be changed after creation</p>
        </div>
      </div>

      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">
          Service Type
        </label>
        <select
          v-model="form.service_type"
          class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
        >
          <option value="web">Web Application</option>
          <option value="mobile">Mobile Application</option>
          <option value="desktop">Desktop Application</option>
          <option value="api">API / Backend Service</option>
        </select>
      </div>

      <div>
        <label class="block text-sm font-medium text-gray-700 mb-1">
          Client ID
        </label>
        <div class="flex gap-2">
          <input
            :value="currentService?.service?.client_id"
            type="text"
            readonly
            class="block w-full rounded-md border-gray-300 bg-gray-50 shadow-sm sm:text-sm font-mono"
          />
          <button
            type="button"
            @click="copyToClipboard(currentService?.service?.client_id)"
            class="inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
          >
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
          </button>
        </div>
        <p class="mt-1 text-xs text-gray-500">Use this Client ID in your application's OAuth configuration</p>
      </div>

      <div>
        <div class="flex items-center justify-between mb-2">
          <label class="block text-sm font-medium text-gray-700">
            Redirect URIs
          </label>
          <button
            type="button"
            @click="addRedirectUri"
            class="inline-flex items-center text-sm text-blue-600 hover:text-blue-700"
          >
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
            </svg>
            Add URI
          </button>
        </div>
        <div class="space-y-2">
          <div
            v-for="(uri, index) in form.redirect_uris"
            :key="index"
            class="flex gap-2"
          >
            <input
              v-model="form.redirect_uris[index]"
              type="url"
              placeholder="https://example.com/callback"
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
              required
            />
            <button
              v-if="form.redirect_uris.length > 1"
              type="button"
              @click="removeRedirectUri(index)"
              class="inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
            >
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>
        <p class="mt-1 text-xs text-gray-500">
          Allowed callback URLs for OAuth authentication
        </p>
      </div>

      <details class="border rounded-md p-4">
        <summary class="cursor-pointer font-medium text-gray-700">
          OAuth Scopes Configuration
        </summary>
        <div class="mt-4 space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">
              GitHub Scopes
            </label>
            <input
              v-model="scopesInput.github"
              type="text"
              placeholder="user:email, read:org"
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            />
            <p class="mt-1 text-xs text-gray-500">Comma-separated list of GitHub OAuth scopes</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">
              Google Scopes
            </label>
            <input
              v-model="scopesInput.google"
              type="text"
              placeholder="email, profile"
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            />
            <p class="mt-1 text-xs text-gray-500">Comma-separated list of Google OAuth scopes</p>
          </div>

          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">
              Microsoft Scopes
            </label>
            <input
              v-model="scopesInput.microsoft"
              type="text"
              placeholder="User.Read, email"
              class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            />
            <p class="mt-1 text-xs text-gray-500">Comma-separated list of Microsoft OAuth scopes</p>
          </div>
        </div>
      </details>

      <div class="flex justify-between items-center pt-4 border-t">
        <button
          type="button"
          @click="showDeleteConfirm = true"
          class="inline-flex items-center px-4 py-2 border border-red-300 rounded-md text-sm font-medium text-red-700 bg-white hover:bg-red-50"
        >
          Delete Service
        </button>

        <div class="flex gap-3">
          <BaseButton
            type="button"
            variant="ghost"
            @click="resetForm"
          >
            Reset
          </BaseButton>
          <BaseButton
            type="submit"
            variant="primary"
            :loading="saving"
          >
            Save Changes
          </BaseButton>
        </div>
      </div>
    </form>

    <BaseModal
      :is-open="showDeleteConfirm"
      title="Delete Service"
      size="md"
      confirm-variant="danger"
      confirm-text="Delete"
      @close="showDeleteConfirm = false"
      @confirm="handleDelete"
    >
      <p class="text-sm text-gray-600">
        Are you sure you want to delete this service? This action cannot be undone.
        All associated data including OAuth configurations and subscription plans will be permanently removed.
      </p>
      <div class="mt-4 p-4 bg-yellow-50 rounded-md">
        <p class="text-sm text-yellow-800">
          <strong>Warning:</strong> Users will no longer be able to authenticate with this service.
        </p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup>
import { ref, computed, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useServicesStore } from '@/stores/services';
import { useOrganizationStore } from '@/stores/organization';
import { useNotifications } from '@/composables/useNotifications';
import BaseInput from '@/components/BaseInput.vue';
import BaseButton from '@/components/BaseButton.vue';
import BaseModal from '@/components/BaseModal.vue';

const route = useRoute();
const router = useRouter();
const servicesStore = useServicesStore();
const organizationStore = useOrganizationStore();
const { showSuccess, showError } = useNotifications();

const currentService = computed(() => servicesStore.currentService);

const form = ref({
  name: '',
  service_type: '',
  redirect_uris: [],
});

const scopesInput = ref({
  github: '',
  google: '',
  microsoft: '',
});

const errors = ref({
  name: '',
});

const saving = ref(false);
const showDeleteConfirm = ref(false);

const initializeForm = () => {
  if (currentService.value) {
    const service = currentService.value.service;
    form.value = {
      name: service.name,
      service_type: service.service_type,
      redirect_uris: [...service.redirect_uris],
    };

    scopesInput.value = {
      github: service.github_scopes?.join(', ') || '',
      google: service.google_scopes?.join(', ') || '',
      microsoft: service.microsoft_scopes?.join(', ') || '',
    };
  }
};

const resetForm = () => {
  initializeForm();
};

const addRedirectUri = () => {
  form.value.redirect_uris.push('');
};

const removeRedirectUri = (index) => {
  form.value.redirect_uris.splice(index, 1);
};

const parseScopes = (input) => {
  if (!input || !input.trim()) return [];
  return input.split(',').map(s => s.trim()).filter(s => s.length > 0);
};

const copyToClipboard = async (text) => {
  try {
    await navigator.clipboard.writeText(text);
    showSuccess('Copied to clipboard');
  } catch (error) {
    showError('Failed to copy to clipboard');
  }
};

const handleUpdate = async () => {
  errors.value = { name: '' };

  const validRedirectUris = form.value.redirect_uris.filter(uri => uri.trim().length > 0);

  if (validRedirectUris.length === 0) {
    showError('At least one redirect URI is required');
    return;
  }

  const payload = {
    name: form.value.name,
    service_type: form.value.service_type,
    redirect_uris: validRedirectUris,
  };

  const githubScopes = parseScopes(scopesInput.value.github);
  const googleScopes = parseScopes(scopesInput.value.google);
  const microsoftScopes = parseScopes(scopesInput.value.microsoft);

  if (githubScopes.length > 0) payload.github_scopes = githubScopes;
  if (googleScopes.length > 0) payload.google_scopes = googleScopes;
  if (microsoftScopes.length > 0) payload.microsoft_scopes = microsoftScopes;

  saving.value = true;

  try {
    await servicesStore.updateService(
      organizationStore.currentOrgSlug,
      currentService.value.service.slug,
      payload
    );

    showSuccess('Service updated successfully');
  } catch (error) {
    console.error('Failed to update service:', error);
    if (error.response?.data?.error) {
      showError(error.response.data.error);
    } else {
      showError('Failed to update service. Please try again.');
    }
  } finally {
    saving.value = false;
  }
};

const handleDelete = async () => {
  try {
    await servicesStore.deleteService(
      organizationStore.currentOrgSlug,
      currentService.value.service.slug
    );

    showSuccess('Service deleted successfully');
    showDeleteConfirm.value = false;

    router.push({
      name: 'ServiceList',
      params: { orgSlug: route.params.orgSlug },
    });
  } catch (error) {
    console.error('Failed to delete service:', error);
    showError('Failed to delete service. Please try again.');
  }
};

watch(currentService, () => {
  if (currentService.value) {
    initializeForm();
  }
}, { immediate: true });
</script>
