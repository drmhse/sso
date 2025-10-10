<template>
  <div>
    <div class="flex justify-between items-center mb-6">
      <div>
        <h1 class="text-2xl font-bold text-gray-900">Services</h1>
        <p class="mt-1 text-sm text-gray-600">
          Manage authentication services for your organization
        </p>
      </div>

      <BaseButton
        variant="primary"
        @click="openCreateModal"
      >
        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
        </svg>
        Create Service
      </BaseButton>
    </div>

    <LoadingSpinner v-if="loading" class="py-12" />

    <EmptyState
      v-else-if="!hasServices"
      icon="folder"
      title="No services yet"
      description="Get started by creating your first authentication service."
    >
      <template #action>
        <BaseButton variant="primary" @click="openCreateModal">
          <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
          </svg>
          Create Service
        </BaseButton>
      </template>
    </EmptyState>

    <div v-else class="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
      <div
        v-for="service in services"
        :key="service.id"
        class="bg-white rounded-lg shadow hover:shadow-md transition-shadow cursor-pointer"
        @click="navigateToService(service)"
      >
        <div class="p-6">
          <div class="flex items-start justify-between">
            <div class="flex items-center">
              <div
                class="flex items-center justify-center w-12 h-12 rounded-lg"
                :class="getServiceTypeColor(service.service_type)"
              >
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path
                    v-if="service.service_type === 'web'"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
                  />
                  <path
                    v-else-if="service.service_type === 'mobile'"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"
                  />
                  <path
                    v-else-if="service.service_type === 'desktop'"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
                  />
                  <path
                    v-else
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"
                  />
                </svg>
              </div>
            </div>
            <span
              class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize"
              :class="getServiceTypeBadgeColor(service.service_type)"
            >
              {{ service.service_type }}
            </span>
          </div>

          <div class="mt-4">
            <h3 class="text-lg font-semibold text-gray-900">
              {{ service.name }}
            </h3>
            <p class="mt-1 text-sm text-gray-500 font-mono truncate">
              {{ service.slug }}
            </p>
          </div>

          <div class="mt-4 flex items-center text-sm text-gray-500">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
            </svg>
            Client ID: {{ formatClientId(service.client_id) }}
          </div>

          <div class="mt-3 flex items-center text-sm text-gray-500">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            {{ service.redirect_uris.length }} redirect URI{{ service.redirect_uris.length !== 1 ? 's' : '' }}
          </div>
        </div>
      </div>
    </div>

    <BaseModal
      :is-open="isCreateModalOpen"
      title="Create New Service"
      size="lg"
      :show-actions="false"
      @close="closeCreateModal"
    >
      <form @submit.prevent="handleCreateService" class="space-y-4">
        <BaseInput
          v-model="form.name"
          label="Service Name"
          placeholder="My Application"
          required
          :error="errors.name"
        />

        <BaseInput
          v-model="form.slug"
          label="Service Slug"
          placeholder="my-app"
          hint="Unique identifier for your service (lowercase, alphanumeric, dashes only)"
          required
          :error="errors.slug"
        />

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Service Type <span class="text-red-500">*</span>
          </label>
          <select
            v-model="form.service_type"
            class="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            required
          >
            <option value="">Select a type</option>
            <option value="web">Web Application</option>
            <option value="mobile">Mobile Application</option>
            <option value="desktop">Desktop Application</option>
            <option value="api">API / Backend Service</option>
          </select>
          <p v-if="errors.service_type" class="mt-1 text-sm text-red-600">
            {{ errors.service_type }}
          </p>
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Redirect URIs <span class="text-red-500">*</span>
          </label>
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
                class="inline-flex items-center px-3 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                @click="removeRedirectUri(index)"
              >
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
          <button
            type="button"
            class="mt-2 inline-flex items-center text-sm text-blue-600 hover:text-blue-700"
            @click="addRedirectUri"
          >
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
            </svg>
            Add Another URI
          </button>
          <p v-if="errors.redirect_uris" class="mt-1 text-sm text-red-600">
            {{ errors.redirect_uris }}
          </p>
        </div>

        <details class="border rounded-md p-4">
          <summary class="cursor-pointer font-medium text-gray-700">
            Advanced: OAuth Scopes (Optional)
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
              <p class="mt-1 text-xs text-gray-500">Comma-separated list</p>
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
              <p class="mt-1 text-xs text-gray-500">Comma-separated list</p>
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
              <p class="mt-1 text-xs text-gray-500">Comma-separated list</p>
            </div>
          </div>
        </details>

        <div class="mt-6 flex justify-end space-x-3 pt-4 border-t">
          <BaseButton
            type="button"
            variant="ghost"
            @click="closeCreateModal"
          >
            Cancel
          </BaseButton>
          <BaseButton
            type="submit"
            variant="primary"
            :loading="creating"
          >
            Create Service
          </BaseButton>
        </div>
      </form>
    </BaseModal>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useServicesStore } from '@/stores/services';
import { useOrganizationStore } from '@/stores/organization';
import { useNotifications } from '@/composables/useNotifications';
import BaseButton from '@/components/BaseButton.vue';
import BaseInput from '@/components/BaseInput.vue';
import BaseModal from '@/components/BaseModal.vue';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import EmptyState from '@/components/EmptyState.vue';

const route = useRoute();
const router = useRouter();
const servicesStore = useServicesStore();
const organizationStore = useOrganizationStore();
const { showSuccess, showError } = useNotifications();

const loading = computed(() => servicesStore.loading);
const services = computed(() => servicesStore.services);
const hasServices = computed(() => servicesStore.hasServices);

const isCreateModalOpen = ref(false);
const creating = ref(false);

const form = ref({
  name: '',
  slug: '',
  service_type: '',
  redirect_uris: [''],
});

const scopesInput = ref({
  github: '',
  google: '',
  microsoft: '',
});

const errors = ref({
  name: '',
  slug: '',
  service_type: '',
  redirect_uris: '',
});

const openCreateModal = () => {
  isCreateModalOpen.value = true;
  resetForm();
};

const closeCreateModal = () => {
  isCreateModalOpen.value = false;
  resetForm();
};

const resetForm = () => {
  form.value = {
    name: '',
    slug: '',
    service_type: '',
    redirect_uris: [''],
  };
  scopesInput.value = {
    github: '',
    google: '',
    microsoft: '',
  };
  errors.value = {
    name: '',
    slug: '',
    service_type: '',
    redirect_uris: '',
  };
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

const handleCreateService = async () => {
  errors.value = {
    name: '',
    slug: '',
    service_type: '',
    redirect_uris: '',
  };

  const validRedirectUris = form.value.redirect_uris.filter(uri => uri.trim().length > 0);

  if (validRedirectUris.length === 0) {
    errors.value.redirect_uris = 'At least one redirect URI is required';
    return;
  }

  const payload = {
    name: form.value.name,
    slug: form.value.slug,
    service_type: form.value.service_type,
    redirect_uris: validRedirectUris,
  };

  const githubScopes = parseScopes(scopesInput.value.github);
  const googleScopes = parseScopes(scopesInput.value.google);
  const microsoftScopes = parseScopes(scopesInput.value.microsoft);

  if (githubScopes.length > 0) payload.github_scopes = githubScopes;
  if (googleScopes.length > 0) payload.google_scopes = googleScopes;
  if (microsoftScopes.length > 0) payload.microsoft_scopes = microsoftScopes;

  creating.value = true;

  try {
    const result = await servicesStore.createService(
      organizationStore.currentOrgSlug,
      payload
    );

    showSuccess('Service created successfully');
    closeCreateModal();

    router.push({
      name: 'ServiceDetail',
      params: {
        orgSlug: organizationStore.currentOrgSlug,
        serviceId: result.service.slug,
      },
    });
  } catch (error) {
    console.error('Failed to create service:', error);

    if (error.response?.data?.error) {
      const errorMsg = error.response.data.error;
      if (errorMsg.toLowerCase().includes('slug')) {
        errors.value.slug = errorMsg;
      } else {
        showError(errorMsg);
      }
    } else {
      showError('Failed to create service. Please try again.');
    }
  } finally {
    creating.value = false;
  }
};

const navigateToService = (service) => {
  router.push({
    name: 'ServiceDetail',
    params: {
      orgSlug: route.params.orgSlug,
      serviceId: service.slug,
    },
  });
};

const getServiceTypeColor = (type) => {
  const colors = {
    web: 'bg-blue-100 text-blue-600',
    mobile: 'bg-purple-100 text-purple-600',
    desktop: 'bg-green-100 text-green-600',
    api: 'bg-orange-100 text-orange-600',
  };
  return colors[type] || 'bg-gray-100 text-gray-600';
};

const getServiceTypeBadgeColor = (type) => {
  const colors = {
    web: 'bg-blue-100 text-blue-800',
    mobile: 'bg-purple-100 text-purple-800',
    desktop: 'bg-green-100 text-green-800',
    api: 'bg-orange-100 text-orange-800',
  };
  return colors[type] || 'bg-gray-100 text-gray-800';
};

const formatClientId = (clientId) => {
  if (!clientId) return '';
  if (clientId.length <= 12) return clientId;
  return `${clientId.substring(0, 8)}...${clientId.substring(clientId.length - 4)}`;
};

onMounted(async () => {
  const orgSlug = route.params.orgSlug;

  if (orgSlug) {
    try {
      if (!organizationStore.currentOrganization || organizationStore.currentOrgSlug !== orgSlug) {
        await organizationStore.fetchOrganization(orgSlug);
      }

      await servicesStore.fetchServices(orgSlug);
    } catch (error) {
      console.error('Failed to load services:', error);
      showError('Failed to load services');
    }
  }
});
</script>
