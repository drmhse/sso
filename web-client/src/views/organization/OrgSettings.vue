<template>
  <div>
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900">Organization Settings</h1>
      <p class="mt-2 text-gray-600">Manage your organization's configuration and settings.</p>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      <p class="mt-2 text-gray-600">Loading settings...</p>
    </div>

    <!-- Error State -->
    <div v-else-if="loadError" class="bg-red-50 border-l-4 border-red-400 p-4 rounded">
      <p class="text-sm text-red-700">{{ loadError }}</p>
    </div>

    <!-- Settings Content -->
    <div v-else class="space-y-6">
      <!-- Success Message -->
      <div v-if="successMessage" class="bg-green-50 border-l-4 border-green-400 p-4 rounded">
        <p class="text-sm text-green-700">{{ successMessage }}</p>
      </div>

      <!-- Basic Information -->
      <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h2 class="text-lg font-semibold text-gray-900">Basic Information</h2>
        </div>
        <div class="px-6 py-6 space-y-6">
          <!-- Organization Name -->
          <div>
            <label for="org-name" class="block text-sm font-medium text-gray-700 mb-2">
              Organization Name
            </label>
            <input
              id="org-name"
              v-model="formData.name"
              type="text"
              class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="Enter organization name"
              :disabled="saving"
            />
          </div>

          <!-- Organization Slug (Read-only) -->
          <div>
            <label for="org-slug" class="block text-sm font-medium text-gray-700 mb-2">
              Organization Slug
            </label>
            <input
              id="org-slug"
              v-model="orgData.slug"
              type="text"
              class="w-full px-4 py-2 border border-gray-300 rounded-lg bg-gray-50 text-gray-500"
              disabled
              readonly
            />
            <p class="mt-1 text-xs text-gray-500">The organization slug cannot be changed.</p>
          </div>

          <!-- Organization Status -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Status
            </label>
            <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold uppercase" :class="{
              'bg-yellow-100 text-yellow-800': orgData.status === 'pending',
              'bg-green-100 text-green-800': orgData.status === 'active',
              'bg-red-100 text-red-800': orgData.status === 'rejected',
              'bg-gray-100 text-gray-800': orgData.status === 'suspended'
            }">
              {{ orgData.status }}
            </span>
          </div>

          <!-- Save Button -->
          <div class="flex items-center justify-between pt-4 border-t border-gray-200">
            <button
              @click="saveBasicSettings"
              :disabled="saving || !hasBasicChanges"
              class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {{ saving ? 'Saving...' : 'Save Changes' }}
            </button>
            <button
              v-if="hasBasicChanges"
              @click="resetBasicForm"
              :disabled="saving"
              class="px-4 py-2 text-gray-600 hover:text-gray-900 transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>

      <!-- Tier & Limits Information -->
      <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h2 class="text-lg font-semibold text-gray-900">Subscription & Limits</h2>
        </div>
        <div class="px-6 py-6 space-y-4">
          <!-- Current Tier -->
          <div v-if="orgData.tier">
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Current Tier
            </label>
            <div class="flex items-center">
              <span class="inline-flex items-center px-4 py-2 rounded-lg bg-blue-50 text-blue-700 font-semibold">
                {{ orgData.tier.display_name }}
              </span>
            </div>
          </div>

          <!-- Service Limit -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Service Limit
            </label>
            <div class="flex items-center space-x-4">
              <div class="flex-1">
                <div class="text-2xl font-bold text-gray-900">
                  {{ orgData.service_count }} / {{ effectiveMaxServices }}
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2 mt-2">
                  <div
                    class="h-2 rounded-full transition-all duration-300"
                    :class="serviceLimitClass"
                    :style="{ width: serviceLimitPercentage + '%' }"
                  ></div>
                </div>
              </div>
            </div>
            <p class="mt-1 text-xs text-gray-500">
              {{ orgData.service_count }} services created out of {{ effectiveMaxServices }} allowed
            </p>
          </div>

          <!-- Member Limit -->
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-2">
              Member Limit
            </label>
            <div class="flex items-center space-x-4">
              <div class="flex-1">
                <div class="text-2xl font-bold text-gray-900">
                  {{ orgData.membership_count }} / {{ effectiveMaxUsers }}
                </div>
                <div class="w-full bg-gray-200 rounded-full h-2 mt-2">
                  <div
                    class="h-2 rounded-full transition-all duration-300"
                    :class="memberLimitClass"
                    :style="{ width: memberLimitPercentage + '%' }"
                  ></div>
                </div>
              </div>
            </div>
            <p class="mt-1 text-xs text-gray-500">
              {{ orgData.membership_count }} members out of {{ effectiveMaxUsers }} allowed
            </p>
          </div>
        </div>
      </div>

      <!-- Danger Zone (Owner Only) -->
      <div v-if="isOwner" class="bg-white shadow rounded-lg border-2 border-red-200">
        <div class="px-6 py-4 border-b border-red-200 bg-red-50">
          <h2 class="text-lg font-semibold text-red-900">Danger Zone</h2>
        </div>
        <div class="px-6 py-6">
          <div class="flex items-start justify-between">
            <div class="flex-1">
              <h3 class="text-sm font-semibold text-gray-900">Delete Organization</h3>
              <p class="mt-1 text-sm text-gray-600">
                Permanently delete this organization and all associated data. This action cannot be undone.
              </p>
            </div>
            <button
              class="ml-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 transition-colors"
              @click="showDeleteWarning = true"
            >
              Delete Organization
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div v-if="showDeleteWarning" class="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50 flex items-center justify-center">
      <div class="relative p-8 bg-white w-full max-w-md m-4 rounded-lg shadow-xl">
        <h3 class="text-lg font-semibold text-gray-900 mb-4">Delete Organization</h3>
        <p class="text-sm text-gray-600 mb-6">
          This feature is not yet implemented. Organization deletion will be available in a future update.
        </p>
        <div class="flex justify-end">
          <button
            @click="showDeleteWarning = false"
            class="px-4 py-2 bg-gray-200 text-gray-800 rounded-lg hover:bg-gray-300 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { useOrganizationStore } from '@/stores/organization';
import { sso } from '@/api';

const route = useRoute();
const organizationStore = useOrganizationStore();

const loading = ref(true);
const loadError = ref(null);
const saving = ref(false);
const successMessage = ref(null);
const showDeleteWarning = ref(false);

const orgData = ref({
  slug: '',
  name: '',
  status: '',
  tier: null,
  membership_count: 0,
  service_count: 0,
  max_services: null,
  max_users: null
});

const formData = ref({
  name: ''
});

const originalFormData = ref({
  name: ''
});

// Check if user is owner
const isOwner = computed(() => {
  // This would need to check the user's role in the organization
  // For now, we'll assume they have permission if they can access this page
  return true;
});

// Computed values for limits
const effectiveMaxServices = computed(() => {
  if (orgData.value.max_services !== null) {
    return orgData.value.max_services;
  }
  return orgData.value.tier?.default_max_services || 0;
});

const effectiveMaxUsers = computed(() => {
  if (orgData.value.max_users !== null) {
    return orgData.value.max_users;
  }
  return orgData.value.tier?.default_max_users || 0;
});

const serviceLimitPercentage = computed(() => {
  if (effectiveMaxServices.value === 0) return 0;
  return Math.min((orgData.value.service_count / effectiveMaxServices.value) * 100, 100);
});

const memberLimitPercentage = computed(() => {
  if (effectiveMaxUsers.value === 0) return 0;
  return Math.min((orgData.value.membership_count / effectiveMaxUsers.value) * 100, 100);
});

const serviceLimitClass = computed(() => {
  const percentage = serviceLimitPercentage.value;
  if (percentage >= 90) return 'bg-red-500';
  if (percentage >= 75) return 'bg-yellow-500';
  return 'bg-green-500';
});

const memberLimitClass = computed(() => {
  const percentage = memberLimitPercentage.value;
  if (percentage >= 90) return 'bg-red-500';
  if (percentage >= 75) return 'bg-yellow-500';
  return 'bg-green-500';
});

// Check for changes
const hasBasicChanges = computed(() => {
  return formData.value.name !== originalFormData.value.name;
});

// Load organization data
const loadOrganizationData = async () => {
  try {
    loading.value = true;
    loadError.value = null;

    const orgSlug = route.params.orgSlug;
    const data = await sso.organizations.get(orgSlug);

    orgData.value = {
      slug: data.organization.slug,
      name: data.organization.name,
      status: data.organization.status,
      tier: data.tier,
      membership_count: data.membership_count,
      service_count: data.service_count,
      max_services: data.organization.max_services,
      max_users: data.organization.max_users
    };

    formData.value = {
      name: data.organization.name
    };

    originalFormData.value = { ...formData.value };

  } catch (error) {
    console.error('Failed to load organization data:', error);
    loadError.value = 'Failed to load organization settings. Please try refreshing the page.';
  } finally {
    loading.value = false;
  }
};

// Save basic settings
const saveBasicSettings = async () => {
  try {
    saving.value = true;
    successMessage.value = null;

    const orgSlug = route.params.orgSlug;
    const payload = {
      name: formData.value.name
    };

    await organizationStore.updateOrganization(orgSlug, payload);

    orgData.value.name = formData.value.name;
    originalFormData.value.name = formData.value.name;

    successMessage.value = 'Organization settings updated successfully!';
    setTimeout(() => {
      successMessage.value = null;
    }, 3000);

  } catch (error) {
    console.error('Failed to save settings:', error);
    loadError.value = 'Failed to save settings. Please try again.';
  } finally {
    saving.value = false;
  }
};

// Reset forms
const resetBasicForm = () => {
  formData.value.name = originalFormData.value.name;
};

onMounted(async () => {
  await loadOrganizationData();
});
</script>
