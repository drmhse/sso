<template>
  <div>
    <div class="mb-6">
      <h1 class="text-2xl font-bold text-gray-900">Billing & Subscription</h1>
      <p class="mt-2 text-gray-600">Manage your organization's subscription plan and billing.</p>
    </div>

    <!-- Loading State -->
    <div v-if="loading" class="text-center py-12">
      <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      <p class="mt-2 text-gray-600">Loading billing information...</p>
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="bg-red-50 border-l-4 border-red-400 p-4 rounded">
      <p class="text-sm text-red-700">{{ error }}</p>
    </div>

    <!-- Billing Content -->
    <div v-else class="space-y-6">
      <!-- Current Plan -->
      <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h2 class="text-lg font-semibold text-gray-900">Current Plan</h2>
        </div>
        <div class="px-6 py-6">
          <div v-if="currentTier" class="flex items-center justify-between">
            <div class="flex-1">
              <div class="flex items-center space-x-4">
                <div class="flex-shrink-0">
                  <div class="w-16 h-16 bg-blue-600 rounded-lg flex items-center justify-center">
                    <svg class="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
                    </svg>
                  </div>
                </div>
                <div>
                  <h3 class="text-2xl font-bold text-gray-900">{{ currentTier.display_name }}</h3>
                  <p class="text-sm text-gray-600 mt-1">{{ currentTier.description || 'Current subscription tier' }}</p>
                </div>
              </div>

              <div class="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="bg-gray-50 rounded-lg p-4">
                  <p class="text-sm text-gray-600">Services</p>
                  <p class="text-2xl font-bold text-gray-900 mt-1">
                    {{ organizationData.service_count }} / {{ currentTier.default_max_services }}
                  </p>
                </div>
                <div class="bg-gray-50 rounded-lg p-4">
                  <p class="text-sm text-gray-600">Team Members</p>
                  <p class="text-2xl font-bold text-gray-900 mt-1">
                    {{ organizationData.membership_count }} / {{ currentTier.default_max_users }}
                  </p>
                </div>
                <div class="bg-gray-50 rounded-lg p-4">
                  <p class="text-sm text-gray-600">Status</p>
                  <p class="mt-1">
                    <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold bg-green-100 text-green-800">
                      Active
                    </span>
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div v-else class="text-center py-8 text-gray-500">
            No tier information available
          </div>
        </div>
      </div>

      <!-- Billing Information Placeholder -->
      <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h2 class="text-lg font-semibold text-gray-900">Payment Method</h2>
        </div>
        <div class="px-6 py-6">
          <div class="bg-blue-50 border-l-4 border-blue-400 p-4 rounded">
            <div class="flex">
              <div class="flex-shrink-0">
                <svg class="h-5 w-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div class="ml-3">
                <p class="text-sm text-blue-700">
                  Payment method management will be available once Stripe integration is fully configured.
                  Contact the platform owner for billing inquiries.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Usage & Limits -->
      <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h2 class="text-lg font-semibold text-gray-900">Usage & Limits</h2>
        </div>
        <div class="px-6 py-6 space-y-6">
          <!-- Services Usage -->
          <div>
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm font-medium text-gray-700">Services</span>
              <span class="text-sm text-gray-600">
                {{ organizationData.service_count }} of {{ effectiveMaxServices }} used
              </span>
            </div>
            <div class="w-full bg-gray-200 rounded-full h-3">
              <div
                class="h-3 rounded-full transition-all duration-300"
                :class="getUsageClass(servicesUsagePercentage)"
                :style="{ width: servicesUsagePercentage + '%' }"
              ></div>
            </div>
          </div>

          <!-- Members Usage -->
          <div>
            <div class="flex items-center justify-between mb-2">
              <span class="text-sm font-medium text-gray-700">Team Members</span>
              <span class="text-sm text-gray-600">
                {{ organizationData.membership_count }} of {{ effectiveMaxUsers }} used
              </span>
            </div>
            <div class="w-full bg-gray-200 rounded-full h-3">
              <div
                class="h-3 rounded-full transition-all duration-300"
                :class="getUsageClass(membersUsagePercentage)"
                :style="{ width: membersUsagePercentage + '%' }"
              ></div>
            </div>
          </div>

          <!-- Upgrade CTA if nearing limits -->
          <div v-if="servicesUsagePercentage > 80 || membersUsagePercentage > 80" class="mt-4 bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded">
            <div class="flex">
              <div class="flex-shrink-0">
                <svg class="h-5 w-5 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div class="ml-3">
                <h3 class="text-sm font-medium text-yellow-800">
                  Approaching Limit
                </h3>
                <div class="mt-2 text-sm text-yellow-700">
                  <p>You're nearing your plan limits. Consider upgrading to avoid service interruption.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Available Plans -->
      <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h2 class="text-lg font-semibold text-gray-900">Available Plans</h2>
        </div>
        <div class="px-6 py-6">
          <div class="bg-blue-50 border-l-4 border-blue-400 p-4 rounded">
            <div class="flex">
              <div class="flex-shrink-0">
                <svg class="h-5 w-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <div class="ml-3">
                <p class="text-sm text-blue-700">
                  Plan upgrades and downgrades will be available once tier management is fully implemented.
                  Contact the platform owner to discuss changing your subscription tier.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Billing History Placeholder -->
      <div class="bg-white shadow rounded-lg">
        <div class="px-6 py-4 border-b border-gray-200">
          <h2 class="text-lg font-semibold text-gray-900">Billing History</h2>
        </div>
        <div class="px-6 py-6">
          <div class="text-center py-8">
            <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <p class="mt-2 text-sm text-gray-500">No billing history available</p>
            <p class="mt-1 text-xs text-gray-400">Invoice history will appear here once billing is configured</p>
          </div>
        </div>
      </div>

      <!-- Support Contact -->
      <div class="bg-gray-50 border border-gray-200 rounded-lg p-6">
        <div class="flex items-start">
          <div class="flex-shrink-0">
            <svg class="h-6 w-6 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 5.636l-3.536 3.536m0 5.656l3.536 3.536M9.172 9.172L5.636 5.636m3.536 9.192l-3.536 3.536M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-5 0a4 4 0 11-8 0 4 4 0 018 0z" />
            </svg>
          </div>
          <div class="ml-3">
            <h3 class="text-sm font-medium text-gray-900">Need help with billing?</h3>
            <p class="mt-2 text-sm text-gray-600">
              If you have questions about your subscription, billing, or need to make changes to your plan,
              please contact the platform administrator.
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { sso } from '@/api';

const route = useRoute();

const loading = ref(true);
const error = ref(null);

const organizationData = ref({
  organization: {},
  tier: null,
  membership_count: 0,
  service_count: 0
});

const currentTier = computed(() => organizationData.value.tier);

const effectiveMaxServices = computed(() => {
  const org = organizationData.value.organization;
  if (org.max_services !== null && org.max_services !== undefined) {
    return org.max_services;
  }
  return currentTier.value?.default_max_services || 0;
});

const effectiveMaxUsers = computed(() => {
  const org = organizationData.value.organization;
  if (org.max_users !== null && org.max_users !== undefined) {
    return org.max_users;
  }
  return currentTier.value?.default_max_users || 0;
});

const servicesUsagePercentage = computed(() => {
  if (effectiveMaxServices.value === 0) return 0;
  return Math.min((organizationData.value.service_count / effectiveMaxServices.value) * 100, 100);
});

const membersUsagePercentage = computed(() => {
  if (effectiveMaxUsers.value === 0) return 0;
  return Math.min((organizationData.value.membership_count / effectiveMaxUsers.value) * 100, 100);
});

const getUsageClass = (percentage) => {
  if (percentage >= 90) return 'bg-red-500';
  if (percentage >= 75) return 'bg-yellow-500';
  return 'bg-green-500';
};

const loadBillingData = async () => {
  try {
    loading.value = true;
    error.value = null;

    const orgSlug = route.params.orgSlug;
    const data = await sso.organizations.get(orgSlug);

    organizationData.value = data;

  } catch (err) {
    console.error('Failed to load billing data:', err);
    error.value = 'Failed to load billing information. Please try refreshing the page.';
  } finally {
    loading.value = false;
  }
};

onMounted(async () => {
  await loadBillingData();
});
</script>
