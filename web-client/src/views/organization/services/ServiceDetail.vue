<template>
  <div>
    <div v-if="loading && !currentService" class="flex justify-center items-center py-12">
      <LoadingSpinner />
    </div>

    <div v-else-if="currentService">
      <div class="mb-6">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-4">
            <button
              @click="navigateBack"
              class="inline-flex items-center text-sm text-gray-500 hover:text-gray-700"
            >
              <svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
              </svg>
              Back to Services
            </button>
          </div>
        </div>

        <div class="mt-4">
          <h1 class="text-2xl font-bold text-gray-900">{{ currentService?.service?.name || 'Service Details' }}</h1>
          <p class="mt-1 text-sm text-gray-600 font-mono">{{ currentService?.service?.slug }}</p>
        </div>
      </div>

      <div class="border-b border-gray-200 mb-6">
        <nav class="-mb-px flex space-x-8">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            @click="activeTab = tab.id"
            :class="[
              activeTab === tab.id
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300',
              'whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm cursor-pointer'
            ]"
          >
            {{ tab.name }}
          </button>
        </nav>
      </div>

      <div v-show="activeTab === 'settings'">
        <ServiceSettings />
      </div>

      <div v-show="activeTab === 'byoo'">
        <BYOOCredentials />
      </div>

      <div v-show="activeTab === 'plans'">
        <ServicePlans />
      </div>
    </div>

    <div v-else class="text-center py-12">
      <p class="text-gray-500">Service not found</p>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useServicesStore } from '@/stores/services';
import { useOrganizationStore } from '@/stores/organization';
import { useNotifications } from '@/composables/useNotifications';
import LoadingSpinner from '@/components/LoadingSpinner.vue';
import ServiceSettings from './components/ServiceSettings.vue';
import BYOOCredentials from './components/BYOOCredentials.vue';
import ServicePlans from './components/ServicePlans.vue';

const route = useRoute();
const router = useRouter();
const servicesStore = useServicesStore();
const organizationStore = useOrganizationStore();
const { error: showError } = useNotifications();

const activeTab = ref('settings');
const loading = computed(() => servicesStore.loading);
const currentService = computed(() => servicesStore.currentService);

const tabs = [
  { id: 'settings', name: 'Settings' },
  { id: 'byoo', name: 'BYOO Credentials' },
  { id: 'plans', name: 'Plans' },
];

const navigateBack = () => {
  router.push({
    name: 'ServiceList',
    params: { orgSlug: route.params.orgSlug },
  });
};

onMounted(async () => {
  const { orgSlug, serviceId } = route.params;

  if (orgSlug && serviceId) {
    try {
      if (!organizationStore.currentOrganization || organizationStore.currentOrgSlug !== orgSlug) {
        await organizationStore.fetchOrganization(orgSlug);
      }

      await servicesStore.fetchService(orgSlug, serviceId);
      await servicesStore.fetchAllOAuthCredentials(orgSlug);
    } catch (error) {
      console.error('Failed to load service:', error);
      showError('Failed to load service details');
    }
  }
});
</script>
