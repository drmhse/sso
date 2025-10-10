<template>
  <div>
    <h1 class="text-2xl font-bold text-gray-900">Organization Dashboard</h1>
    <p class="mt-2 text-gray-600">Welcome to your organization dashboard.</p>

    <!-- Pending Approval State -->
    <div v-if="!organizationStore.isActive" class="mt-6">
      <div class="bg-yellow-50 border-l-4 border-yellow-400 p-6 rounded-lg">
        <div class="flex">
          <div class="flex-shrink-0">
            <svg class="h-6 w-6 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <div class="ml-3">
            <h3 class="text-lg font-medium text-yellow-800">
              Organization Pending Approval
            </h3>
            <div class="mt-2 text-sm text-yellow-700">
              <p>Your organization <span class="font-semibold">{{ organizationStore.currentOrgName }}</span> is currently awaiting platform owner approval.</p>
              <p class="mt-2">You'll be able to access the following features once approved:</p>
              <ul class="mt-2 ml-5 list-disc space-y-1">
                <li>Create and manage services</li>
                <li>Configure custom OAuth credentials (BYOO)</li>
                <li>View and manage end users</li>
                <li>Full dashboard access</li>
              </ul>
              <p class="mt-3 text-xs">Current status: <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase" :class="{
                'bg-yellow-100 text-yellow-800': organizationStore.currentOrgStatus === 'pending',
                'bg-green-100 text-green-800': organizationStore.currentOrgStatus === 'active',
                'bg-red-100 text-red-800': organizationStore.currentOrgStatus === 'rejected',
                'bg-gray-100 text-gray-800': organizationStore.currentOrgStatus === 'suspended'
              }">{{ organizationStore.currentOrgStatus || 'Loading...' }}</span></p>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Active Organization Dashboard -->
    <div v-else class="mt-6 bg-white shadow rounded-lg p-6">
      <p class="text-sm text-gray-500">Organization dashboard will be implemented in future phases.</p>
    </div>
  </div>
</template>

<script setup>
import { onMounted } from 'vue';
import { useRoute } from 'vue-router';
import { useOrganizationStore } from '@/stores/organization';

const route = useRoute();
const organizationStore = useOrganizationStore();

onMounted(async () => {
  const orgSlug = route.params.orgSlug;
  if (orgSlug && !organizationStore.currentOrganization) {
    try {
      await organizationStore.fetchOrganization(orgSlug);
    } catch (error) {
      console.error('Failed to fetch organization:', error);
    }
  }
});
</script>
