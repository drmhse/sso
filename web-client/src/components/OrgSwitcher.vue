<template>
  <div class="relative" v-if="authStore.currentOrgSlug">
    <!-- Dropdown Button -->
    <button
      @click="isOpen = !isOpen"
      type="button"
      class="inline-flex items-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50"
    >
      <svg class="h-4 w-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
      </svg>
      <span class="truncate max-w-[150px]">{{ currentOrgName }}</span>
      <svg class="h-4 w-4 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
      </svg>
    </button>

    <!-- Dropdown Menu -->
    <Transition
      enter-active-class="transition ease-out duration-100"
      enter-from-class="transform opacity-0 scale-95"
      enter-to-class="transform opacity-100 scale-100"
      leave-active-class="transition ease-in duration-75"
      leave-from-class="transform opacity-100 scale-100"
      leave-to-class="transform opacity-0 scale-95"
    >
      <div
        v-if="isOpen"
        class="absolute right-0 z-10 mt-2 w-64 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none"
        @click.stop
      >
        <div class="py-1">
          <!-- Current Organization Header -->
          <div class="px-4 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider border-b">
            Your Organizations
          </div>

          <!-- Loading State -->
          <div v-if="loading" class="px-4 py-3 text-sm text-gray-500 text-center">
            Loading...
          </div>

          <!-- Organization List -->
          <div v-else-if="organizations.length > 0" class="max-h-64 overflow-y-auto">
            <button
              v-for="org in organizations"
              :key="org.organization.id"
              @click="switchOrganization(org.organization.slug)"
              class="w-full text-left px-4 py-2 text-sm hover:bg-gray-100 flex items-center justify-between"
              :class="{ 'bg-blue-50': org.organization.slug === authStore.currentOrgSlug }"
            >
              <div class="flex-1 min-w-0">
                <p class="font-medium text-gray-900 truncate">{{ org.organization.name }}</p>
                <p class="text-xs text-gray-500 truncate">{{ org.organization.slug }}</p>
              </div>
              <span
                v-if="org.organization.slug === authStore.currentOrgSlug"
                class="ml-2 inline-flex items-center text-blue-600"
              >
                <svg class="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                </svg>
              </span>
              <span
                v-else
                class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
                :class="{
                  'bg-green-100 text-green-800': org.organization.status === 'active',
                  'bg-yellow-100 text-yellow-800': org.organization.status === 'pending',
                  'bg-gray-100 text-gray-800': org.organization.status === 'suspended'
                }"
              >
                {{ org.organization.status }}
              </span>
            </button>
          </div>

          <!-- No Organizations -->
          <div v-else class="px-4 py-3 text-sm text-gray-500 text-center">
            No organizations found
          </div>
        </div>
      </div>
    </Transition>

    <!-- Click outside to close -->
    <div v-if="isOpen" class="fixed inset-0 z-0" @click="isOpen = false"></div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { sso } from '@/api';

const router = useRouter();
const route = useRoute();
const authStore = useAuthStore();

const isOpen = ref(false);
const loading = ref(false);
const organizations = ref([]);

const currentOrgName = computed(() => {
  const currentOrg = organizations.value.find(
    org => org.organization.slug === authStore.currentOrgSlug
  );
  return currentOrg?.organization.name || authStore.currentOrgSlug || 'Select Organization';
});

const loadOrganizations = async () => {
  try {
    loading.value = true;
    const orgs = await sso.organizations.list({ status: 'active' });
    organizations.value = orgs;
  } catch (error) {
    console.error('Failed to load organizations:', error);
  } finally {
    loading.value = false;
  }
};

const switchOrganization = async (orgSlug) => {
  if (orgSlug === authStore.currentOrgSlug) {
    isOpen.value = false;
    return;
  }

  try {
    // Get admin login URL for the target organization
    const loginUrl = sso.auth.getAdminLoginUrl('github', { org_slug: orgSlug });

    // Redirect to admin login for the selected org
    window.location.href = loginUrl;
  } catch (error) {
    console.error('Failed to switch organization:', error);
  }
};

onMounted(() => {
  loadOrganizations();
});
</script>
