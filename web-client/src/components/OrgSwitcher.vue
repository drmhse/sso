<template>
  <div class="relative" v-if="authStore.currentOrgSlug">
    <!-- Dropdown Button -->
    <button
      @click="isOpen = !isOpen"
      type="button"
      class="inline-flex items-center gap-x-2 rounded-md bg-gray-50 px-3 py-2 text-sm font-medium text-gray-900 hover:bg-gray-100 transition-colors border border-gray-200"
    >
      <div class="flex items-center justify-center h-5 w-5 rounded bg-blue-600 text-white text-xs font-semibold">
        {{ currentOrgInitials }}
      </div>
      <span class="truncate max-w-[150px]">{{ currentOrgName }}</span>
      <svg class="h-4 w-4 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l4-4 4 4m0 6l-4 4-4-4" />
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
        class="absolute left-0 z-10 mt-2 w-72 origin-top-left rounded-lg bg-white shadow-xl ring-1 ring-black ring-opacity-5 focus:outline-none"
        @click.stop
      >
        <div class="py-2">
          <!-- Current Organization Header -->
          <div class="px-4 py-2 border-b border-gray-100">
            <p class="text-xs font-semibold text-gray-500 uppercase tracking-wider">
              Your Organizations
            </p>
          </div>

          <!-- Loading State -->
          <div v-if="loading" class="px-4 py-6 text-sm text-gray-500 text-center">
            <div class="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600 mx-auto"></div>
            <p class="mt-2">Loading organizations...</p>
          </div>

          <!-- Organization List -->
          <div v-else-if="organizations.length > 0" class="max-h-80 overflow-y-auto py-1">
            <button
              v-for="org in organizations"
              :key="org.organization.id"
              @click="switchOrganization(org.organization.slug)"
              class="w-full text-left px-4 py-3 hover:bg-gray-50 flex items-center gap-3 transition-colors group"
              :class="{ 'bg-blue-50 hover:bg-blue-100': org.organization.slug === authStore.currentOrgSlug }"
            >
              <!-- Org Icon/Initials -->
              <div
                class="flex items-center justify-center h-8 w-8 rounded flex-shrink-0 text-white text-xs font-semibold"
                :class="org.organization.slug === authStore.currentOrgSlug ? 'bg-blue-600' : 'bg-gray-400 group-hover:bg-gray-500'"
              >
                {{ getOrgInitials(org.organization.name) }}
              </div>

              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2">
                  <p class="font-medium text-gray-900 truncate text-sm">
                    {{ org.organization.name }}
                  </p>
                  <span
                    v-if="org.organization.slug === authStore.currentOrgSlug"
                    class="inline-flex items-center text-blue-600"
                  >
                    <svg class="h-4 w-4" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd" />
                    </svg>
                  </span>
                </div>
                <div class="flex items-center gap-2 mt-0.5">
                  <p class="text-xs text-gray-500 truncate">{{ org.organization.slug }}</p>
                  <span
                    v-if="org.organization.slug !== authStore.currentOrgSlug"
                    class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
                    :class="{
                      'bg-green-100 text-green-700': org.organization.status === 'active',
                      'bg-yellow-100 text-yellow-700': org.organization.status === 'pending',
                      'bg-gray-100 text-gray-600': org.organization.status === 'suspended'
                    }"
                  >
                    {{ org.organization.status }}
                  </span>
                </div>
              </div>
            </button>
          </div>

          <!-- No Organizations -->
          <div v-else class="px-4 py-8 text-center">
            <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
            </svg>
            <p class="mt-2 text-sm text-gray-500">No organizations found</p>
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

const currentOrgInitials = computed(() => {
  return getOrgInitials(currentOrgName.value);
});

const getOrgInitials = (name) => {
  if (!name) return 'OR';
  const words = name.trim().split(' ');
  if (words.length >= 2) {
    return (words[0][0] + words[1][0]).toUpperCase();
  }
  return name.substring(0, 2).toUpperCase();
};

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
