<template>
  <aside class="w-64 bg-white shadow-sm min-h-screen">
    <nav class="mt-5 px-2">
      <template v-if="isPlatformOwner">
        <div class="mb-4">
          <h3 class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Platform
          </h3>
          <div class="mt-2 space-y-1">
            <router-link
              to="/platform/dashboard"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive('/platform/dashboard') ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Dashboard
            </router-link>
            <router-link
              to="/platform/organizations"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive('/platform/organizations') ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Organizations
            </router-link>
          </div>
        </div>
      </template>

      <template v-if="currentOrgSlug">
        <div class="mb-4">
          <h3 class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
            Organization
          </h3>
          <div class="mt-2 space-y-1">
            <router-link
              :to="`/orgs/${currentOrgSlug}/dashboard`"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive(`/orgs/${currentOrgSlug}/dashboard`) ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Dashboard
            </router-link>
            <router-link
              :to="`/orgs/${currentOrgSlug}/services`"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive(`/orgs/${currentOrgSlug}/services`) ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Services
            </router-link>
            <router-link
              v-if="canManageTeam"
              :to="`/orgs/${currentOrgSlug}/members`"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive(`/orgs/${currentOrgSlug}/members`) ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Team Members
            </router-link>
            <router-link
              :to="`/orgs/${currentOrgSlug}/settings`"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive(`/orgs/${currentOrgSlug}/settings`) ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Settings
            </router-link>
          </div>
        </div>
      </template>

      <div class="mb-4">
        <h3 class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
          User
        </h3>
        <div class="mt-2 space-y-1">
          <router-link
            to="/invitations"
            class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
            :class="isActive('/invitations') ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
          >
            Invitations
          </router-link>
        </div>
      </div>
    </nav>
  </aside>
</template>

<script setup>
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { usePermissions } from '@/composables/usePermissions';

const route = useRoute();
const authStore = useAuthStore();
const { isPlatformOwner, canManageTeam } = usePermissions();

const currentOrgSlug = computed(() => authStore.currentOrgSlug);

const isActive = (path) => {
  return route.path === path || route.path.startsWith(path + '/');
};
</script>
