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
              v-if="isOrgActive"
              :to="`/orgs/${currentOrgSlug}/services`"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive(`/orgs/${currentOrgSlug}/services`) ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Services
            </router-link>
            <div
              v-else
              @click="handleRestrictedClick($event, 'Services')"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md text-gray-600 opacity-50 cursor-not-allowed"
            >
              Services
            </div>
            <router-link
              v-if="canManageTeam && isOrgActive"
              :to="`/orgs/${currentOrgSlug}/members`"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive(`/orgs/${currentOrgSlug}/members`) ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Team Members
            </router-link>
            <div
              v-else-if="canManageTeam && !isOrgActive"
              @click="handleRestrictedClick($event, 'Team Members')"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md text-gray-600 opacity-50 cursor-not-allowed"
            >
              Team Members
            </div>
            <router-link
              v-if="isOrgActive"
              :to="`/orgs/${currentOrgSlug}/settings`"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md hover:bg-gray-50"
              :class="isActive(`/orgs/${currentOrgSlug}/settings`) ? 'bg-gray-100 text-gray-900' : 'text-gray-600'"
            >
              Settings
            </router-link>
            <div
              v-else
              @click="handleRestrictedClick($event, 'Settings')"
              class="group flex items-center px-3 py-2 text-sm font-medium rounded-md text-gray-600 opacity-50 cursor-not-allowed"
            >
              Settings
            </div>
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
import { useOrganizationStore } from '@/stores/organization';
import { usePermissions } from '@/composables/usePermissions';
import { useNotifications } from '@/composables/useNotifications';

const route = useRoute();
const authStore = useAuthStore();
const organizationStore = useOrganizationStore();
const { isPlatformOwner, canManageTeam } = usePermissions();
const { showWarning } = useNotifications();

const currentOrgSlug = computed(() => authStore.currentOrgSlug);
const isOrgActive = computed(() => organizationStore.isActive);

const isActive = (path) => {
  return route.path === path || route.path.startsWith(path + '/');
};

const handleRestrictedClick = (event, feature) => {
  if (!isOrgActive.value) {
    event.preventDefault();
    showWarning(`${feature} is only available for active organizations. Your organization is awaiting approval.`);
  }
};
</script>
