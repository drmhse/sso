<template>
  <aside class="w-64 bg-white border-r border-gray-200 flex-shrink-0 overflow-y-auto">
    <nav class="mt-6 px-3 pb-6">
      <template v-if="isPlatformOwner">
        <div class="mb-6">
          <h3 class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
            Platform
          </h3>
          <div class="space-y-1">
            <router-link
              to="/platform/dashboard"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive('/platform/dashboard') ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive('/platform/dashboard') ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
              </svg>
              Dashboard
            </router-link>
            <router-link
              to="/platform/organizations"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive('/platform/organizations') ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive('/platform/organizations') ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
              </svg>
              Organizations
            </router-link>
            <router-link
              to="/platform/audit-log"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive('/platform/audit-log') ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive('/platform/audit-log') ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              Audit Log
            </router-link>
          </div>
        </div>
      </template>

      <template v-if="currentOrgSlug">
        <div class="mb-6">
          <h3 class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
            Organization
          </h3>
          <div class="space-y-1">
            <router-link
              :to="`/orgs/${currentOrgSlug}/dashboard`"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive(`/orgs/${currentOrgSlug}/dashboard`) ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive(`/orgs/${currentOrgSlug}/dashboard`) ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
              </svg>
              Dashboard
            </router-link>
            <router-link
              v-if="isOrgActive"
              :to="`/orgs/${currentOrgSlug}/services`"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive(`/orgs/${currentOrgSlug}/services`) ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive(`/orgs/${currentOrgSlug}/services`) ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
              Services
            </router-link>
            <div
              v-else
              @click="handleRestrictedClick($event, 'Services')"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md text-gray-400 opacity-60 cursor-not-allowed"
            >
              <svg class="h-5 w-5 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
              Services
            </div>
            <router-link
              v-if="canManageTeam && isOrgActive"
              :to="`/orgs/${currentOrgSlug}/members`"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive(`/orgs/${currentOrgSlug}/members`) ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive(`/orgs/${currentOrgSlug}/members`) ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
              Team Members
            </router-link>
            <div
              v-else-if="canManageTeam && !isOrgActive"
              @click="handleRestrictedClick($event, 'Team Members')"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md text-gray-400 opacity-60 cursor-not-allowed"
            >
              <svg class="h-5 w-5 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
              </svg>
              Team Members
            </div>
            <router-link
              v-if="isOrgActive"
              :to="`/orgs/${currentOrgSlug}/users`"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive(`/orgs/${currentOrgSlug}/users`) ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive(`/orgs/${currentOrgSlug}/users`) ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
              </svg>
              End Users
            </router-link>
            <div
              v-else
              @click="handleRestrictedClick($event, 'End Users')"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md text-gray-400 opacity-60 cursor-not-allowed"
            >
              <svg class="h-5 w-5 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
              </svg>
              End Users
            </div>
            <router-link
              v-if="isOrgActive"
              :to="`/orgs/${currentOrgSlug}/billing`"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive(`/orgs/${currentOrgSlug}/billing`) ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive(`/orgs/${currentOrgSlug}/billing`) ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
              </svg>
              Billing
            </router-link>
            <div
              v-else
              @click="handleRestrictedClick($event, 'Billing')"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md text-gray-400 opacity-60 cursor-not-allowed"
            >
              <svg class="h-5 w-5 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
              </svg>
              Billing
            </div>
            <router-link
              v-if="isOrgActive"
              :to="`/orgs/${currentOrgSlug}/settings`"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md transition-colors"
              :class="isActive(`/orgs/${currentOrgSlug}/settings`) ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
            >
              <svg class="h-5 w-5" :class="isActive(`/orgs/${currentOrgSlug}/settings`) ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              Settings
            </router-link>
            <div
              v-else
              @click="handleRestrictedClick($event, 'Settings')"
              class="group flex items-center gap-3 px-3 py-2.5 text-sm font-medium rounded-md text-gray-400 opacity-60 cursor-not-allowed"
            >
              <svg class="h-5 w-5 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              Settings
            </div>
          </div>
        </div>
      </template>

      <div class="mb-6">
        <h3 class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">
          User
        </h3>
        <div class="space-y-1">
          <router-link
            to="/invitations"
            class="group flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors"
            :class="isActive('/invitations') ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
          >
            <svg class="h-5 w-5" :class="isActive('/invitations') ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
            Invitations
          </router-link>
          <router-link
            to="/settings/connections"
            class="group flex items-center gap-3 px-3 py-2 text-sm font-medium rounded-md transition-colors"
            :class="isActive('/settings/connections') ? 'bg-blue-50 text-blue-700' : 'text-gray-700 hover:bg-gray-50'"
          >
            <svg class="h-5 w-5" :class="isActive('/settings/connections') ? 'text-blue-600' : 'text-gray-400 group-hover:text-gray-500'" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
            </svg>
            Connected Accounts
          </router-link>
        </div>
      </div>
    </nav>
  </aside>
</template>

<script setup>
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { useOrganizationStore } from '@/stores/organization';
import { usePermissions } from '@/composables/usePermissions';
import { useNotifications } from '@/composables/useNotifications';

const emit = defineEmits(['close']);

const route = useRoute();
const router = useRouter();
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

// Close sidebar on mobile when navigating
router.afterEach(() => {
  emit('close');
});
</script>
