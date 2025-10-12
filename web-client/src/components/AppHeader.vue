<template>
  <header class="bg-white border-b border-gray-200 flex-shrink-0">
    <div class="px-4 sm:px-6 lg:px-8">
      <div class="flex justify-between h-16">
        <!-- Left section: Logo and main navigation -->
        <div class="flex items-center space-x-3 sm:space-x-8">
          <!-- Mobile Menu Button -->
          <button
            @click="$emit('toggle-sidebar')"
            class="lg:hidden p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-md transition-colors"
            aria-label="Toggle sidebar"
          >
            <svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>

          <!-- Logo -->
          <router-link
            :to="homeRoute"
            class="flex items-center space-x-2 hover:opacity-80 transition-opacity"
          >
            <div class="flex items-center justify-center h-8 w-8 rounded bg-blue-600">
              <svg class="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <span class="text-xl font-bold text-gray-900 hidden sm:inline">SSO</span>
          </router-link>

          <!-- Organization Switcher - Hide on small mobile -->
          <OrgSwitcher v-if="authStore.currentOrgSlug" class="hidden sm:block" />
        </div>

        <!-- Right section: User menu and actions -->
        <div class="flex items-center space-x-2 sm:space-x-3">
          <!-- Invitations Badge - Hide on small mobile -->
          <router-link
            to="/invitations"
            class="hidden sm:flex relative p-2 text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded-md transition-colors"
            title="Invitations"
          >
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </router-link>

          <!-- Divider - Hide on mobile -->
          <div class="hidden sm:block h-6 w-px bg-gray-300"></div>

          <!-- User Menu Dropdown -->
          <div class="relative">
            <button
              @click="isUserMenuOpen = !isUserMenuOpen"
              type="button"
              class="flex items-center space-x-2 sm:space-x-3 px-2 sm:px-3 py-2 rounded-md hover:bg-gray-100 transition-colors"
            >
              <!-- User Avatar/Initials -->
              <div class="flex items-center justify-center h-8 w-8 rounded-full bg-gradient-to-br from-blue-500 to-blue-600 text-white text-sm font-semibold">
                {{ userInitials }}
              </div>
              <div class="hidden md:block text-left">
                <p class="text-sm font-medium text-gray-900 max-w-[150px] truncate">
                  {{ userName }}
                </p>
                <p class="text-xs text-gray-500 max-w-[150px] truncate">
                  {{ authStore.userEmail }}
                </p>
              </div>
              <svg class="h-4 w-4 text-gray-400 hidden sm:block" fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
                v-if="isUserMenuOpen"
                class="absolute right-0 z-10 mt-2 w-64 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none"
                @click.stop
              >
                <div class="py-1">
                  <!-- User Info Header -->
                  <div class="px-4 py-3 border-b border-gray-100">
                    <p class="text-sm font-medium text-gray-900 truncate">
                      {{ authStore.userEmail }}
                    </p>
                    <p class="text-xs text-gray-500 mt-1">
                      {{ userRole }}
                    </p>
                  </div>

                  <!-- Navigation Links -->
                  <div class="py-1">
                    <router-link
                      to="/settings/connections"
                      @click="isUserMenuOpen = false"
                      class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                    >
                      <div class="flex items-center">
                        <svg class="mr-3 h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
                        </svg>
                        Connected Accounts
                      </div>
                    </router-link>

                    <router-link
                      to="/invitations"
                      @click="isUserMenuOpen = false"
                      class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                    >
                      <div class="flex items-center">
                        <svg class="mr-3 h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                        </svg>
                        My Invitations
                      </div>
                    </router-link>
                  </div>

                  <!-- Platform Owner Links -->
                  <div v-if="authStore.isPlatformOwner" class="border-t border-gray-100 py-1">
                    <div class="px-4 py-2 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                      Platform
                    </div>
                    <router-link
                      to="/platform/dashboard"
                      @click="isUserMenuOpen = false"
                      class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                    >
                      <div class="flex items-center">
                        <svg class="mr-3 h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                        </svg>
                        Platform Dashboard
                      </div>
                    </router-link>
                    <router-link
                      to="/platform/organizations"
                      @click="isUserMenuOpen = false"
                      class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                    >
                      <div class="flex items-center">
                        <svg class="mr-3 h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                        </svg>
                        All Organizations
                      </div>
                    </router-link>
                    <router-link
                      to="/platform/audit-log"
                      @click="isUserMenuOpen = false"
                      class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 transition-colors"
                    >
                      <div class="flex items-center">
                        <svg class="mr-3 h-5 w-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        Audit Log
                      </div>
                    </router-link>
                  </div>

                  <!-- Sign Out -->
                  <div class="border-t border-gray-100 py-1">
                    <button
                      @click="handleLogout"
                      class="block w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors"
                    >
                      <div class="flex items-center">
                        <svg class="mr-3 h-5 w-5 text-red-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                        </svg>
                        Sign out
                      </div>
                    </button>
                  </div>
                </div>
              </div>
            </Transition>

            <!-- Click outside to close -->
            <div v-if="isUserMenuOpen" class="fixed inset-0 z-0" @click="isUserMenuOpen = false"></div>
          </div>
        </div>
      </div>
    </div>
  </header>
</template>

<script setup>
import { ref, computed } from 'vue';
import { useRouter } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import OrgSwitcher from '@/components/OrgSwitcher.vue';

defineEmits(['toggle-sidebar']);

const router = useRouter();
const authStore = useAuthStore();
const isUserMenuOpen = ref(false);

const userInitials = computed(() => {
  const email = authStore.userEmail || '';
  if (authStore.user?.name) {
    const nameParts = authStore.user.name.split(' ');
    if (nameParts.length >= 2) {
      return (nameParts[0][0] + nameParts[nameParts.length - 1][0]).toUpperCase();
    }
    return nameParts[0].substring(0, 2).toUpperCase();
  }
  return email.substring(0, 2).toUpperCase();
});

const userName = computed(() => {
  return authStore.user?.name || authStore.userEmail?.split('@')[0] || 'User';
});

const userRole = computed(() => {
  if (authStore.isPlatformOwner) {
    return 'Platform Owner';
  }
  if (authStore.currentRole) {
    return authStore.currentRole.charAt(0).toUpperCase() + authStore.currentRole.slice(1);
  }
  return 'Member';
});

const homeRoute = computed(() => {
  if (authStore.isPlatformOwner) {
    return '/platform/dashboard';
  }
  if (authStore.currentOrgSlug) {
    return `/orgs/${authStore.currentOrgSlug}/dashboard`;
  }
  return '/home';
});

const handleLogout = () => {
  isUserMenuOpen.value = false;
  authStore.logout();
  router.push('/login');
};
</script>
