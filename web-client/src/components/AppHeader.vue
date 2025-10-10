<template>
  <header class="bg-white shadow">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
      <div class="flex justify-between h-16">
        <div class="flex items-center">
          <h1 class="text-xl font-bold text-gray-900">SSO Admin</h1>
        </div>

        <div class="flex items-center space-x-4">
          <span class="text-sm text-gray-700">{{ authStore.userEmail }}</span>

          <button
            @click="handleLogout"
            class="text-sm text-gray-700 hover:text-gray-900 px-3 py-2 rounded-md hover:bg-gray-100"
          >
            Sign out
          </button>
        </div>
      </div>
    </div>
  </header>
</template>

<script setup>
import { useRouter } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const authStore = useAuthStore();

const handleLogout = () => {
  authStore.logout();
  router.push('/login');
};
</script>
