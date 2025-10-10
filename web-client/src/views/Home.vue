<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 px-4">
    <div class="text-center">
      <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
      <p class="mt-4 text-gray-600">Redirecting to your dashboard...</p>
    </div>
  </div>
</template>

<script setup>
import { onMounted } from 'vue';
import { useRouter } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const authStore = useAuthStore();

onMounted(() => {
  // Smart redirector based on user's authentication state and claims
  if (authStore.isPlatformOwner) {
    // Platform owners go to platform dashboard
    router.replace('/platform/dashboard');
  } else if (authStore.currentOrgSlug) {
    // Users with an organization go to their org dashboard
    router.replace(`/orgs/${authStore.currentOrgSlug}/dashboard`);
  } else {
    // New users without an organization go to signup
    router.replace('/signup');
  }
});
</script>
