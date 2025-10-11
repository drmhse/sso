<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 px-4">
    <div class="max-w-md w-full text-center">
      <!-- Device Flow Success -->
      <div v-if="status === 'device_success'" class="space-y-4">
        <div class="rounded-full h-12 w-12 bg-green-100 mx-auto flex items-center justify-center">
          <svg class="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <h2 class="text-2xl font-bold text-gray-900">Device Authorized</h2>
        <p class="text-gray-600">
          Your device has been successfully authorized. You can now close this window and return to your application.
        </p>
      </div>

      <div v-else-if="status === 'loading'" class="space-y-4">
        <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
        <p class="text-gray-600">Completing sign in...</p>
      </div>

      <div v-else-if="status === 'error'" class="space-y-4">
        <div class="rounded-full h-12 w-12 bg-red-100 mx-auto flex items-center justify-center">
          <svg class="h-6 w-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </div>
        <h2 class="text-2xl font-bold text-gray-900">Authentication Failed</h2>
        <p class="text-gray-600">{{ errorMessage }}</p>
        <button
          @click="$router.push('/login')"
          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          Back to Login
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const route = useRoute();
const authStore = useAuthStore();

const status = ref('loading');
const errorMessage = ref('');
const isDeviceFlowSuccess = ref(false);

onMounted(async () => {
  try {
    // Check for device flow success first
    if (route.query.device_flow_status === 'success') {
      isDeviceFlowSuccess.value = true;
      status.value = 'device_success';
      return;
    }

    // Extract tokens from URL query parameters
    const accessToken = route.query.access_token;
    const refreshToken = route.query.refresh_token;
    const error = route.query.error;

    if (error) {
      throw new Error(error);
    }

    if (!accessToken || !refreshToken) {
      throw new Error('No authentication tokens received');
    }

    // Handle the login callback with both tokens
    await authStore.handleLoginCallback(accessToken, refreshToken);

    // Redirect to home (which will then redirect to the appropriate dashboard)
    router.push('/');
  } catch (error) {
    console.error('Callback error:', error);
    status.value = 'error';
    errorMessage.value = error.message || 'An unexpected error occurred';
  }
});
</script>
