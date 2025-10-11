<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 px-4">
    <div class="max-w-md w-full space-y-8">
      <!-- Step 1: Enter code -->
      <div v-if="!loginContext">
        <div class="text-center">
          <h2 class="text-3xl font-extrabold text-gray-900">Activate Your Device</h2>
          <p class="mt-2 text-sm text-gray-600">
            Enter the code displayed on your CLI or device to authorize platform access.
          </p>
        </div>

        <form @submit.prevent="verifyCode" class="mt-8 space-y-6">
          <div>
            <label for="code" class="sr-only">Activation Code</label>
            <input
              id="code"
              v-model="userCode"
              type="text"
              required
              :disabled="loading"
              class="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-blue-500 focus:border-blue-500 focus:z-10 sm:text-sm"
              placeholder="XXXX-XXXX"
              pattern="[A-Z0-9]{4}-[A-Z0-9]{4}"
              maxlength="9"
            />
          </div>

          <div v-if="error" class="rounded-md bg-red-50 p-4">
            <div class="flex">
              <div class="ml-3">
                <h3 class="text-sm font-medium text-red-800">{{ error }}</h3>
              </div>
            </div>
          </div>

          <div>
            <button
              type="submit"
              :disabled="loading"
              class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-400 disabled:cursor-not-allowed"
            >
              <span v-if="!loading">Continue</span>
              <span v-else>Verifying...</span>
            </button>
          </div>
        </form>
      </div>

      <!-- Step 2: Choose provider -->
      <div v-else>
        <div class="text-center">
          <h2 class="text-3xl font-extrabold text-gray-900">Authorize Device</h2>
          <p class="mt-2 text-sm text-gray-600">
            Sign in to complete the activation for <strong>{{ loginContext.service_slug }}</strong> service.
          </p>
        </div>

        <div class="mt-8 space-y-4">
          <button
            v-if="isProviderAvailable('github')"
            @click="handleLogin('github')"
            class="w-full flex items-center justify-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <svg class="w-5 h-5 mr-2" fill="currentColor" viewBox="0 0 24 24">
              <path
                fill-rule="evenodd"
                d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                clip-rule="evenodd"
              />
            </svg>
            Sign in with GitHub
          </button>

          <button
            v-if="isProviderAvailable('google')"
            @click="handleLogin('google')"
            class="w-full flex items-center justify-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <svg class="w-5 h-5 mr-2" viewBox="0 0 24 24">
              <path
                fill="#4285F4"
                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
              />
              <path
                fill="#34A853"
                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
              />
              <path
                fill="#FBBC05"
                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
              />
              <path
                fill="#EA4335"
                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
              />
            </svg>
            Sign in with Google
          </button>

          <button
            v-if="isProviderAvailable('microsoft')"
            @click="handleLogin('microsoft')"
            class="w-full flex items-center justify-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            <svg class="w-5 h-5 mr-2" viewBox="0 0 23 23">
              <path fill="#f3f3f3" d="M0 0h23v23H0z" />
              <path fill="#f35325" d="M1 1h10v10H1z" />
              <path fill="#81bc06" d="M12 1h10v10H12z" />
              <path fill="#05a6f0" d="M1 12h10v10H1z" />
              <path fill="#ffba08" d="M12 12h10v10H12z" />
            </svg>
            Sign in with Microsoft
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { sso } from '@/api';

const userCode = ref('');
const loading = ref(false);
const error = ref('');
const loginContext = ref(null);

const verifyCode = async () => {
  loading.value = true;
  error.value = '';

  try {
    const context = await sso.auth.deviceCode.verify(userCode.value);
    loginContext.value = context;
  } catch (err) {
    error.value = err.message || 'Invalid or expired code. Please try again.';
  } finally {
    loading.value = false;
  }
};

const isProviderAvailable = (provider) => {
  return loginContext.value?.available_providers?.includes(provider) ?? false;
};

const handleLogin = (provider) => {
  // Use the admin login flow for platform-level device authorization
  const loginUrl = sso.auth.getAdminLoginUrl(provider, {
    org_slug: loginContext.value.org_slug,
    user_code: userCode.value,
  });
  window.location.href = loginUrl;
};
</script>
