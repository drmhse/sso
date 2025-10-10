<template>
  <div class="min-h-screen bg-gray-50 py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-2xl mx-auto">
      <div class="text-center mb-8">
        <h2 class="text-3xl font-extrabold text-gray-900">Create Your Organization</h2>
        <p class="mt-2 text-sm text-gray-600">
          Register your organization to start using the SSO platform
        </p>
      </div>

      <div class="bg-white shadow sm:rounded-lg">
        <div class="px-4 py-5 sm:p-6">
          <form @submit.prevent="handleSubmit" class="space-y-6">
            <div>
              <label for="name" class="block text-sm font-medium text-gray-700">
                Organization Name
              </label>
              <input
                type="text"
                id="name"
                v-model="formData.name"
                required
                class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="Acme Corporation"
              />
            </div>

            <div>
              <label for="slug" class="block text-sm font-medium text-gray-700">
                Organization Slug
              </label>
              <div class="mt-1">
                <input
                  type="text"
                  id="slug"
                  v-model="formData.slug"
                  required
                  pattern="[a-z0-9-]+"
                  class="block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="acme-corp"
                />
              </div>
              <p class="mt-2 text-sm text-gray-500">
                Lowercase letters, numbers, and hyphens only. This will be used in URLs.
              </p>
            </div>

            <div>
              <label for="domain" class="block text-sm font-medium text-gray-700">
                Domain (Optional)
              </label>
              <input
                type="text"
                id="domain"
                v-model="formData.domain"
                class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="acme.com"
              />
            </div>

            <div v-if="error" class="rounded-md bg-red-50 p-4">
              <div class="flex">
                <div class="flex-shrink-0">
                  <svg class="h-5 w-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd" />
                  </svg>
                </div>
                <div class="ml-3">
                  <p class="text-sm text-red-800">{{ error }}</p>
                </div>
              </div>
            </div>

            <div v-if="success" class="rounded-md bg-green-50 p-4">
              <div class="flex">
                <div class="flex-shrink-0">
                  <svg class="h-5 w-5 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                  </svg>
                </div>
                <div class="ml-3">
                  <p class="text-sm text-green-800">
                    Organization created successfully! Awaiting platform owner approval.
                  </p>
                </div>
              </div>
            </div>

            <div class="flex justify-end space-x-3">
              <button
                type="button"
                @click="$router.push('/login')"
                class="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="loading || success"
                class="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {{ loading ? 'Creating...' : 'Create Organization' }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { sso } from '@/api';

const formData = ref({
  name: '',
  slug: '',
  domain: '',
});

const loading = ref(false);
const error = ref('');
const success = ref(false);

const handleSubmit = async () => {
  loading.value = true;
  error.value = '';
  success.value = false;

  try {
    const payload = {
      name: formData.value.name,
      slug: formData.value.slug,
    };

    if (formData.value.domain) {
      payload.domain = formData.value.domain;
    }

    await sso.organizations.createPublic(payload);
    success.value = true;

    // Reset form
    formData.value = {
      name: '',
      slug: '',
      domain: '',
    };
  } catch (err) {
    console.error('Failed to create organization:', err);
    error.value = err.message || 'Failed to create organization. Please try again.';
  } finally {
    loading.value = false;
  }
};
</script>
