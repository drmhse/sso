<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 px-4">
    <div class="max-w-md w-full text-center">
      <h1 class="text-9xl font-bold text-gray-200">404</h1>
      <h2 class="mt-4 text-3xl font-bold text-gray-900">Page not found</h2>
      <p class="mt-2 text-gray-600">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <div class="mt-6">
        <button
          @click="$router.push('/')"
          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          Go to Dashboard
        </button>
      </div>
    </div>
  </div>
</template>

<script setup>
</script>
