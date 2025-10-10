<template>
  <div class="min-h-screen bg-gray-100">
    <AppHeader />

    <div class="flex">
      <AppSidebar v-if="showSidebar" />

      <main class="flex-1">
        <div class="py-6">
          <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <slot />
          </div>
        </div>
      </main>
    </div>

    <NotificationPanel />
  </div>
</template>

<script setup>
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import AppHeader from '@/components/AppHeader.vue';
import AppSidebar from '@/components/AppSidebar.vue';
import NotificationPanel from '@/components/NotificationPanel.vue';

const route = useRoute();

const showSidebar = computed(() => {
  // Don't show sidebar on certain routes
  const noSidebarRoutes = ['Login', 'Callback', 'Signup', 'NotFound'];
  return !noSidebarRoutes.includes(route.name);
});
</script>
