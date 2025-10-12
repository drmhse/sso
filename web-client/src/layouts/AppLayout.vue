<template>
  <div class="h-screen flex flex-col bg-gray-100 overflow-hidden">
    <!-- Fixed Header -->
    <AppHeader @toggle-sidebar="toggleMobileSidebar" />

    <!-- Main Content Area with Sidebar -->
    <div class="flex flex-1 overflow-hidden">
      <!-- Mobile Sidebar Overlay -->
      <Transition
        enter-active-class="transition-opacity duration-300"
        enter-from-class="opacity-0"
        enter-to-class="opacity-100"
        leave-active-class="transition-opacity duration-300"
        leave-from-class="opacity-100"
        leave-to-class="opacity-0"
      >
        <div
          v-if="isMobileSidebarOpen && showSidebar"
          class="fixed inset-0 bg-gray-900 bg-opacity-50 z-20 lg:hidden"
          @click="closeMobileSidebar"
        ></div>
      </Transition>

      <!-- Fixed Sidebar - Desktop always visible, Mobile slide-in -->
      <Transition
        enter-active-class="transition-transform duration-300"
        enter-from-class="-translate-x-full"
        enter-to-class="translate-x-0"
        leave-active-class="transition-transform duration-300"
        leave-from-class="translate-x-0"
        leave-to-class="-translate-x-full"
      >
        <AppSidebar
          v-if="showSidebar && (isMobileSidebarOpen || !isMobile)"
          :class="isMobile ? 'fixed inset-y-0 left-0 z-30' : ''"
          @close="closeMobileSidebar"
        />
      </Transition>

      <!-- Scrollable Main Content -->
      <main class="flex-1 overflow-y-auto">
        <div class="py-4 sm:py-6">
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
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRoute } from 'vue-router';
import AppHeader from '@/components/AppHeader.vue';
import AppSidebar from '@/components/AppSidebar.vue';
import NotificationPanel from '@/components/NotificationPanel.vue';

const route = useRoute();
const isMobileSidebarOpen = ref(false);
const isMobile = ref(false);

const showSidebar = computed(() => {
  // Don't show sidebar on certain routes
  const noSidebarRoutes = ['Login', 'Callback', 'Signup', 'NotFound', 'Landing'];
  return !noSidebarRoutes.includes(route.name);
});

const checkMobile = () => {
  isMobile.value = window.innerWidth < 1024; // lg breakpoint
};

const toggleMobileSidebar = () => {
  isMobileSidebarOpen.value = !isMobileSidebarOpen.value;
};

const closeMobileSidebar = () => {
  isMobileSidebarOpen.value = false;
};

onMounted(() => {
  checkMobile();
  window.addEventListener('resize', checkMobile);
});

onUnmounted(() => {
  window.removeEventListener('resize', checkMobile);
});
</script>
